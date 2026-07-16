package dnsserver

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gdns2tcp/internal/codec"
	"gdns2tcp/internal/dnshelpers"
	"gdns2tcp/internal/protocol"
	gproxy "gdns2tcp/internal/proxy"
)

const (
	// reverseTTL is the per-cid idle timeout. Operator's TCP socket sets this
	// indirectly: if the operator vanishes, the per-cid buffers drain and the
	// cleanup goroutine reaps them after this window.
	//
	// 30 minutes covers typical long-running interactive sessions (vim, top,
	// watch, log tails) that sit idle between bursts of input. Shorter would
	// kill SSH sessions mid-session; longer would let dead cids sit around
	// chewing memory on busy servers.
	reverseTTL = 30 * time.Minute

	// reverseMaxBufBytes caps each direction's queued bytes per cid. Past this
	// the producing side blocks: SOCKS5 reader pauses when operator→agent is
	// full; agent's awrite is told FULL and retries.
	reverseMaxBufBytes = 1 << 20

	// reverseMaxConn caps concurrent live tunnels server-wide.
	reverseMaxConn = 64

	proxyDisabledResponse = "Proxy is disabled."
	proxyAuthFailResponse = authFailedResponse

	// reverseDefaultWatchdogWindow is the default first-accept window. Per-
	// server instance config overrides it via Config.ProxyWatchdogWindow so
	// tests can shrink it without sharing state across goroutines.
	reverseDefaultWatchdogWindow = 30 * time.Second

	// reverseLeaseTTL is how long an OPEN handed to an agent stays reserved
	// for that exact poll request.  DNS is lossy: deleting an item from the
	// queue before the agent has acknowledged it made one dropped apoll reply
	// strand a SOCKS connection until its idle timeout.
	reverseLeaseTTL = 10 * time.Second

	// reverseOpenTimeout bounds the time an operator waits for the agent to
	// dial the requested target before SOCKS CONNECT receives a failure.
	reverseOpenTimeout = 15 * time.Second

	// proxyResponseTTL retains an axchg response long enough for the agent to
	// retry exactly the same QNAME after a UDP/TCP timeout.  It is deliberately
	// shorter than reverseLeaseTTL; the periodic janitor also bounds the map.
	proxyResponseTTL      = 30 * time.Second
	maxProxyResponseCache = 512
	maxOutboundUnacked    = 128
)

// reverseConn carries one tunnel: the operator's local TCP socket on one end
// and the byte buffers polled by the agent on the other. Two ring-buffer-ish
// bytes.Buffer instances back each direction.
//
// awriteWindow caps how far ahead the agent's awrite seq is allowed to run
// past the next-expected one. axchgWorkers=32 on the agent + an in-channel
// queue of 32 jobs + axchgRetries=3 multiplying each seq's lifetime under
// packet loss adds up to ~96 worst-case in-flight seqs. On fast transports
// (TCP DNS over LAN / loopback) workers cycle much faster than the server
// drains, easily doubling or tripling the naive estimate. 512 covers the
// realistic burst without meaningful memory cost (~42 KB of oooWrite map
// entries at 84 bytes/chunk).
const awriteWindow = 512

type reverseConn struct {
	target     string // "host:port" — agent dials this
	operator   net.Conn
	aead       cipher.AEAD
	sessionKey [32]byte
	compressor *gproxy.Compressor
	mu         sync.Mutex
	// writeMu serialises the writev to rc.operator so concurrent awrite/
	// axchg drains don't interleave bytes on the operator socket. It's
	// held only across the syscall — drain itself runs under rc.mu.
	writeMu     sync.Mutex
	opToAgent   bytes.Buffer
	opCond      *sync.Cond
	seqAgentIn  uint64 // last contiguously written awrite seq
	seqOpToA    uint64 // next aread seq to issue
	oooWrite    map[uint64][]byte
	agentClosed bool
	opClosed    bool
	expires     time.Time

	// Lease/open negotiation.  New agents include a unique poll ID in apoll
	// and then send aopen once the target dial succeeds or fails.  Legacy
	// apoll (without a poll ID) remains supported and resolves openReady at
	// pickup time, preserving compatibility with already deployed agents.
	leaseID      string
	leaseExpires time.Time
	leaseModern  bool
	leaseVersion byte
	openReady    chan struct{}
	openOnce     sync.Once
	openStatus   byte
	openPollID   string

	// responseCache makes axchg idempotent by request nonce. Completed entries
	// keep only headers and the DATA sequence; the payload itself lives once in
	// outbound until read ACK. This avoids retaining hundreds of independent
	// ~64 KiB TCP TXT payloads per tunnel.
	responseCache map[uint64]*cachedProxyResponse
	// outbound holds server->agent chunks until the agent acknowledges the
	// highest contiguous sequence it has written to the local target.
	outbound              map[uint64]outboundProxyResponse
	outboundPlainBytes    int
	outboundReservedBytes int
	outboundInFlight      int
	readAck               uint64

	// Anti-replay window for read-side commands (aread/aclose).  A 64-bit
	// bitmap was smaller but rejected valid replies with the UDP worker count
	// (96) whenever scheduling reordered more than 64 requests.  Keep a
	// bounded set instead; entries older than nonceReplayWindow are pruned.
	nonceFloor uint64
	nonceSeen  map[uint64]struct{}

	// readWaiters fans the "new operator bytes" signal out to every
	// long-poll axchg/aread that's currently parked. reversePumpOperator
	// closes them all on each opToAgent.Write so any in-flight long-poll
	// wakes up immediately (Шаг C). Slice is drained on each signal —
	// waiters re-register on their next call if they need to wait again.
	readWaiters []chan struct{}
}

type cachedProxyResponse struct {
	done        chan struct{}
	ready       bool
	writeStatus string
	readHead    string
	readSeq     uint64
	expires     time.Time
}

type outboundProxyResponse struct {
	segments   []string
	plainBytes int
}

// signalOneReaderLocked wakes a single parked aread/axchg — the one that
// has been waiting the longest (FIFO). The remaining waiters stay parked.
// Used when new operator bytes arrive: only one worker needs to wake up,
// drain the chunk, and ship it; the rest would just see EMPTY on a
// pure-read axchg, wasting one DNS round-trip each.
//
// Caller must hold rc.mu. Safe to call when readWaiters is empty.
func (rc *reverseConn) signalOneReaderLocked() {
	if len(rc.readWaiters) == 0 {
		return
	}
	ch := rc.readWaiters[0]
	rc.readWaiters = rc.readWaiters[1:]
	close(ch)
}

// closeAllReadersLocked wakes every currently parked aread/axchg at once.
// Used on tunnel teardown (reverseCloseConn) so every worker observes
// CLOSED and exits — none should keep parking on a dead cid.
//
// Caller must hold rc.mu. Safe to call when readWaiters is empty.
func (rc *reverseConn) closeAllReadersLocked() {
	for _, w := range rc.readWaiters {
		close(w)
	}
	rc.readWaiters = nil
}

// drainContiguousWritesLocked pulls every in-order chunk out of oooWrite
// starting at seqAgentIn+1, advances rc.seqAgentIn to the last consumed
// seq, and returns the chunks as a net.Buffers. Caller must hold rc.mu.
//
// Advancing under rc.mu — together with writeMu serialising the actual
// writev — is what closes the duplicate-seq race: a concurrent awrite for
// any seq ≤ rc.seqAgentIn now correctly fast-paths to "ACK seq" instead of
// re-storing into oooWrite and re-delivering the same bytes to the
// operator socket. The writev itself runs unlocked from rc.mu, so other
// callers can keep filling oooWrite in the meantime, but writeMu keeps
// their writev's serialised behind ours — preserving stream order.
//
// Picking the batch upfront (rather than write-one-then-relock) collapses
// N operator.Write syscalls into a single writev, which on bulk inbound
// traffic was the dominant CPU cost on the server side.
func (rc *reverseConn) drainContiguousWritesLocked(maxBatch int) net.Buffers {
	if rc.oooWrite == nil {
		return nil
	}
	var batch net.Buffers
	for {
		if maxBatch > 0 && len(batch) >= maxBatch {
			break
		}
		next := rc.seqAgentIn + 1
		data, ok := rc.oooWrite[next]
		if !ok {
			break
		}
		delete(rc.oooWrite, next)
		batch = append(batch, data)
		rc.seqAgentIn = next
	}
	return batch
}

// commitOperatorWrite runs the actual writev on the operator socket. Caller
// must already hold rc.writeMu (acquired before releasing rc.mu — see the
// drain-then-write pattern in applyAxchgWrite and proxyAgentWrite). The
// rc.mu → rc.writeMu locking order keeps two concurrent drains from
// reordering bytes on the operator socket: whoever grabbed writeMu first
// also drained first, so their writev runs first.
//
// A short write (n < total bytes) means the operator stream is now
// truncated relative to seqAgentIn and unrecoverable; we surface it as an
// error so the caller tears the tunnel down.
func (rc *reverseConn) commitOperatorWrite(batch net.Buffers) error {
	want := int64(0)
	for _, b := range batch {
		want += int64(len(b))
	}
	n, err := batch.WriteTo(rc.operator)
	if err != nil {
		return err
	}
	if n != want {
		return fmt.Errorf("short writev: wrote %d of %d", n, want)
	}
	return nil
}

// drainBatchSize caps how many chunks a single writev can carry. The cap
// keeps any one drain from monopolising rc.mu and lets other axchg calls
// progress between batches. 32 is a multiple of the awriteWindow=64 so an
// already-buffered burst clears in two batches.
const drainBatchSize = 32

// awaitReadData parks the caller for up to window while waiting for new
// op→agent bytes. Returns true if data arrived (or the tunnel closed),
// false on plain timeout. Used by collectAxchgRead's long-poll path.
//
// Long-polling halves perceived latency on interactive traffic: an SSH
// keystroke from the operator arrives on the server, signals the parked
// axchg, and the agent gets the chunk inside one RTT instead of waiting
// for its next poll tick (which used to add up to cfg.pollMax = 200ms).
func (rc *reverseConn) awaitReadData(window time.Duration) bool {
	rc.mu.Lock()
	if rc.opToAgent.Len() > 0 || rc.opClosed || rc.agentClosed {
		rc.mu.Unlock()
		return true
	}
	ch := make(chan struct{})
	rc.readWaiters = append(rc.readWaiters, ch)
	rc.mu.Unlock()

	timer := time.NewTimer(window)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		// Best-effort de-registration; if a signal already fired we'll
		// harmlessly remove a closed channel.
		rc.mu.Lock()
		for i, w := range rc.readWaiters {
			if w == ch {
				rc.readWaiters = append(rc.readWaiters[:i], rc.readWaiters[i+1:]...)
				break
			}
		}
		rc.mu.Unlock()
		return false
	}
}

// longPollWindow caps how long a single aread/axchg waits for data before
// returning EMPTY. Picked to fit comfortably inside the DNS resolver's
// default UDP timeout (5s) while being long enough that an idle SSH
// session needs ~5 round-trips per second instead of ~50 with cfg.pollMax.
const longPollWindow = 150 * time.Millisecond

// acceptNonce returns true if n hasn't been seen yet in this cid's sliding
// window. Caller must hold rc.mu.
const nonceReplayWindow = 65536

func (rc *reverseConn) acceptNonce(n uint64) bool {
	if n == 0 {
		return false
	}
	if rc.nonceSeen == nil {
		rc.nonceSeen = make(map[uint64]struct{}, nonceReplayWindow)
	}
	if n > rc.nonceFloor {
		rc.nonceFloor = n
	}
	if _, exists := rc.nonceSeen[n]; exists {
		return false
	}
	rc.nonceSeen[n] = struct{}{}
	if len(rc.nonceSeen) > nonceReplayWindow {
		floor := rc.nonceFloor
		for seen := range rc.nonceSeen {
			if seen < floor && floor-seen >= nonceReplayWindow {
				delete(rc.nonceSeen, seen)
			}
		}
	}
	return true
}

func cloneSegments(in []string) []string {
	return append([]string(nil), in...)
}

// beginResponse either reserves a nonce for the caller that will compute its
// response, or returns a previously cached/in-flight response.  rc.mu must be
// held by the caller.  An in-flight duplicate waits outside the lock so DNS
// retries cannot race a long-poll and turn into false replay failures.
func (rc *reverseConn) beginResponse(nonce uint64, now time.Time) (cached []string, wait <-chan struct{}, owner bool) {
	if rc.responseCache == nil {
		rc.responseCache = make(map[uint64]*cachedProxyResponse)
	}
	if entry, ok := rc.responseCache[nonce]; ok {
		if entry.ready && now.Before(entry.expires) {
			return rc.materializeCachedResponseLocked(entry), nil, false
		}
		if !entry.ready {
			return nil, entry.done, false
		}
		delete(rc.responseCache, nonce)
	}
	if len(rc.responseCache) >= maxProxyResponseCache {
		// Keep the map bounded even under a broken resolver continually
		// assigning fresh nonces.  Expired entries are preferred; otherwise
		// any completed entry is safe to evict because the agent retries
		// quickly and still has read ACK based recovery.
		for key, entry := range rc.responseCache {
			if entry.ready && now.After(entry.expires) {
				delete(rc.responseCache, key)
				break
			}
		}
		if len(rc.responseCache) >= maxProxyResponseCache {
			for key, entry := range rc.responseCache {
				if entry.ready {
					delete(rc.responseCache, key)
					break
				}
			}
		}
	}
	rc.responseCache[nonce] = &cachedProxyResponse{done: make(chan struct{})}
	return nil, nil, true
}

func (rc *reverseConn) materializeCachedResponseLocked(entry *cachedProxyResponse) []string {
	if entry == nil || !entry.ready {
		return nil
	}
	out := []string{entry.writeStatus}
	if entry.readSeq != 0 {
		if retained, ok := rc.outbound[entry.readSeq]; ok {
			return append(out, cloneSegments(retained.segments)...)
		}
		// A later delivery may already have advanced readAck and released the
		// payload. Returning EMPTY is safe: the agent has written this sequence.
		if entry.readSeq <= rc.readAck {
			return append(out, "EMPTY")
		}
		return nil
	}
	if entry.readHead != "" {
		out = append(out, entry.readHead)
	}
	return out
}

// finishResponse publishes a response reserved by beginResponse.  It is safe
// to call exactly once for an owner.  rc.mu must not be held by the caller.
func (rc *reverseConn) finishResponse(nonce uint64, response []string, now time.Time) {
	rc.mu.Lock()
	entry, ok := rc.responseCache[nonce]
	if ok && !entry.ready {
		if len(response) > 0 {
			entry.writeStatus = response[0]
		}
		if len(response) > 1 {
			entry.readHead = response[1]
			if strings.HasPrefix(response[1], "DATA ") {
				entry.readSeq, _ = strconv.ParseUint(strings.TrimPrefix(response[1], "DATA "), 16, 64)
				entry.readHead = ""
			}
		}
		entry.ready = true
		entry.expires = now.Add(proxyResponseTTL)
		close(entry.done)
		entry.done = nil
	}
	rc.mu.Unlock()
}

// applyReadAck drops only chunks the agent has confirmed as written to its
// upstream target.  Chunks remain available across a lost DNS response.
// rc.mu must be held by the caller.
func (rc *reverseConn) applyReadAck(ack uint64) {
	if ack <= rc.readAck {
		return
	}
	rc.readAck = ack
	for seq, retained := range rc.outbound {
		if seq <= ack {
			rc.outboundPlainBytes -= retained.plainBytes
			delete(rc.outbound, seq)
		}
	}
	if rc.outboundPlainBytes < 0 {
		rc.outboundPlainBytes = 0
	}
	rc.opCond.Broadcast()
}

func (rc *reverseConn) signalOpen(status byte) {
	rc.openOnce.Do(func() {
		rc.openStatus = status
		close(rc.openReady)
	})
}

// reverseState lives on Server when AllowProxy is true. Holds the rendezvous
// queues and the SOCKS5 TCP listener's state.
type reverseState struct {
	mu       sync.Mutex
	conns    map[string]*reverseConn // cid → conn
	pending  []*reverseConn          // FIFO of cids awaiting an agent
	pendCids map[*reverseConn]string // reverse lookup

	maxBufCap      int
	maxConns       int
	watchdogWindow time.Duration
	socksLn        net.Listener
	logger         interface {
		Printf(format string, v ...interface{})
	}
	parentSrv    *Server
	shutdownCh   chan struct{}
	shutdownOnce sync.Once

	// agentReady is closed once the first apoll arrives, signalling
	// ServeSOCKS5 that it's safe to bind the operator-facing port. Until
	// this fires the SOCKS5 listener stays unbound and accepts no traffic.
	agentReady   chan struct{}
	agentReadyMu sync.Mutex // protects single close of agentReady
	knownAgents  map[string]time.Time

	// authFailLogMu + lastAuthFailLog rate-limit the diagnostic line we
	// emit on apoll authentication failures. A misconfigured agent (wrong
	// secret or huge clock drift) loops at ~1 apoll/sec; without rate
	// limiting we'd flood the server log. One line per source IP per minute
	// is enough for a human admin to notice.
	authFailLogMu   sync.Mutex
	lastAuthFailLog map[string]time.Time
}

func newReverseState(maxBufCap, maxConns int, watchdog time.Duration, logger interface {
	Printf(format string, v ...interface{})
}) *reverseState {
	if maxBufCap <= 0 {
		maxBufCap = reverseMaxBufBytes
	}
	if maxConns <= 0 {
		maxConns = reverseMaxConn
	}
	if watchdog <= 0 {
		watchdog = reverseDefaultWatchdogWindow
	}
	return &reverseState{
		conns:           make(map[string]*reverseConn),
		pendCids:        make(map[*reverseConn]string),
		maxBufCap:       maxBufCap,
		maxConns:        maxConns,
		watchdogWindow:  watchdog,
		logger:          logger,
		shutdownCh:      make(chan struct{}),
		agentReady:      make(chan struct{}),
		knownAgents:     make(map[string]time.Time),
		lastAuthFailLog: make(map[string]time.Time),
	}
}

// logApollAuthFail emits one diagnostic line per source-IP per minute when
// an apoll fails authentication. The line tells the admin whether the
// failure is clock drift (then "fix NTP") or a real MAC mismatch (then
// "wrong -secret/-pass"). Without this distinction operators tend to
// re-check the secret first — a 5-minute debugging detour — when the real
// issue is the VPS clock has drifted.
func (r *reverseState) logApollAuthFail(client, timestamp string, now time.Time, logger interface {
	Printf(format string, v ...interface{})
}) {
	r.authFailLogMu.Lock()
	last := r.lastAuthFailLog[client]
	if now.Sub(last) < time.Minute {
		r.authFailLogMu.Unlock()
		return
	}
	r.lastAuthFailLog[client] = now
	r.authFailLogMu.Unlock()

	drift, ok := protocol.AuthDriftMinutes(timestamp, now)
	if !ok {
		logger.Printf("apoll auth fail from %s: malformed timestamp (agent corrupted query or wire-format mismatch)", client)
		return
	}
	absDrift := drift
	if absDrift < 0 {
		absDrift = -absDrift
	}
	if absDrift > protocol.VerifyAuthWindowMinutes {
		side := "agent clock is behind"
		if drift < 0 {
			side = "agent clock is ahead"
		}
		logger.Printf("apoll auth fail from %s: clock drift %+d min (window ±%d) — %s; run `sudo chronyc -a makestep` / `sudo ntpdate -u pool.ntp.org` on the side that's wrong",
			client, drift, protocol.VerifyAuthWindowMinutes, side)
		return
	}
	logger.Printf("apoll auth fail from %s: timestamp within ±%d min window so clocks are fine — check that agent's -pass matches server's -secret exactly",
		client, protocol.VerifyAuthWindowMinutes)
}

// noteAgent records a poll from an agent IP. Returns true on the first poll
// from this IP (used to decide whether to log "agent connected"). Also closes
// agentReady on the very first call from any agent.
func (r *reverseState) noteAgent(addr string) bool {
	now := time.Now()
	r.agentReadyMu.Lock()
	defer r.agentReadyMu.Unlock()
	_, known := r.knownAgents[addr]
	r.knownAgents[addr] = now
	if !known {
		select {
		case <-r.agentReady:
			// already closed
		default:
			close(r.agentReady)
		}
	}
	return !known
}

// --- SOCKS5 listener -------------------------------------------------------

// ServeSOCKS5 starts the operator-facing SOCKS5/TCP listener. Returns when the
// listener stops accepting (called by parent on shutdown). Authentication uses
// SOCKS5 username/password method (RFC 1929) with username = "gdns2tcp" and
// password = -secret, so only operators holding the secret can drive the
// tunnel even though the listener is exposed on a public port.
func (s *Server) ServeSOCKS5(addr string) error {
	if !s.allowProxy || s.reverse == nil {
		return errors.New("proxy is disabled")
	}
	// Fail-fast on obviously bad addresses so a typo doesn't get masked by
	// the wait-for-agent step below.
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return fmt.Errorf("invalid -socks-listen %q: %w", addr, err)
	}
	authNote := "auth: user=gdns2tcp password=<-secret>"
	if s.socksNoAuth {
		authNote = "auth: none (-socks-no-auth)"
	}
	s.logger.Printf("SOCKS5 will bind to tcp://%s (%s) once an agent connects", addr, authNote)

	// Block until the first agent's apoll arrives. Without this the operator
	// would be able to dial SOCKS5 before any agent is around to service
	// CONNECT requests, which produces the misleading "socket error or
	// timeout" the operator sees in their proxychains output.
	select {
	case <-s.reverse.agentReady:
	case <-s.reverse.shutdownCh:
		return nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socks5 listen %s: %w", addr, err)
	}
	s.reverse.mu.Lock()
	s.reverse.socksLn = ln
	s.reverse.parentSrv = s
	s.reverse.mu.Unlock()
	s.logger.Printf("SOCKS5 listening on tcp://%s (%s)", addr, authNote)

	// Watchdog: if no inbound connection arrives within the window AND the
	// bind isn't loopback, surface a one-shot diagnostic. Most "the listener
	// is up but my proxychains times out" failures are a host firewall
	// dropping inbound TCP on the bind interface.
	var accepts atomic.Int64
	go s.runFirstAcceptWatchdog(addr, &accepts)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.reverse.shutdownCh:
				return nil
			default:
				return err
			}
		}
		accepts.Add(1)
		go s.handleSOCKS5Operator(conn)
	}
}

// runFirstAcceptWatchdog logs a one-shot diagnostic if no inbound SOCKS5
// connections arrive within s.reverse.watchdogWindow. It is suppressed when
// the bind host is loopback (no firewall would block 127.0.0.1) and when the
// listener is taken down during shutdown.
func (s *Server) runFirstAcceptWatchdog(addr string, accepts *atomic.Int64) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	switch host {
	case "127.0.0.1", "::1", "localhost", "0.0.0.0", "":
		// 0.0.0.0/"" mean "all interfaces" — the operator picked broad bind
		// and we can't pin a specific iface to suggest, so skip the hint.
		if host == "127.0.0.1" || host == "::1" || host == "localhost" {
			return
		}
	}
	select {
	case <-time.After(s.reverse.watchdogWindow):
	case <-s.reverse.shutdownCh:
		return
	}
	if accepts.Load() > 0 {
		return
	}
	ifaceName := interfaceNameForIPv4(host)
	if ifaceName == "" {
		ifaceName = "<iface>"
	}
	s.logger.Printf(`WARNING: no SOCKS5 connections in %s on tcp://%s.
  The listener is up and an agent is connected — typical cause is a server
  firewall dropping inbound TCP. Quick checks:
    ss -tlnp | grep %s
    iptables -L INPUT -n -v | grep -E '%s|%s'
  From the operator host:
    nc -v %s %s
  If timeout — open the port on the bind interface, for example:
    sudo iptables -I INPUT -i %s -p tcp --dport %s -j ACCEPT`,
		s.reverse.watchdogWindow, addr,
		port,
		port, ifaceName,
		host, port,
		ifaceName, port)
}

// interfaceNameForIPv4 returns the OS-level interface name whose first IPv4
// matches `host`. Best-effort: returns "" if no match. Used purely for log
// hint construction in runFirstAcceptWatchdog.
func interfaceNameForIPv4(host string) string {
	want := net.ParseIP(host)
	if want == nil {
		return ""
	}
	want = want.To4()
	if want == nil {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil && v4.Equal(want) {
				return iface.Name
			}
		}
	}
	return ""
}

// HandleSOCKS5OperatorForTest exposes the per-connection SOCKS5 handler so
// integration tests in sibling packages can plug their own listener. Not part
// of the supported API surface.
func (s *Server) HandleSOCKS5OperatorForTest(conn net.Conn) {
	s.handleSOCKS5Operator(conn)
}

func (s *Server) handleSOCKS5Operator(conn net.Conn) {
	defer conn.Close()
	tuneTCPConn(conn) // Шаг G: kill Nagle, arm keepalive
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if s.socksNoAuth {
		if err := socks5NoAuthSelect(conn); err != nil {
			s.logger.Printf("socks5 method-select %s: %v", conn.RemoteAddr(), err)
			return
		}
	} else if err := socks5Authenticate(conn, s.secret); err != nil {
		s.logger.Printf("socks5 auth failed %s: %v", conn.RemoteAddr(), err)
		return
	}
	target, err := socks5ReadConnect(conn)
	if err != nil {
		_ = socks5WriteReply(conn, 0x01)
		s.logger.Printf("socks5 connect parse %s: %v", conn.RemoteAddr(), err)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	cid, rc, err := s.reverseEnqueueOpen(target, conn)
	if err != nil {
		_ = socks5WriteReply(conn, 0x05) // connection refused
		s.logger.Printf("socks5 enqueue %s→%s: %v", conn.RemoteAddr(), target, err)
		return
	}
	status := s.waitReverseOpen(cid, rc)
	if status != 0x00 {
		_ = socks5WriteReply(conn, status)
		s.reverseCloseConn(cid, rc, fmt.Sprintf("agent target dial status %#x", status))
		return
	}
	if err := socks5WriteReply(conn, status); err != nil {
		s.reverseCloseConn(cid, rc, "socks5 reply write: "+err.Error())
		return
	}
	s.logger.Printf("socks5 open cid=%s op=%s target=%s", cid, conn.RemoteAddr(), target)

	// Pump local socket → opToAgent buffer. The aread handler drains it.
	s.reversePumpOperator(cid, rc)
}

// waitReverseOpen waits until an agent has either completed its local target
// dial (aopen), a legacy agent has picked up the CID, or the lease/dial window
// expires.  SOCKS5 CONNECT must not advertise success before this point.
func (s *Server) waitReverseOpen(cid string, rc *reverseConn) byte {
	timer := time.NewTimer(reverseOpenTimeout)
	defer timer.Stop()
	select {
	case <-rc.openReady:
		return rc.openStatus
	case <-timer.C:
		return 0x04 // host unreachable / target did not answer in time
	case <-s.reverse.shutdownCh:
		return 0x01
	}
}

// reverseEnqueueOpen allocates a cid + state and places it in the pending
// queue. The next apoll request hands it off to an agent.
func (s *Server) reverseEnqueueOpen(target string, op net.Conn) (string, *reverseConn, error) {
	s.reverse.mu.Lock()
	defer s.reverse.mu.Unlock()
	if len(s.reverse.conns) >= s.reverse.maxConns {
		return "", nil, errors.New("server at capacity")
	}
	cid, err := gproxy.NewCID()
	if err != nil {
		return "", nil, err
	}
	aead, err := gproxy.SessionAEAD(s.secret, cid)
	if err != nil {
		return "", nil, err
	}
	compressor, err := gproxy.GetCompressor()
	if err != nil {
		return "", nil, err
	}
	rc := &reverseConn{
		target:     target,
		operator:   op,
		aead:       aead,
		sessionKey: protocol.DeriveSessionKey(s.secret, cid),
		compressor: compressor,
		expires:    time.Now().Add(reverseTTL),
		openReady:  make(chan struct{}),
		openStatus: 0x01, // general failure until an agent proves otherwise
		outbound:   make(map[uint64]outboundProxyResponse),
	}
	rc.opCond = sync.NewCond(&rc.mu)
	s.reverse.conns[cid] = rc
	s.reverse.pending = append(s.reverse.pending, rc)
	s.reverse.pendCids[rc] = cid
	return cid, rc, nil
}

// reversePumpOperator copies the operator's TCP bytes into opToAgent. Pauses
// when the buffer is at cap; resumes after the agent's aread drains it.
func (s *Server) reversePumpOperator(cid string, rc *reverseConn) {
	readSize := 4096
	if s.reverse.maxBufCap < readSize {
		readSize = s.reverse.maxBufCap
	}
	if readSize < 1 {
		readSize = 1
	}
	// Never read a chunk that can never fit into opToAgent.  Previously a
	// valid small -proxy-buf-bytes value made the first Read block forever on
	// opCond while the agent had no bytes it could drain.
	buf := make([]byte, readSize)
	for {
		n, err := rc.operator.Read(buf)
		if n > 0 {
			rc.mu.Lock()
			for !rc.opClosed && !rc.agentClosed && rc.opToAgent.Len()+rc.outboundPlainBytes+rc.outboundReservedBytes+n > s.reverse.maxBufCap {
				rc.opCond.Wait()
			}
			if rc.opClosed || rc.agentClosed {
				rc.mu.Unlock()
				s.reverseCloseConn(cid, rc, "tunnel closed during operator pump")
				return
			}
			rc.opToAgent.Write(buf[:n])
			rc.expires = time.Now().Add(reverseTTL)
			// Шаг C+fairness: wake one parked worker — they drain the
			// chunk; waking all 16 would spawn 15 wasted DNS round-trips
			// since only one can take the data.
			rc.signalOneReaderLocked()
			rc.mu.Unlock()
		}
		if err != nil {
			s.reverseCloseConn(cid, rc, "operator EOF/error: "+err.Error())
			return
		}
	}
}

// reverseCloseConn marks the tunnel as closed from one side and removes it
// from the server-wide indexes. The agent learns via subsequent aread/axchg
// returning CLOSED for an unknown cid; aclose remains idempotent.
func (s *Server) reverseCloseConn(cid string, rc *reverseConn, reason string) {
	if rc == nil {
		return
	}
	// Keep reverseState -> reverseConn as the single lock ordering.  Poll and
	// aopen inspect pending state under reverseState.mu and then rc.mu; taking
	// rc.mu first here used to permit a shutdown/lease deadlock.
	if s.reverse != nil {
		s.reverse.mu.Lock()
		cid = s.reverse.removeConnLocked(cid, rc)
		s.reverse.mu.Unlock()
	}
	closedNow := false
	rc.mu.Lock()
	if !rc.opClosed || !rc.agentClosed {
		rc.opClosed = true
		rc.agentClosed = true
		_ = rc.operator.Close()
		rc.opCond.Broadcast()
		rc.closeAllReadersLocked() // Шаг C: unblock every parked long-poll
		closedNow = true
	}
	rc.mu.Unlock()
	if closedNow {
		s.logger.Printf("reverse close cid=%s (%s)", cid, reason)
	}
}

// removeConnLocked drops rc from every reverseState index. Caller must hold
// reverseState.mu. Returns a printable cid, looking it up from rc when the
// caller only had a pointer.
func (r *reverseState) removeConnLocked(cid string, rc *reverseConn) string {
	if cid == "" || cid == "?" {
		if known, ok := r.pendCids[rc]; ok {
			cid = known
		}
	}
	if cid != "" && cid != "?" {
		if r.conns[cid] == rc {
			delete(r.conns, cid)
		}
	}
	for known, c := range r.conns {
		if c == rc {
			delete(r.conns, known)
			if cid == "" || cid == "?" {
				cid = known
			}
			break
		}
	}
	if known, ok := r.pendCids[rc]; ok {
		if cid == "" || cid == "?" {
			cid = known
		}
		delete(r.pendCids, rc)
	}
	for i, pending := range r.pending {
		if pending == rc {
			r.pending = append(r.pending[:i], r.pending[i+1:]...)
			break
		}
	}
	if cid == "" {
		return "?"
	}
	return cid
}

// --- Agent DNS endpoints ---------------------------------------------------

// apoll: agent asks "any new tunnels?".  Modern agents include one unique
// poll ID in the authenticated payload.  The server leases (rather than
// removes) a CID and repeats the same OPEN for a retry of that poll ID.  A
// lease without aopen expires and another agent can pick it up.  Empty-payload
// apoll remains the legacy wire format for existing agents.
//
// The agent's source IP is recorded so the server can (1) log a single
// "agent connected" line per new agent and (2) signal ServeSOCKS5 to bind
// only after at least one agent is around to handle CONNECT requests.
func (s *Server) proxyAgentPoll(args []string, now time.Time, client string) []string {
	if !s.allowProxy || s.reverse == nil {
		return []string{proxyDisabledResponse}
	}
	payload, ts, mac, ok := splitAuthenticatedArgs(args)
	if !ok || !protocol.VerifyAuth(s.secret, s.authDomain, "apoll", payload, ts, mac, now) {
		s.reverse.logApollAuthFail(client, ts, now, s.logger)
		return []string{proxyAuthFailResponse}
	}
	if s.reverse.noteAgent(client) {
		s.logger.Printf("agent connected from %s (first apoll)", client)
	}
	if len(payload) > 2 {
		return []string{"ERR malformed"}
	}
	pollID := ""
	protocolVersion := byte(1)
	if len(payload) >= 1 {
		pollID = strings.ToLower(payload[0])
		if !validPollID(pollID) {
			return []string{"ERR bad poll"}
		}
	}
	if len(payload) == 2 {
		if strings.ToLower(payload[1]) != "v2" {
			return []string{"ERR malformed"}
		}
		protocolVersion = 2
	}

	for {
		s.reverse.mu.Lock()
		if len(s.reverse.pending) == 0 {
			s.reverse.mu.Unlock()
			return []string{"EMPTY"}
		}
		if pollID != "" {
			for _, rc := range s.reverse.pending {
				cid := s.reverse.pendCids[rc]
				if cid == "" || s.reverse.conns[cid] != rc {
					continue
				}
				rc.mu.Lock()
				if rc.leaseID == pollID {
					rc.leaseExpires = now.Add(reverseLeaseTTL)
					if protocolVersion > rc.leaseVersion {
						rc.leaseVersion = protocolVersion
					}
					rc.mu.Unlock()
					s.reverse.mu.Unlock()
					return []string{"OPEN " + cid + " " + dnshelpers.B32LowerNoPad.EncodeToString([]byte(rc.target))}
				}
				if rc.leaseID == "" || !now.Before(rc.leaseExpires) {
					rc.leaseID = pollID
					rc.leaseExpires = now.Add(reverseLeaseTTL)
					rc.leaseModern = true
					rc.leaseVersion = protocolVersion
					rc.mu.Unlock()
					s.reverse.mu.Unlock()
					return []string{"OPEN " + cid + " " + dnshelpers.B32LowerNoPad.EncodeToString([]byte(rc.target))}
				}
				rc.mu.Unlock()
			}
			s.reverse.mu.Unlock()
			return []string{"EMPTY"}
		}

		// Legacy behavior: remove the pending entry at pickup and allow the
		// SOCKS handler to proceed.  New agents never use this branch.
		rc := s.reverse.pending[0]
		s.reverse.pending = s.reverse.pending[1:]
		cid := s.reverse.pendCids[rc]
		delete(s.reverse.pendCids, rc)
		_, live := s.reverse.conns[cid]
		s.reverse.mu.Unlock()
		if !live || cid == "" {
			continue
		}
		rc.signalOpen(0x00)
		targetB32 := dnshelpers.B32LowerNoPad.EncodeToString([]byte(rc.target))
		return []string{"OPEN " + cid + " " + targetB32}
	}
}

func validPollID(value string) bool {
	if len(value) != 16 {
		return false
	}
	for _, c := range value {
		if (c >= 'a' && c <= 'f') || (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

// aopen is the modern lease acknowledgement.  It is authenticated with the
// regular command HMAC because no tunnel traffic may flow until the target
// dial result is known.
//
// Wire: cid . pollID . status . timestamp . token . aopen . domain
// status is ok, refused, unreachable, or timeout.
func (s *Server) proxyAgentOpen(args []string, now time.Time) []string {
	if !s.allowProxy || s.reverse == nil {
		return []string{proxyDisabledResponse}
	}
	payload, ts, mac, ok := splitAuthenticatedArgs(args)
	if !ok || !protocol.VerifyAuth(s.secret, s.authDomain, "aopen", payload, ts, mac, now) {
		return []string{proxyAuthFailResponse}
	}
	if len(payload) != 3 {
		return []string{"ERR malformed"}
	}
	cid := strings.ToLower(payload[0])
	pollID := strings.ToLower(payload[1])
	if !gproxy.ValidCID(cid) || !validPollID(pollID) {
		return []string{"ERR malformed"}
	}
	status := map[string]byte{
		"ok":          0x00,
		"refused":     0x05,
		"unreachable": 0x04,
		"timeout":     0x06,
	}[strings.ToLower(payload[2])]
	if status == 0 && strings.ToLower(payload[2]) != "ok" {
		return []string{"ERR malformed"}
	}

	s.reverse.mu.Lock()
	rc, exists := s.reverse.conns[cid]
	if !exists {
		s.reverse.mu.Unlock()
		return []string{"OK"}
	}
	rc.mu.Lock()
	if rc.openPollID == pollID && rc.openStatus == status {
		rc.mu.Unlock()
		s.reverse.mu.Unlock()
		return []string{"OK"}
	}
	if !rc.leaseModern || rc.leaseID != pollID || !now.Before(rc.leaseExpires) {
		rc.mu.Unlock()
		s.reverse.mu.Unlock()
		return []string{"ERR lease"}
	}
	rc.leaseID = ""
	rc.leaseExpires = time.Time{}
	rc.leaseModern = false
	rc.openPollID = pollID
	rc.openStatus = status
	if status == 0x00 {
		// The lease has become an active tunnel.  It must no longer be
		// eligible for any other agent's poll.
		for i, pending := range s.reverse.pending {
			if pending == rc {
				s.reverse.pending = append(s.reverse.pending[:i], s.reverse.pending[i+1:]...)
				break
			}
		}
		delete(s.reverse.pendCids, rc)
	}
	rc.mu.Unlock()
	s.reverse.mu.Unlock()

	rc.signalOpen(status)
	if status != 0x00 {
		s.reverseCloseConn(cid, rc, "agent target dial failed")
	}
	return []string{"OK"}
}

// astatus resolves an ambiguous aopen timeout without mutating tunnel state.
// New agents negotiate this command through apoll's v2 marker; v1 agents keep
// the original aopen-only flow for rolling compatibility.
func (s *Server) proxyAgentStatus(args []string, now time.Time) []string {
	if !s.allowProxy || s.reverse == nil {
		return []string{proxyDisabledResponse}
	}
	payload, ts, mac, ok := splitAuthenticatedArgs(args)
	if !ok || !protocol.VerifyAuth(s.secret, s.authDomain, "astatus", payload, ts, mac, now) || len(payload) != 2 {
		return []string{proxyAuthFailResponse}
	}
	cid := strings.ToLower(payload[0])
	pollID := strings.ToLower(payload[1])
	if !gproxy.ValidCID(cid) || !validPollID(pollID) {
		return []string{"CLOSED"}
	}
	s.reverse.mu.Lock()
	rc := s.reverse.conns[cid]
	if rc == nil {
		s.reverse.mu.Unlock()
		return []string{"CLOSED"}
	}
	rc.mu.Lock()
	state := "CLOSED"
	switch {
	case rc.openPollID == pollID && rc.openStatus == 0x00:
		state = "OPEN"
	case rc.leaseVersion >= 2 && rc.leaseID == pollID && now.Before(rc.leaseExpires):
		state = "PENDING"
	}
	rc.mu.Unlock()
	s.reverse.mu.Unlock()
	return []string{state}
}

// aread: agent fetches operator-to-target bytes for cid. Returns
// "DATA <seq>" + base64 ciphertext chunks, or "EMPTY", or "CLOSED".
//
// Wire (post-session-MAC cutover):
//
//	cid . nonce . ["x-tcp"] . smac . aread . domain
func (s *Server) proxyAgentRead(args []string, now time.Time) []string {
	if !s.allowProxy || s.reverse == nil {
		return []string{proxyDisabledResponse}
	}
	if len(args) < 3 || len(args) > 4 {
		return []string{"ERR malformed"}
	}
	cid := strings.ToLower(args[0])
	if !gproxy.ValidCID(cid) {
		return []string{"ERR bad cid"}
	}
	nonce, err := strconv.ParseUint(args[1], 16, 64)
	if err != nil {
		return []string{"ERR bad nonce"}
	}
	smac := args[len(args)-1]
	maxRead := gproxy.MaxReadBytes
	if len(args) == 4 {
		if args[2] != gproxy.AxchgTCPMarker && args[2] != "tcp" {
			return []string{"ERR malformed"}
		}
		maxRead = gproxy.MaxReadBytesTCP
	}

	s.reverse.mu.Lock()
	rc, ok := s.reverse.conns[cid]
	s.reverse.mu.Unlock()
	if !ok {
		return []string{"CLOSED"}
	}
	if !protocol.VerifySessionMAC(rc.sessionKey, "aread", nonce, smac) {
		return []string{proxyAuthFailResponse}
	}

	rc.mu.Lock()
	if !rc.acceptNonce(nonce) {
		rc.mu.Unlock()
		return []string{proxyAuthFailResponse}
	}
	bufEmpty := rc.opToAgent.Len() == 0
	rc.mu.Unlock()
	if bufEmpty {
		rc.awaitReadData(longPollWindow) // Шаг C
	}

	rc.mu.Lock()
	if rc.opToAgent.Len() == 0 {
		isClosed := rc.opClosed || rc.agentClosed
		rc.expires = now.Add(reverseTTL)
		rc.mu.Unlock()
		if isClosed {
			return []string{"CLOSED"}
		}
		return []string{"WAIT"}
	}
	// Reserve one byte of plaintext budget for the compressor's flag byte
	// (see internal/proxy/compress.go). Without this, an incompressible
	// chunk would tip the on-wire size over maxRead.
	take := rc.opToAgent.Len()
	if take > maxRead-1 {
		take = maxRead - 1
	}
	rawBuf := gproxy.GetBuf(take)
	// defer rather than eager release so a panic in compressor.Encode or
	// SealChunkTo doesn't leak the pooled buffer.
	defer gproxy.PutBuf(rawBuf)
	_, _ = rc.opToAgent.Read(*rawBuf)
	rc.seqOpToA++
	seq := rc.seqOpToA
	rc.expires = now.Add(reverseTTL)
	rc.opCond.Broadcast() // wake operator pump if it was blocked
	rc.mu.Unlock()

	plaintext := rc.compressor.Encode(*rawBuf)
	// Seal into a pooled dst buffer — base64.EncodeToString below allocates
	// its own string, so `b64` doesn't reference the pool buffer once
	// EncodeToString returns; the defer releases the scratch on all paths.
	ctBufPtr := gproxy.GetBuf(len(plaintext) + 16)
	defer gproxy.PutBuf(ctBufPtr)
	ct := gproxy.SealChunkTo((*ctBufPtr)[:0], rc.aead, gproxy.DirServerToClient, seq, plaintext)
	b64 := base64.StdEncoding.EncodeToString(ct)
	out := []string{"DATA " + strconv.FormatUint(seq, 16)}
	out = append(out, codec.ChunkString(b64, codec.TXTChunkSize)...)
	return out
}

// awrite: agent posts target-to-operator bytes. Server decrypts and writes
// to operator's TCP socket.
//
// Wire (post-session-MAC cutover):
//
//	cid . seq . chunk1 . chunk2 ... . smac . awrite . domain
//
// The seq is both the per-cid awrite ordering key (replay-protected via
// rc.seqAgentIn) and the input to the session MAC, so no extra nonce is
// needed.
func (s *Server) proxyAgentWrite(args []string, now time.Time) []string {
	if !s.allowProxy || s.reverse == nil {
		return []string{proxyDisabledResponse}
	}
	if len(args) < 4 {
		return []string{"ERR malformed"}
	}
	cid := strings.ToLower(args[0])
	if !gproxy.ValidCID(cid) {
		return []string{"ERR bad cid"}
	}
	seq, err := strconv.ParseUint(args[1], 16, 64)
	if err != nil {
		return []string{"ERR bad seq"}
	}
	smac := args[len(args)-1]
	dataLabels := args[2 : len(args)-1]
	if len(dataLabels) == 0 {
		return []string{"ERR malformed"}
	}

	s.reverse.mu.Lock()
	rc, ok := s.reverse.conns[cid]
	s.reverse.mu.Unlock()
	if !ok {
		return []string{"ERR unknown cid"}
	}
	if !protocol.VerifySessionMAC(rc.sessionKey, "awrite", seq, smac) {
		return []string{proxyAuthFailResponse}
	}

	rc.mu.Lock()
	if rc.opClosed || rc.agentClosed {
		rc.mu.Unlock()
		return []string{"ERR closed"}
	}
	if seq <= rc.seqAgentIn {
		rc.expires = now.Add(reverseTTL)
		rc.mu.Unlock()
		return []string{"OK"}
	}
	if seq > rc.seqAgentIn+awriteWindow {
		rc.mu.Unlock()
		return []string{"ERR seq"}
	}
	rc.mu.Unlock()

	// Agents send lowercase base32; some resolvers upper-case DNS labels
	// in transit. B32DecodeAny picks the right decoder without an extra
	// strings.ToUpper allocation on the hot chunk-write path.
	encoded := strings.Join(dataLabels, "")
	ciphertext, err := dnshelpers.B32DecodeAny(encoded)
	if err != nil {
		return []string{"ERR " + err.Error()}
	}
	// Open into a pooled dst; compressor.Decode below returns a fresh
	// slice so we can release the plaintext scratch after Decode reads it.
	ptBufPtr := gproxy.GetBuf(len(ciphertext))
	plaintext, err := gproxy.OpenChunkTo((*ptBufPtr)[:0], rc.aead, gproxy.DirClientToServer, seq, ciphertext)
	defer gproxy.PutBuf(ptBufPtr)
	if err != nil {
		return []string{"ERR open"}
	}
	decompressed, err := rc.compressor.Decode(plaintext)
	if err != nil {
		return []string{"ERR decompress"}
	}

	rc.mu.Lock()
	if seq <= rc.seqAgentIn {
		rc.expires = now.Add(reverseTTL)
		rc.mu.Unlock()
		return []string{"OK"}
	}
	if rc.oooWrite == nil {
		rc.oooWrite = make(map[uint64][]byte)
	}
	rc.oooWrite[seq] = decompressed
	for {
		batch := rc.drainContiguousWritesLocked(drainBatchSize)
		if len(batch) == 0 {
			break
		}
		// Acquire writeMu before releasing rc.mu so the writev order
		// matches the drain order (rc.mu → writeMu hierarchy).
		rc.writeMu.Lock()
		rc.mu.Unlock()
		err := rc.commitOperatorWrite(batch)
		rc.writeMu.Unlock()
		if err != nil {
			s.reverseCloseConn(cid, rc, "operator write: "+err.Error())
			return []string{"ERR write"}
		}
		rc.mu.Lock()
	}
	rc.expires = now.Add(reverseTTL)
	rc.mu.Unlock()
	return []string{"OK"}
}

// aclose: agent signals tunnel closure (target EOF or agent-side error).
//
// Wire (post-session-MAC cutover):
//
//	cid . nonce . smac . aclose . domain
//
// Idempotent — repeated aclose on the same nonce is silently absorbed (the
// agent might retry on a DNS timeout). Unknown-cid still answers OK so the
// agent's defer doesn't have to distinguish "raced GC" from a real failure.
func (s *Server) proxyAgentClose(args []string, now time.Time) []string {
	if !s.allowProxy || s.reverse == nil {
		return []string{proxyDisabledResponse}
	}
	if len(args) != 3 {
		return []string{"ERR malformed"}
	}
	cid := strings.ToLower(args[0])
	if !gproxy.ValidCID(cid) {
		return []string{"ERR bad cid"}
	}
	nonce, err := strconv.ParseUint(args[1], 16, 64)
	if err != nil {
		return []string{"ERR bad nonce"}
	}
	smac := args[2]

	s.reverse.mu.Lock()
	rc, ok := s.reverse.conns[cid]
	s.reverse.mu.Unlock()
	if !ok {
		return []string{"OK"}
	}
	if !protocol.VerifySessionMAC(rc.sessionKey, "aclose", nonce, smac) {
		return []string{proxyAuthFailResponse}
	}
	// We deliberately don't reject duplicate nonces here — aclose is
	// already idempotent. The MAC binds the nonce, so replay can't free
	// new state.
	_ = now
	s.reverseCloseConn(cid, rc, "agent close")
	return []string{"OK"}
}

// axchg: full-duplex hot path. One DNS query carries an awrite chunk *and*
// pulls an aread chunk in the same round-trip. For SSH/REPL-style traffic
// this halves the perceived latency vs sequential awrite+aread.
//
// Wire (request):
//
//	cid . write_seq . chunk1 . chunk2 ... . ["x-tcp"] . read_nonce . smac . axchg . domain
//
// write_seq == 0 means "no payload, this is a pure read". When write_seq > 0
// the labels between it and read_nonce are the base32 ciphertext chunks (same
// encoding as awrite).
//
// Wire (TXT response, two-line minimum):
//
//	"ACK <write_seq>"          (or "ACK 0" for pure read)
//	"DATA <read_seq>" + b64    or "EMPTY" or "CLOSED" or "WAIT"
//	... b64 chunks ...
//
// MAC is computed over (axchg, read_nonce) — write_seq is implicitly bound
// via the awrite-seq replay tracking (rc.seqAgentIn), so a single nonce
// guards just the aread component.
func (s *Server) proxyAgentExchange(args []string, now time.Time) []string {
	if !s.allowProxy || s.reverse == nil {
		return []string{proxyDisabledResponse}
	}
	if len(args) < 4 {
		return []string{"ERR malformed"}
	}
	cid := strings.ToLower(args[0])
	if !gproxy.ValidCID(cid) {
		return []string{"ERR bad cid"}
	}
	writeSeq, err := strconv.ParseUint(args[1], 16, 64)
	if err != nil {
		return []string{"ERR bad seq"}
	}
	smac := args[len(args)-1]
	readNonce, err := strconv.ParseUint(args[len(args)-2], 16, 64)
	if err != nil {
		return []string{"ERR bad nonce"}
	}
	// Optional read ACK and TCP hint live immediately before the nonce/smac
	// trailer.  They contain '-' and therefore cannot collide with base32
	// ciphertext labels.
	maxRead := gproxy.MaxReadBytes
	chunksEnd := len(args) - 2
	var readAck uint64
	if chunksEnd > 0 && strings.HasPrefix(args[chunksEnd-1], "a-") {
		readAck, err = strconv.ParseUint(strings.TrimPrefix(args[chunksEnd-1], "a-"), 16, 64)
		if err != nil {
			return []string{"ERR bad ack"}
		}
		chunksEnd--
	}
	if chunksEnd > 0 && args[chunksEnd-1] == gproxy.AxchgTCPMarker {
		maxRead = gproxy.MaxReadBytesTCP
		chunksEnd--
	}
	dataLabels := args[2:chunksEnd]

	s.reverse.mu.Lock()
	rc, ok := s.reverse.conns[cid]
	s.reverse.mu.Unlock()
	if !ok {
		return []string{"CLOSED"}
	}
	if !protocol.VerifySessionMAC(rc.sessionKey, "axchg", readNonce, smac) {
		return []string{proxyAuthFailResponse}
	}

	rc.mu.Lock()
	cached, wait, owner := rc.beginResponse(readNonce, now)
	if cached != nil {
		rc.mu.Unlock()
		return cached
	}
	if wait != nil {
		rc.mu.Unlock()
		select {
		case <-wait:
			rc.mu.Lock()
			entry := rc.responseCache[readNonce]
			if out := rc.materializeCachedResponseLocked(entry); out != nil {
				rc.mu.Unlock()
				return out
			}
			rc.mu.Unlock()
			return []string{"ERR retry"}
		case <-time.After(longPollWindow + time.Second):
			return []string{"ERR retry"}
		}
	}
	if !owner {
		rc.mu.Unlock()
		return []string{proxyAuthFailResponse}
	}
	duplicateNonce := !rc.acceptNonce(readNonce)
	rc.applyReadAck(readAck)
	rc.mu.Unlock()

	// --- Write phase (if any) ------------------------------------------------
	writeStatus := "ACK " + strconv.FormatUint(writeSeq, 16)
	if writeSeq > 0 {
		if len(dataLabels) == 0 {
			out := []string{"ERR malformed"}
			rc.finishResponse(readNonce, out, now)
			return out
		}
		writeStatus = s.applyAxchgWrite(rc, writeSeq, dataLabels, now)
		if strings.HasPrefix(writeStatus, "ERR") {
			out := []string{writeStatus}
			rc.finishResponse(readNonce, out, now)
			return out
		}
	}

	// A compact response-cache entry may have been evicted before a delayed
	// TCP retry arrived. The nonce proves this request was handled already.
	// Re-apply the write idempotently, but never drain a new read chunk: return
	// the oldest retained outbound sequence (or EMPTY/CLOSED) instead.
	if duplicateNonce {
		readSegs := s.collectRetainedAxchgRead(rc, now)
		out := make([]string, 0, 1+len(readSegs))
		out = append(out, writeStatus)
		out = append(out, readSegs...)
		rc.finishResponse(readNonce, out, now)
		return out
	}

	// --- Read phase ----------------------------------------------------------
	// Long-poll only makes sense on pure-read axchgs. When the request
	// already delivered a write chunk, the server has done useful work and
	// should answer immediately so the agent's pipeline doesn't stall on
	// 16 workers all parked for longPollWindow at once.
	readSegs := s.collectAxchgRead(rc, maxRead, now, writeSeq == 0)

	out := make([]string, 0, 1+len(readSegs))
	out = append(out, writeStatus)
	out = append(out, readSegs...)
	rc.finishResponse(readNonce, out, now)
	return out
}

// applyAxchgWrite folds the awrite seq/data path into a single call so axchg
// doesn't duplicate proxyAgentWrite. Returns the per-protocol status string
// ("ACK <seq>", "ERR ...") to put on the first response line.
func (s *Server) applyAxchgWrite(rc *reverseConn, seq uint64, dataLabels []string, now time.Time) string {
	rc.mu.Lock()
	if rc.opClosed || rc.agentClosed {
		rc.mu.Unlock()
		return "ERR closed"
	}
	if seq <= rc.seqAgentIn {
		rc.expires = now.Add(reverseTTL)
		rc.mu.Unlock()
		return "ACK " + strconv.FormatUint(seq, 16)
	}
	if seq > rc.seqAgentIn+awriteWindow {
		rc.mu.Unlock()
		return "ERR seq"
	}
	rc.mu.Unlock()

	// Agents send lowercase base32; some resolvers upper-case DNS labels
	// in transit. B32DecodeAny picks the right decoder without an extra
	// strings.ToUpper allocation on the hot chunk-write path.
	encoded := strings.Join(dataLabels, "")
	ciphertext, err := dnshelpers.B32DecodeAny(encoded)
	if err != nil {
		return "ERR " + err.Error()
	}
	// Open into a pooled dst; compressor.Decode below returns a fresh
	// slice so we can release the plaintext scratch after Decode reads it.
	ptBufPtr := gproxy.GetBuf(len(ciphertext))
	plaintext, err := gproxy.OpenChunkTo((*ptBufPtr)[:0], rc.aead, gproxy.DirClientToServer, seq, ciphertext)
	defer gproxy.PutBuf(ptBufPtr)
	if err != nil {
		return "ERR open"
	}
	decompressed, err := rc.compressor.Decode(plaintext)
	if err != nil {
		return "ERR decompress"
	}

	rc.mu.Lock()
	if seq <= rc.seqAgentIn {
		rc.expires = now.Add(reverseTTL)
		rc.mu.Unlock()
		return "ACK " + strconv.FormatUint(seq, 16)
	}
	if rc.oooWrite == nil {
		rc.oooWrite = make(map[uint64][]byte)
	}
	rc.oooWrite[seq] = decompressed
	for {
		batch := rc.drainContiguousWritesLocked(drainBatchSize)
		if len(batch) == 0 {
			break
		}
		// Acquire writeMu before releasing rc.mu so the writev order
		// matches the drain order (rc.mu → writeMu hierarchy).
		rc.writeMu.Lock()
		rc.mu.Unlock()
		err := rc.commitOperatorWrite(batch)
		rc.writeMu.Unlock()
		if err != nil {
			cidLookup := s.cidForReverseConn(rc)
			s.reverseCloseConn(cidLookup, rc, "operator write: "+err.Error())
			return "ERR write"
		}
		rc.mu.Lock()
	}
	rc.expires = now.Add(reverseTTL)
	rc.mu.Unlock()
	return "ACK " + strconv.FormatUint(seq, 16)
}

// collectAxchgRead drains up to maxRead bytes of op→agent data into a TXT
// segment list ("DATA <seq>" + b64 chunks), or returns ["EMPTY"]/["CLOSED"]
// when there's nothing pending / the tunnel is dead.
//
// Шаг C: when allowLongPoll is true and the buffer is empty on entry, the
// call parks for up to longPollWindow waiting for new operator bytes. A
// signal from reversePumpOperator wakes us inside ~one operator-side TCP
// segment. Callers pass allowLongPoll=false on the write-bearing axchg
// path so a 16-worker pipeline doesn't stall behind 16 simultaneous parks.
func (s *Server) collectAxchgRead(rc *reverseConn, maxRead int, now time.Time, allowLongPoll bool) []string {
	if allowLongPoll {
		rc.mu.Lock()
		bufEmpty := rc.opToAgent.Len() == 0
		rc.mu.Unlock()
		if bufEmpty {
			rc.awaitReadData(longPollWindow)
		}
	}

	rc.mu.Lock()
	if len(rc.outbound)+rc.outboundInFlight >= maxOutboundUnacked {
		if data := rc.oldestOutboundLocked(); data != nil {
			rc.expires = now.Add(reverseTTL)
			rc.mu.Unlock()
			return data
		}
		rc.mu.Unlock()
		return []string{"EMPTY"}
	}
	if rc.opToAgent.Len() == 0 {
		isClosed := rc.opClosed || rc.agentClosed
		rc.expires = now.Add(reverseTTL)
		rc.mu.Unlock()
		if isClosed {
			return []string{"CLOSED"}
		}
		return []string{"EMPTY"}
	}
	take := rc.opToAgent.Len()
	if take > maxRead-1 {
		take = maxRead - 1
	}
	rawBuf := gproxy.GetBuf(take)
	// See collectAgentRead for the panic-safe defer pattern rationale.
	defer gproxy.PutBuf(rawBuf)
	_, _ = rc.opToAgent.Read(*rawBuf)
	rc.seqOpToA++
	seq := rc.seqOpToA
	rc.outboundInFlight++
	rc.outboundReservedBytes += take
	rc.expires = now.Add(reverseTTL)
	rc.mu.Unlock()

	plaintext := rc.compressor.Encode(*rawBuf)
	// Same pool-friendly seal pattern as collectAgentRead.
	ctBufPtr2 := gproxy.GetBuf(len(plaintext) + 16)
	defer gproxy.PutBuf(ctBufPtr2)
	ct := gproxy.SealChunkTo((*ctBufPtr2)[:0], rc.aead, gproxy.DirServerToClient, seq, plaintext)
	b64 := base64.StdEncoding.EncodeToString(ct)
	out := []string{"DATA " + strconv.FormatUint(seq, 16)}
	out = append(out, codec.ChunkString(b64, codec.TXTChunkSize)...)
	rc.mu.Lock()
	if rc.outbound == nil {
		rc.outbound = make(map[uint64]outboundProxyResponse)
	}
	rc.outboundInFlight--
	rc.outboundReservedBytes -= take
	rc.outbound[seq] = outboundProxyResponse{segments: cloneSegments(out), plainBytes: take}
	rc.outboundPlainBytes += take
	rc.mu.Unlock()
	return out
}

func (rc *reverseConn) oldestOutboundLocked() []string {
	var (
		seq  uint64
		data []string
	)
	for candidate, retained := range rc.outbound {
		if candidate <= rc.readAck {
			continue
		}
		if data == nil || candidate < seq {
			seq, data = candidate, retained.segments
		}
	}
	return cloneSegments(data)
}

func (s *Server) collectRetainedAxchgRead(rc *reverseConn, now time.Time) []string {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if data := rc.oldestOutboundLocked(); data != nil {
		rc.expires = now.Add(reverseTTL)
		return data
	}
	rc.expires = now.Add(reverseTTL)
	if rc.opClosed || rc.agentClosed {
		return []string{"CLOSED"}
	}
	return []string{"EMPTY"}
}

// cidForReverseConn does a reverse lookup; used only on the rare error path
// where we already have rc but need to print the cid for logging.
func (s *Server) cidForReverseConn(rc *reverseConn) string {
	s.reverse.mu.Lock()
	defer s.reverse.mu.Unlock()
	for cid, c := range s.reverse.conns {
		if c == rc {
			return cid
		}
	}
	return "?"
}

// --- Cleanup & shutdown ----------------------------------------------------

func (s *Server) proxyCleanupExpiredLocked(now time.Time) {
	if s.reverse == nil {
		return
	}
	s.reverse.mu.Lock()
	snapshot := make([]struct {
		cid string
		rc  *reverseConn
	}, 0, len(s.reverse.conns))
	for cid, rc := range s.reverse.conns {
		snapshot = append(snapshot, struct {
			cid string
			rc  *reverseConn
		}{cid: cid, rc: rc})
	}
	s.reverse.mu.Unlock()

	var expiredConns []struct {
		cid string
		rc  *reverseConn
	}
	for _, item := range snapshot {
		item.rc.mu.Lock()
		if item.rc.leaseModern && !now.Before(item.rc.leaseExpires) {
			// Keep the CID in pending: the next agent poll will acquire a
			// new lease.  Only the abandoned lease itself expires.
			item.rc.leaseID = ""
			item.rc.leaseExpires = time.Time{}
			item.rc.leaseModern = false
		}
		for nonce, entry := range item.rc.responseCache {
			if entry.ready && !now.Before(entry.expires) {
				delete(item.rc.responseCache, nonce)
			}
		}
		expired := now.After(item.rc.expires)
		both := item.rc.opClosed && item.rc.agentClosed
		item.rc.mu.Unlock()
		if !expired && !both {
			continue
		}
		expiredConns = append(expiredConns, struct {
			cid string
			rc  *reverseConn
		}{cid: item.cid, rc: item.rc})
	}
	// These maps are diagnostic-only.  Without cleanup a long-running
	// server that sees many transient DNS source addresses grows forever.
	s.reverse.agentReadyMu.Lock()
	for addr, seen := range s.reverse.knownAgents {
		if now.Sub(seen) > reverseTTL {
			delete(s.reverse.knownAgents, addr)
		}
	}
	s.reverse.agentReadyMu.Unlock()
	s.reverse.authFailLogMu.Lock()
	for addr, seen := range s.reverse.lastAuthFailLog {
		if now.Sub(seen) > reverseTTL {
			delete(s.reverse.lastAuthFailLog, addr)
		}
	}
	s.reverse.authFailLogMu.Unlock()
	for _, item := range expiredConns {
		s.reverseCloseConn(item.cid, item.rc, "idle past "+reverseTTL.String())
	}
}

// proxyShutdown closes the SOCKS5 listener and every live tunnel.
func (s *Server) proxyShutdown() {
	if s.reverse == nil {
		return
	}
	s.reverse.shutdownOnce.Do(func() {
		close(s.reverse.shutdownCh)
	})
	s.reverse.mu.Lock()
	if s.reverse.socksLn != nil {
		_ = s.reverse.socksLn.Close()
	}
	conns := make(map[string]*reverseConn, len(s.reverse.conns))
	for k, v := range s.reverse.conns {
		conns[k] = v
	}
	s.reverse.conns = make(map[string]*reverseConn)
	s.reverse.pending = nil
	s.reverse.mu.Unlock()
	for cid, rc := range conns {
		s.reverseCloseConn(cid, rc, "server shutdown")
	}
}

// --- SOCKS5 wire helpers (RFC 1928 + RFC 1929 auth) ------------------------

const (
	socks5UserPassMethod = 0x02
)

// socks5NoAuthSelect handles the method-selection step when -socks-no-auth is
// set: the server advertises NO AUTHENTICATION REQUIRED (0x00). The client's
// proposed method list is read but only honored insofar as method 0x00 is
// present — any well-formed client offers it.
func socks5NoAuthSelect(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("read methods header: %w", err)
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version %d", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return errors.New("client did not offer no-auth method")
	}
	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

// socks5Authenticate negotiates method 0x02 (username/password) per RFC 1929.
// Username is fixed to "gdns2tcp"; password must equal the server's -secret.
func socks5Authenticate(conn net.Conn, secret string) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("read methods header: %w", err)
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("unsupported SOCKS version %d", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	hasUserPass := false
	for _, m := range methods {
		if m == socks5UserPassMethod {
			hasUserPass = true
			break
		}
	}
	if !hasUserPass {
		_, _ = conn.Write([]byte{0x05, 0xFF})
		return errors.New("client did not offer username/password method")
	}
	if _, err := conn.Write([]byte{0x05, socks5UserPassMethod}); err != nil {
		return err
	}
	// Subnegotiation: VER(1)=01, ULEN(1), UNAME, PLEN(1), PASSWD.
	vlen := make([]byte, 2)
	if _, err := io.ReadFull(conn, vlen); err != nil {
		return err
	}
	if vlen[0] != 0x01 {
		return fmt.Errorf("unsupported subneg version %d", vlen[0])
	}
	uname := make([]byte, int(vlen[1]))
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	passwd := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return err
	}
	if string(uname) != "gdns2tcp" || string(passwd) != secret {
		_, _ = conn.Write([]byte{0x01, 0x01}) // status≠0 = failure
		return errors.New("invalid credentials")
	}
	_, _ = conn.Write([]byte{0x01, 0x00}) // success
	return nil
}

// socks5ReadConnect parses the CONNECT request and returns "host:port".
func socks5ReadConnect(conn net.Conn) (string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 || head[1] != 0x01 {
		return "", fmt.Errorf("unsupported VER/CMD %d/%d", head[0], head[1])
	}
	var host string
	switch head[3] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", err
		}
		buf := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		return "", fmt.Errorf("unsupported ATYP %d", head[3])
	}
	pbuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, pbuf); err != nil {
		return "", err
	}
	port := int(binary.BigEndian.Uint16(pbuf))
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func socks5WriteReply(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// tuneTCPConn applies the TCP_NODELAY + SO_KEEPALIVE pair to a connection
// when it's a *net.TCPConn (the common case here — SOCKS5 operators dial
// over TCP). Silently a no-op for non-TCP transports such as net.Pipe used
// in unit tests.
//
// Why both:
//   - NoDelay: a SSH/REPL keystroke flushes ~5 bytes; without NoDelay Nagle
//     batches it with the next ACK, adding up to ~40 ms of perceived RTT.
//   - KeepAlive: long-idle SOCKS5 sessions silently die in NAT after a few
//     minutes. The 30 s probe interval keeps the conntrack entry warm.
func tuneTCPConn(c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(30 * time.Second)
}
