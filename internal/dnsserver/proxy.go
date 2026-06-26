package dnsserver

import (
	"bytes"
	"crypto/cipher"
	"encoding/base32"
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

	// Anti-replay window for read-side commands (aread/aclose). The agent
	// chooses a monotonic nonce per request; the server accepts each one at
	// most once. We track the highest seen nonce (nonceFloor) and a 64-bit
	// bitmap for nonces in the trailing window. Out-of-order arrivals up to
	// 64 behind the floor are still accepted; older ones are dropped.
	nonceFloor  uint64
	nonceBitmap uint64

	// readWaiters fans the "new operator bytes" signal out to every
	// long-poll axchg/aread that's currently parked. reversePumpOperator
	// closes them all on each opToAgent.Write so any in-flight long-poll
	// wakes up immediately (Шаг C). Slice is drained on each signal —
	// waiters re-register on their next call if they need to wait again.
	readWaiters []chan struct{}
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
func (rc *reverseConn) acceptNonce(n uint64) bool {
	if n == 0 {
		return false
	}
	if n > rc.nonceFloor {
		shift := n - rc.nonceFloor
		if shift >= 64 {
			rc.nonceBitmap = 0
		} else {
			rc.nonceBitmap <<= shift
		}
		rc.nonceFloor = n
		rc.nonceBitmap |= 1
		return true
	}
	// n <= floor: check whether it's still inside the trailing window.
	diff := rc.nonceFloor - n
	if diff >= 64 {
		return false
	}
	mask := uint64(1) << diff
	if rc.nonceBitmap&mask != 0 {
		return false
	}
	rc.nonceBitmap |= mask
	return true
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
	if err := socks5WriteReply(conn, 0x00); err != nil {
		s.reverseCloseConn(cid, rc, "socks5 reply write: "+err.Error())
		return
	}
	s.logger.Printf("socks5 open cid=%s op=%s target=%s", cid, conn.RemoteAddr(), target)

	// Pump local socket → opToAgent buffer. The aread handler drains it.
	s.reversePumpOperator(cid, rc)
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
	buf := make([]byte, 4096)
	for {
		n, err := rc.operator.Read(buf)
		if n > 0 {
			rc.mu.Lock()
			for !rc.opClosed && !rc.agentClosed && rc.opToAgent.Len()+n > s.reverse.maxBufCap {
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

	if s.reverse != nil {
		s.reverse.mu.Lock()
		cid = s.reverse.removeConnLocked(cid, rc)
		s.reverse.mu.Unlock()
	}
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

// apoll: agent asks "any new tunnels?". Returns "OPEN <cid> <target_b32>" or
// "EMPTY". Idempotent — the same cid is handed to the first apoll that pulls
// it; we don't requeue.
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

	for {
		s.reverse.mu.Lock()
		if len(s.reverse.pending) == 0 {
			s.reverse.mu.Unlock()
			return []string{"EMPTY"}
		}
		rc := s.reverse.pending[0]
		s.reverse.pending = s.reverse.pending[1:]
		cid := s.reverse.pendCids[rc]
		delete(s.reverse.pendCids, rc)
		_, live := s.reverse.conns[cid]
		s.reverse.mu.Unlock()
		if !live || cid == "" {
			continue
		}

		targetB32 := strings.ToLower(reverseB32().EncodeToString([]byte(rc.target)))
		return []string{"OPEN " + cid + " " + targetB32}
	}
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
	_, _ = rc.opToAgent.Read(*rawBuf)
	rc.seqOpToA++
	seq := rc.seqOpToA
	rc.expires = now.Add(reverseTTL)
	rc.opCond.Broadcast() // wake operator pump if it was blocked
	rc.mu.Unlock()

	plaintext := rc.compressor.Encode(*rawBuf)
	gproxy.PutBuf(rawBuf)
	ct := gproxy.SealChunk(rc.aead, gproxy.DirServerToClient, seq, plaintext)
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

	encoded := strings.ToUpper(strings.Join(dataLabels, ""))
	ciphertext, err := reverseB32().DecodeString(encoded)
	if err != nil {
		return []string{"ERR " + err.Error()}
	}
	plaintext, err := gproxy.OpenChunk(rc.aead, gproxy.DirClientToServer, seq, ciphertext)
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
	// Optional TCP hint, like aread. Goes just before the nonce/smac trailer.
	// The marker must not be a bare base32 word; otherwise a ciphertext label
	// can be mistaken for transport metadata.
	maxRead := gproxy.MaxReadBytes
	chunksEnd := len(args) - 2
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
	if !rc.acceptNonce(readNonce) {
		rc.mu.Unlock()
		return []string{proxyAuthFailResponse}
	}
	rc.mu.Unlock()

	// --- Write phase (if any) ------------------------------------------------
	writeStatus := "ACK " + strconv.FormatUint(writeSeq, 16)
	if writeSeq > 0 {
		if len(dataLabels) == 0 {
			return []string{"ERR malformed"}
		}
		writeStatus = s.applyAxchgWrite(rc, writeSeq, dataLabels, now)
		if strings.HasPrefix(writeStatus, "ERR") {
			return []string{writeStatus}
		}
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

	encoded := strings.ToUpper(strings.Join(dataLabels, ""))
	ciphertext, err := reverseB32().DecodeString(encoded)
	if err != nil {
		return "ERR " + err.Error()
	}
	plaintext, err := gproxy.OpenChunk(rc.aead, gproxy.DirClientToServer, seq, ciphertext)
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
	_, _ = rc.opToAgent.Read(*rawBuf)
	rc.seqOpToA++
	seq := rc.seqOpToA
	rc.expires = now.Add(reverseTTL)
	rc.opCond.Broadcast()
	rc.mu.Unlock()

	plaintext := rc.compressor.Encode(*rawBuf)
	gproxy.PutBuf(rawBuf) // raw was copied into compressor's output; release now
	ct := gproxy.SealChunk(rc.aead, gproxy.DirServerToClient, seq, plaintext)
	b64 := base64.StdEncoding.EncodeToString(ct)
	out := []string{"DATA " + strconv.FormatUint(seq, 16)}
	out = append(out, codec.ChunkString(b64, codec.TXTChunkSize)...)
	return out
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

func reverseB32() *base32.Encoding {
	return base32.StdEncoding.WithPadding(base32.NoPadding)
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
