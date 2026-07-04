// Command gdns2tcp-client-proxy is the agent that runs inside a target
// network. It long-polls the gdns2tcp server's apoll endpoint for new tunnel
// requests, dials the requested host:port locally, and bridges bytes back to
// the operator through aread/awrite. The operator never talks DNS — they hit
// the server's SOCKS5/TCP listener on port 9050 directly.
package main

import (
	"context"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
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

const defaultDNSPort = "53"

type config struct {
	// domain is the canonical DNS domain — the one baked into HMAC
	// signatures. For single-domain configs it also equals the QNAME
	// suffix. For sharded configs it's the first entry of shardDomains.
	domain string
	// shardDomains is the full accepted set (canonical first). QNAMEs
	// rotate through this list round-robin so per-domain resolver
	// rate-limits accumulate rather than serialize on one zone.
	shardDomains []string
	// shardAuthDomains is protocol.AuthDomain(shardDomains[i]) precomputed
	// once at parseFlags time — the shape JoinNameFast wants as suffix.
	shardAuthDomains []string
	// shardLongest is the longest domain in shardDomains — used for the
	// worst-case budget in maxAxchgWritePlaintextBytes so no shard can
	// overflow the 253-char QNAME limit.
	shardLongest string
	// shardRotor drives round-robin selection from apoll/aclose (which
	// don't have a natural per-worker index). axchg workers hold their
	// own local counter for cheaper contention-free rotation.
	shardRotor *atomic.Uint64

	pass          string
	dnsServer     string
	dnsPort       string
	tcp           bool
	pollMin       time.Duration
	pollMax       time.Duration
	maxConn       int
	retries       int
	targetTimeout time.Duration
}

// longestBudgetDomain returns the domain the QNAME-length budget must
// assume worst-case — parseFlags precomputes shardLongest, but test
// fixtures build config{} directly, so fall back to cfg.domain there.
func (c config) longestBudgetDomain() string {
	if c.shardLongest != "" {
		return c.shardLongest
	}
	return c.domain
}

// pickShardAuthDomain returns the next shard suffix for a non-worker
// caller (apoll/aclose) by round-robining shardRotor. Single-domain
// configs skip the atomic and just return the sole entry. Configs
// constructed without parseFlags (test fixtures) fall back to computing
// AuthDomain from cfg.domain directly.
func (c config) pickShardAuthDomain() string {
	if len(c.shardAuthDomains) == 0 {
		return protocol.AuthDomain(c.domain)
	}
	if len(c.shardAuthDomains) == 1 || c.shardRotor == nil {
		return c.shardAuthDomains[0]
	}
	idx := c.shardRotor.Add(1) % uint64(len(c.shardAuthDomains))
	return c.shardAuthDomains[idx]
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := parseFlags()
	if cfg.domain == "" {
		return errors.New("domain is required")
	}
	if cfg.pass == "" {
		return errors.New("password is required")
	}
	if cfg.dnsServer == "" {
		addr, err := autoResolverAddr(cfg.domain)
		if err != nil {
			return err
		}
		cfg.dnsServer = addr
		fmt.Printf("using DNS server %s:%s for %s\n", cfg.dnsServer, cfg.dnsPort, cfg.domain)
	}
	resolver := newTxtResolver(cfg)
	fmt.Printf("polling %s for tunnel requests (max %d concurrent)\n", cfg.domain, cfg.maxConn)

	var live atomic.Int64
	delay := cfg.pollMin
	for {
		if int(live.Load()) >= cfg.maxConn {
			time.Sleep(cfg.pollMax)
			continue
		}
		cid, target, err := agentPoll(cfg, resolver)
		if err != nil {
			fmt.Fprintf(os.Stderr, "apoll: %v\n", err)
			time.Sleep(cfg.pollMax)
			continue
		}
		if cid == "" {
			time.Sleep(delay)
			delay *= 2
			if delay > cfg.pollMax {
				delay = cfg.pollMax
			}
			continue
		}
		delay = cfg.pollMin
		live.Add(1)
		go func(cid, target string) {
			defer live.Add(-1)
			handleTunnel(cfg, resolver, cid, target)
		}(cid, target)
	}
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.domain, "domain", "", "authoritative gdns2tcp domain. Accepts a single name or CSV list (a.com,b.com,c.com) — the first is used as the canonical HMAC domain, all are rotated round-robin as QNAME suffixes to spread load across resolver per-zone rate-limits.")
	flag.StringVar(&cfg.domain, "d", "", "short alias for -domain")
	flag.StringVar(&cfg.pass, "password", "", "shared encryption secret (must match server's -password)")
	flag.StringVar(&cfg.pass, "p", "", "short alias for -password")
	flag.StringVar(&cfg.dnsServer, "dns-server", "", "DNS server address; empty uses the system resolver")
	flag.StringVar(&cfg.dnsServer, "ds", "", "short alias for -dns-server")
	flag.StringVar(&cfg.dnsPort, "dns-port", defaultDNSPort, "DNS server port; defaults to 53")
	flag.StringVar(&cfg.dnsPort, "dp", defaultDNSPort, "short alias for -dns-port")
	flag.BoolVar(&cfg.tcp, "tcp", false, "use TCP instead of UDP for DNS queries")
	flag.DurationVar(&cfg.pollMin, "poll-min", 20*time.Millisecond, "minimum apoll/aread interval when active")
	flag.DurationVar(&cfg.pollMax, "poll-max", 200*time.Millisecond, "maximum apoll/aread interval after consecutive idle responses")
	flag.IntVar(&cfg.maxConn, "max-conn", 32, "maximum concurrent local tunnels (1-512)")
	flag.IntVar(&cfg.retries, "retries", 3, "DNS query attempts before failing")
	flag.DurationVar(&cfg.targetTimeout, "target-dial-timeout", 1*time.Second, "TCP dial timeout when the agent connects to the host the operator's SOCKS5 CONNECT asks for. Lower values speed up port-scan workloads through the tunnel (filtered ports release their cid sooner); raise if you legitimately tunnel to slow upstreams")
	flag.Parse()

	cfg.domain, cfg.shardDomains, cfg.shardAuthDomains, cfg.shardLongest = protocol.ParseDomainCSV(cfg.domain)
	cfg.shardRotor = new(atomic.Uint64)
	cfg.dnsPort = strings.TrimSpace(cfg.dnsPort)
	if cfg.dnsPort == "" {
		cfg.dnsPort = defaultDNSPort
	}
	if cfg.maxConn < 1 {
		cfg.maxConn = 1
	}
	if cfg.maxConn > 512 {
		cfg.maxConn = 512
	}
	if cfg.retries < 1 {
		cfg.retries = 1
	}
	if cfg.pollMin <= 0 {
		cfg.pollMin = 20 * time.Millisecond
	}
	if cfg.pollMax <= 0 {
		cfg.pollMax = 200 * time.Millisecond
	}
	if cfg.pollMax < cfg.pollMin {
		cfg.pollMax = cfg.pollMin
	}
	if cfg.targetTimeout <= 0 {
		cfg.targetTimeout = 1 * time.Second
	}
	return cfg
}

// autoResolverAddr picks a DNS server address for the agent when -ds
// wasn't provided. Tries /etc/resolv.conf first (Unix-family), then
// falls back to resolving cfg.domain via the OS default resolver and
// using that IP (works on Windows / any platform where resolv.conf
// isn't present or readable).
func autoResolverAddr(domain string) (string, error) {
	if addr, err := resolvConfNameserver(); err == nil {
		return addr, nil
	}
	// Fallback: ask the platform resolver where -domain points and
	// use the first IPv4. Works on Windows too.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return "", fmt.Errorf("no /etc/resolv.conf and cannot resolve %s: %w; specify -dns-server explicitly", domain, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	if len(ips) > 0 {
		return ips[0].String(), nil
	}
	return "", fmt.Errorf("no IPs returned for %s; specify -dns-server explicitly", domain)
}

func resolvConfNameserver() (string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return fields[1], nil
		}
	}
	return "", errors.New("no nameserver line in /etc/resolv.conf")
}

// --- Tunnel handling -------------------------------------------------------

// tunnelSession is the per-cid state shared by the two pumps: AEAD, session
// MAC key, and an atomic nonce counter used by aread/aclose for replay
// protection on the server. Each request bumps nonce.Add(1).
type tunnelSession struct {
	aead       cipher.AEAD
	sessionKey [32]byte
	compressor *gproxy.Compressor
	nonce      atomic.Uint64
}

func (ts *tunnelSession) nextNonce() uint64 {
	return ts.nonce.Add(1)
}

// handleTunnel dials the target locally and bridges bytes through the DNS
// tunnel until either side closes.
func handleTunnel(cfg config, resolver *txtResolver, cid, target string) {
	dialer := net.Dialer{Timeout: cfg.targetTimeout, KeepAlive: 30 * time.Second}
	upstream, err := dialer.Dial("tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial %s for cid=%s: %v\n", target, cid, err)
		ts := &tunnelSession{sessionKey: protocol.DeriveSessionKey(cfg.pass, cid)}
		_ = agentClose(cfg, resolver, ts, cid)
		return
	}
	defer upstream.Close()
	// Шаг G: kill Nagle on the upstream so interactive byte echoes don't get
	// coalesced. KeepAlive is already armed via the Dialer above.
	if tc, ok := upstream.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	aead, err := gproxy.SessionAEAD(cfg.pass, cid)
	if err != nil {
		ts := &tunnelSession{sessionKey: protocol.DeriveSessionKey(cfg.pass, cid)}
		_ = agentClose(cfg, resolver, ts, cid)
		return
	}
	compressor, err := gproxy.GetCompressor()
	if err != nil {
		ts := &tunnelSession{sessionKey: protocol.DeriveSessionKey(cfg.pass, cid)}
		_ = agentClose(cfg, resolver, ts, cid)
		return
	}
	ts := &tunnelSession{
		aead:       aead,
		sessionKey: protocol.DeriveSessionKey(cfg.pass, cid),
		compressor: compressor,
	}
	// Worst-case budget assumes seq+nonce fit in 32 bits (= 8 hex chars
	// each). With 96 axchg workers and one seq per chunk, at 100K q/s
	// the cap is exceeded only after ~12 hours of continuous bulk —
	// well beyond reverseTTL. Server still parses any uint64 via base
	// 16, so a wraparound only causes the agent's query to overflow
	// the 253-char limit (FORMERR + tunnel close), not corruption.
	//
	// For sharded configs we budget against the *longest* configured
	// shard — a shorter shard would just leave headroom, but a longer
	// one would silently overflow QNAME once the RR cursor lands there.
	worstBuf := maxAxchgWritePlaintextBytes(cfg.longestBudgetDomain(), cfg.tcp, 8, 8) - 1
	if worstBuf < 16 {
		fmt.Fprintf(os.Stderr, "domain %q too long: axchg plaintext budget is %d bytes, need at least 16\n", cfg.domain, worstBuf)
		_ = agentClose(cfg, resolver, ts, cid)
		return
	}

	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	runBidirectionalTunnel(cfg, tuningForCfg(cfg), resolver, ts, cid, upstream, done, stop)

	_ = upstream.Close()
	_ = agentClose(cfg, resolver, ts, cid)
}

// axchgRetries is how many times a worker retries a single axchg round-trip
// before tearing down the tunnel. 1–5% UDP loss is normal on residential
// and cellular WAN; without retries, a bulk download trips
// `connection closed` mid-stream the first time a packet drops. Each retry
// uses a fresh nonce internally — the server doesn't conflate retries with
// replays. Safe for write-bearing exchanges because the server fast-paths
// duplicate seqs (seq ≤ seqAgentIn → ACK without re-applying).
const axchgRetries = 3

// errServerSeq is the typed sentinel for the server's "ERR seq" response
// (agent's awrite seq is too far ahead of the server's drain). Workers
// match on this with errors.Is to apply backpressure without relying on
// fragile string equality.
var errServerSeq = errors.New("ERR seq")

// tunnelTuning groups every per-tunnel knob whose ideal value differs
// between UDP and TCP DNS transports. Splitting them lets each transport
// be tuned independently: bumping UDP worker count doesn't push TCP into
// pool-contention regression, and vice versa.
type tunnelTuning struct {
	// workers is the per-tunnel axchg worker goroutine count. Each
	// worker independently picks a write job from the queue (or issues
	// a pure-read pull) and runs one DNS round-trip.
	workers int
	// reorderCap bounds the per-cid reorder buffer for op→upstream
	// chunks. Sized as workers × 4 so a burst of out-of-order arrivals
	// can settle without overflow.
	reorderCap int
	// backpressureCap is the wall-clock budget a single worker spends
	// absorbing "ERR seq" retries before letting the error propagate.
	// Tuned generously — well short of reverseTTL (30 min) so a stuck
	// tunnel is torn down before the server's GC reclaims it, but long
	// enough to ride out goroutine-scheduling skew on the slowest seq.
	backpressureCap time.Duration
}

// udpTuning and tcpTuning are the two presets. UDP wins from more
// workers (per-RT CPU dominates on loopback / LAN, parallelism scales
// almost linearly). TCP saturates earlier because the DNS-over-TCP pool
// holds only `tcpPoolConns` sockets and adding workers past that just
// piles HoL contention onto the same conns.
var (
	udpTuning = tunnelTuning{
		workers:         96,
		reorderCap:      96 * 4,
		backpressureCap: 5 * time.Minute,
	}
	tcpTuning = tunnelTuning{
		workers:         32,
		reorderCap:      32 * 4,
		backpressureCap: 5 * time.Minute,
	}
)

func tuningForCfg(cfg config) tunnelTuning {
	if cfg.tcp {
		return tcpTuning
	}
	return udpTuning
}

// runBidirectionalTunnel replaces the prior pair of pumpOperatorToUpstream /
// pumpUpstreamToOperator goroutines with a single dispatcher backed by the
// axchg command. Every DNS query carries both directions: workers pick the
// next write job if there is one, otherwise issue a pure-read axchg.
//
// Throughput effect: on interactive traffic (SSH, REPL) each keystroke and
// echo pair fits inside one DNS round-trip instead of two — perceived RTT
// halves. Bulk traffic gets the full pipeline of N concurrent axchgs.
func runBidirectionalTunnel(cfg config, tuning tunnelTuning, resolver *txtResolver, ts *tunnelSession, cid string, upstream net.Conn, done <-chan struct{}, stop func()) {
	writeJobs := make(chan awriteJob, tuning.workers)
	readResults := make(chan exchangeResult, tuning.workers)
	internalStop := make(chan struct{})
	var stopOnce sync.Once
	stopAll := func() {
		stopOnce.Do(func() { close(internalStop) })
		stop()
	}
	// Guarantee `done` closes regardless of which exit path runs. Without
	// this, the EOF path (close(writeJobs); return) leaves the upstream
	// deadline-poke goroutine parked on done/internalStop forever.
	defer stop()

	var workerWG sync.WaitGroup
	for i := 0; i < tuning.workers; i++ {
		workerWG.Add(1)
		go func(workerIdx int) {
			defer workerWG.Done()
			delay := cfg.pollMin
			// Each worker holds a local shard cursor seeded with its
			// own index, so N workers × M shards spread evenly across
			// zones without any cross-worker contention. Single-domain
			// configs collapse to a constant (shardAuthDomains[0]).
			// Test fixtures may construct config{} without
			// parseFlags — fall back to cfg.pickShardAuthDomain which
			// derives from cfg.domain in that case.
			shardIdx := workerIdx
			pickShard := func() string {
				if len(cfg.shardAuthDomains) == 0 {
					return cfg.pickShardAuthDomain()
				}
				d := cfg.shardAuthDomains[shardIdx%len(cfg.shardAuthDomains)]
				shardIdx++
				return d
			}
			for {
				var job awriteJob
				haveJob := false
				select {
				case <-done:
					return
				case <-internalStop:
					return
				case j, ok := <-writeJobs:
					if !ok {
						return
					}
					job = j
					haveJob = true
				default:
				}
				if !haveJob {
					// No write pending — wait briefly for either one to
					// appear or for a backoff tick. Pure-read axchgs poll
					// the server for op→agent data.
					timer := time.NewTimer(delay)
					select {
					case <-done:
						timer.Stop()
						return
					case <-internalStop:
						timer.Stop()
						return
					case j, ok := <-writeJobs:
						timer.Stop()
						if !ok {
							return
						}
						job = j
						haveJob = true
					case <-timer.C:
					}
				}
				var (
					res               exchangeResult
					err               error
					backpressureStart time.Time
				)
				for attempt := 0; attempt < axchgRetries; attempt++ {
					shardAuth := pickShard()
					if haveJob {
						res, err = agentExchange(cfg, resolver, ts, cid, job.seq, job.data, shardAuth)
					} else {
						res, err = agentExchange(cfg, resolver, ts, cid, 0, nil, shardAuth)
					}
					if err == nil {
						break
					}
					if haveJob && errors.Is(err, errServerSeq) {
						if backpressureStart.IsZero() {
							backpressureStart = time.Now()
						}
						if time.Since(backpressureStart) > tuning.backpressureCap {
							// Server has been refusing this seq for too long;
							// fall through to the normal error path which
							// tears the tunnel down.
						} else {
							// First few hits use a short sleep so a transient
							// window-full (server's about to drain) recovers
							// in ~1 ms instead of ~15 ms. Persistent
							// backpressure escalates to the wider 5-24 ms
							// jitter that spaces 32 workers apart.
							var jitter time.Duration
							if elapsedMs := time.Since(backpressureStart).Milliseconds(); elapsedMs < 20 {
								jitter = time.Duration(1+rand.IntN(3)) * time.Millisecond
							} else {
								jitter = time.Duration(5+rand.IntN(20)) * time.Millisecond
							}
							// NewTimer+Stop instead of time.After so we don't
							// leak timer goroutines when canceled via done/
							// internalStop.
							timer := time.NewTimer(jitter)
							select {
							case <-done:
								timer.Stop()
								gproxy.PutBuf(job.bufPtr)
								return
							case <-internalStop:
								timer.Stop()
								gproxy.PutBuf(job.bufPtr)
								return
							case <-timer.C:
							}
							attempt--
							continue
						}
					}
					if attempt < axchgRetries-1 {
						time.Sleep(time.Duration(20*(attempt+1)) * time.Millisecond)
					}
				}
				if haveJob {
					gproxy.PutBuf(job.bufPtr)
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "axchg cid=%s (%d attempts): %v\n", cid, axchgRetries, err)
					stopAll()
					return
				}
				select {
				case readResults <- res:
				case <-done:
					return
				case <-internalStop:
					return
				}
				if res.readClosed {
					return
				}
				if res.readEmpty && !haveJob {
					delay *= 2
					if delay > cfg.pollMax {
						delay = cfg.pollMax
					}
				} else {
					delay = cfg.pollMin
				}
			}
		}(i)
	}

	// Upstream reader: target → writeJobs channel. Blocking Read; a second
	// goroutine watches done/internalStop and pokes the socket with a
	// time-in-the-past deadline so the blocked Read returns immediately.
	// This eliminates the previous 100 ms polling loop which used to add up
	// to ~100 ms tail latency on the first byte from upstream.
	//
	// bufSize reserves one byte of plaintext budget for the compressor's
	// flag prefix; without it an incompressible chunk would overflow the
	// axchg name-length cap.
	go func() {
		select {
		case <-done:
		case <-internalStop:
		}
		_ = upstream.SetReadDeadline(time.Unix(1, 0))
	}()
	go func() {
		var seq uint64
		// Budget only changes when hexWidth(seq+1) rolls over the next
		// power-of-16 boundary (seq = 15, 255, 4095, 65535, …). Caching
		// the last (width, bufSize) pair skips the arithmetic + string-
		// length work on the other ~99.9% of iterations.
		var cachedSeqWidth int
		var cachedBufSize int
		for {
			// Refuse to issue more queries once the per-tunnel counters
			// approach 32 bits — the budget calc assumes 8-hex-char
			// seq/nonce and an overflow would silently start emitting
			// 9+ char labels, blowing the 253-char query name and
			// causing the server to FORMERR every round-trip until the
			// tunnel dies. Tear down cleanly instead.
			if nonceGuardExceeded(seq, ts.nonce.Load(), tuning.workers) {
				fmt.Fprintf(os.Stderr, "axchg cid=%s: seq/nonce approaching 32-bit cap, closing tunnel\n", cid)
				stopAll()
				return
			}
			seqWidth := hexWidth(seq + 1)
			if seqWidth != cachedSeqWidth {
				cachedSeqWidth = seqWidth
				cachedBufSize = maxAxchgWritePlaintextBytes(cfg.longestBudgetDomain(), cfg.tcp, seqWidth, 8) - 1
				if cachedBufSize < 16 {
					cachedBufSize = 16
				}
			}
			bufPtr := gproxy.GetBuf(cachedBufSize)
			n, err := upstream.Read(*bufPtr)
			if n > 0 {
				seq++
				job := awriteJob{
					seq:    seq,
					data:   (*bufPtr)[:n],
					bufPtr: bufPtr,
				}
				select {
				case writeJobs <- job:
				case <-done:
					gproxy.PutBuf(bufPtr)
					return
				case <-internalStop:
					gproxy.PutBuf(bufPtr)
					return
				}
			} else {
				// Read returned (0, err) — buf was untouched, return it
				// straight to the pool so it doesn't escape the GC.
				gproxy.PutBuf(bufPtr)
			}
			if err != nil {
				// Cancellation paths share the same deadline-poke trick;
				// distinguish by inspecting the stop channels.
				select {
				case <-done:
					return
				case <-internalStop:
					return
				default:
				}
				// Upstream EOF (or error). Close writeJobs so workers
				// finish in-flight chunks instead of being killed mid-
				// round-trip (which drops the last ~2 KB of the stream).
				close(writeJobs)
				return
			}
		}
	}()

	go func() {
		workerWG.Wait()
		close(readResults)
	}()

	// Read reorder + writer: in-order delivery to upstream.
	nextSeq := uint64(1)
	pending := make(map[uint64][]byte, tuning.reorderCap)
	for r := range readResults {
		if r.readClosed {
			stopAll()
			drainExchange(readResults)
			_ = flushContiguous(pending, &nextSeq, upstream)
			return
		}
		if r.readEmpty || len(r.readData) == 0 {
			continue
		}
		if r.readSeq < nextSeq {
			continue
		}
		pending[r.readSeq] = r.readData
		if len(pending) > tuning.reorderCap {
			fmt.Fprintf(os.Stderr, "axchg cid=%s: reorder buffer overflow (lost seq %d?), closing\n", cid, nextSeq)
			stopAll()
			drainExchange(readResults)
			return
		}
		if err := flushContiguous(pending, &nextSeq, upstream); err != nil {
			stopAll()
			drainExchange(readResults)
			return
		}
	}
	// readResults closed → all workers exited (clean teardown path).
	// Flush any contiguous reads still buffered, then warn if a gap left
	// data stranded: the operator will see EOF mid-stream rather than
	// silently-truncated bytes followed by EOF.
	_ = flushContiguous(pending, &nextSeq, upstream)
	if len(pending) > 0 {
		fmt.Fprintf(os.Stderr, "axchg cid=%s: stream truncated at seq %d, %d chunks lost\n", cid, nextSeq, len(pending))
	}
}

// flushContiguous writes pending[*nextSeq], pending[*nextSeq+1], ... to
// upstream until the first gap, advancing *nextSeq as it goes. Returns
// the first upstream.Write error or nil. The map is mutated in place;
// any entries beyond the gap remain for the caller to inspect.
//
// The contiguous chunks are gathered into a net.Buffers and issued as a
// single writev(2) so a burst of 10-32 in-order chunks costs one syscall
// instead of one per chunk. Falls back to Write when only one chunk is
// ready (no need to allocate a net.Buffers for a single slice).
func flushContiguous(pending map[uint64][]byte, nextSeq *uint64, upstream net.Conn) error {
	// Fast path: nothing to flush.
	first, ok := pending[*nextSeq]
	if !ok {
		return nil
	}
	// Peek ahead to see how many contiguous chunks are ready. Single-chunk
	// case skips the net.Buffers allocation entirely.
	if _, hasNext := pending[*nextSeq+1]; !hasNext {
		delete(pending, *nextSeq)
		if _, err := upstream.Write(first); err != nil {
			return err
		}
		*nextSeq++
		return nil
	}
	// Multi-chunk case — gather and writev.
	batch := net.Buffers{first}
	seq := *nextSeq + 1
	for {
		data, ok := pending[seq]
		if !ok {
			break
		}
		batch = append(batch, data)
		seq++
	}
	if _, err := batch.WriteTo(upstream); err != nil {
		return err
	}
	for i := *nextSeq; i < seq; i++ {
		delete(pending, i)
	}
	*nextSeq = seq
	return nil
}

func drainExchange(ch <-chan exchangeResult) {
	for range ch {
	}
}

type awriteJob struct {
	seq    uint64
	data   []byte
	bufPtr *[]byte // pooled buffer backing `data`; PutBuf releases after use
}

// maxAxchgWritePlaintextBytes returns the largest raw byte count we can
// place in a single axchg DNS query name without exceeding 253 printable
// chars. The layout is:
//
//	cid(16) . writeSeq(seqWidth) . [dataLabels...] . ["x-tcp"(5)] . readNonce(nonceWidth) . smac(8) . "axchg"(5) . domain
//
// seqWidth / nonceWidth let the caller pass the *actual* decimal-digit
// widths of the seq and nonce to be sent. Passing the worst-case width
// (20 for uint64 in decimal) is the conservative startup check; passing
// the predicted next-iteration widths lets the reader reclaim ~10-30
// chars of overhead that the worst-case reserves but rarely uses,
// translating to +5-15 plaintext bytes per chunk.
//
// The tcp flag adds 6 chars (label + dot) when present.
//
// Returns the math-computed budget without clamping; a domain long enough to
// drive the result toward zero or negative makes axchg infeasible at this
// transport, and handleTunnel refuses to start in that case. Silently
// returning a fallback budget here would yield queries that exceed 253 chars
// and the server would FORMERR every round-trip.
func maxAxchgWritePlaintextBytes(domain string, tcp bool, seqWidth, nonceWidth int) int {
	const (
		dnsNameMax = 253
		cidLabel   = 16
		smacLabel  = 7 // 4-byte MAC encoded as 7 base32 chars (NoPadding)
		cmdLabel   = 5 // "axchg"
		// dotsMargin reserves chars for the dots between labels.
		// Actual count: 2 (cid,seq) + dataLabels + (1 if tcp) + 3
		// (nonce, smac, axchg) + 1 (domain) − 1 = 5+dataLabels (UDP)
		// or 6+dataLabels (TCP). With expanded budgets we top out at
		// ~4 data labels → 9 dots UDP, 10 TCP. Margin 12 keeps safety.
		dotsMargin = 12
	)
	overhead := cidLabel + seqWidth + nonceWidth + smacLabel + cmdLabel + len(domain) + dotsMargin
	if tcp {
		overhead += len(gproxy.AxchgTCPMarker) + 1
	}
	available := dnsNameMax - overhead
	raw := (available * 5) / 8
	raw -= 16
	return raw
}

// hexWidth returns the number of hex digits needed to represent n (with
// n=0 counted as 1 digit). Used by the reader to predict the worst-case
// width of the next seq/nonce before computing the chunk budget. Hex is
// chosen over decimal because uint64 fits in 16 hex chars vs 20 decimal
// — that 8-char savings translates to ~5 bytes more plaintext per chunk
// at worst-case widths.
// nonceGuardExceeded returns true when the per-tunnel counters are close
// enough to overflowing the 32-bit budget assumption that we should tear
// the tunnel down rather than emit queries that overflow the 253-char
// QNAME limit. At 100K q/s × 96 workers this triggers after ~12 hours of
// continuous bulk on a single cid — well beyond realistic SOCKS5 session
// lengths but possible for long-running pipes.
//
// Exposed as a package-level helper so the exhaustion path can be
// exercised in unit tests without spinning up a full tunnel.
func nonceGuardExceeded(seq, currentNonce uint64, workers int) bool {
	return seq+1 > 0xFFFFFFFF || currentNonce+uint64(workers) > 0xFFFFFFFF
}

func hexWidth(n uint64) int {
	if n == 0 {
		return 1
	}
	w := 0
	for n > 0 {
		w++
		n >>= 4
	}
	return w
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

// --- DNS RPC wrappers ------------------------------------------------------

// b32 is the lowercase-alphabet base32 used to encode axchg ciphertext
// into DNS labels. Encoder outputs are already lowercase (no strings.ToLower
// copy needed); the matching decoder is dnshelpers.B32DecodeAny which
// accepts either case in case a resolver upper-cases labels in transit.
var b32 = dnshelpers.B32LowerNoPad

// agentPoll asks the server "any pending opens?". Returns (cid, target,
// nil) on a hit, ("", "", nil) on EMPTY, or an error.
func agentPoll(cfg config, resolver *txtResolver) (cid, target string, err error) {
	name := authenticatedName(cfg.pass, cfg.domain, cfg.pickShardAuthDomain(), "apoll", nil)
	resp, err := resolver.query(name)
	if err != nil {
		return "", "", err
	}
	if resp == "EMPTY" {
		return "", "", nil
	}
	if strings.HasPrefix(resp, "ERR ") {
		return "", "", errors.New(resp)
	}
	if !strings.HasPrefix(resp, "OPEN ") {
		return "", "", fmt.Errorf("unexpected apoll response: %q", resp)
	}
	parts := strings.SplitN(resp[len("OPEN "):], " ", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("malformed OPEN response: %q", resp)
	}
	cid = parts[0]
	if !gproxy.ValidCID(cid) {
		return "", "", fmt.Errorf("bad cid in OPEN: %q", cid)
	}
	// Target is base32-encoded by the server; older servers send uppercase,
	// newer ones lowercase. dnshelpers.B32DecodeAny handles both without
	// paying a strings.ToUpper allocation on the common (lowercase) path.
	rawTarget, err := dnshelpers.B32DecodeAny(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decode target: %w", err)
	}
	return cid, string(rawTarget), nil
}

// exchangeResult captures what one axchg DNS round-trip yielded: the write
// side returned ACK <writeSeq>, and the read side returned either a chunk,
// EMPTY, or CLOSED. Pure-read axchgs leave writeSeq=0.
type exchangeResult struct {
	ackedWriteSeq uint64
	readData      []byte
	readSeq       uint64
	readClosed    bool
	readEmpty     bool
}

// agentExchange runs a single axchg DNS round-trip combining one awrite
// chunk (or none) with a fresh aread pull. Returns the parsed exchangeResult
// or an error; the caller decides what to retry.
//
// Wire: cid . writeSeq . [writeChunks...] . [x-tcp] . readNonce . smac . axchg . <shard>
// shardAuthDomain picks which configured shard suffix ends the QNAME.
// HMAC/session MAC don't touch shardAuthDomain — they use ts.sessionKey
// derived from canonical (cfg.domain), so any shard is auth-equivalent.
func agentExchange(cfg config, resolver *txtResolver, ts *tunnelSession, cid string, writeSeq uint64, writeData []byte, shardAuthDomain string) (exchangeResult, error) {
	readNonce := ts.nextNonce()
	args := make([]string, 0, 8)
	args = append(args, cid, strconv.FormatUint(writeSeq, 16))
	if writeSeq > 0 {
		compressed := ts.compressor.Encode(writeData)
		// Seal into a pooled dst buffer so aead.Seal doesn't allocate a
		// fresh ciphertext slice per chunk. `enc` is a fresh string that
		// copies bytes out of the pooled scratch, so we can release
		// immediately after EncodeToString returns. Use a closure so a
		// hypothetical panic in Seal/Encode still returns the buffer.
		ctBufPtr := gproxy.GetBuf(len(compressed) + 16)
		var enc string
		func() {
			defer gproxy.PutBuf(ctBufPtr)
			ct := gproxy.SealChunkTo((*ctBufPtr)[:0], ts.aead, gproxy.DirClientToServer, writeSeq, compressed)
			enc = b32.EncodeToString(ct) // already lowercase — see b32 var doc
		}()
		args = append(args, codec.ChunkString(enc, 63)...)
	}
	if cfg.tcp {
		args = append(args, gproxy.AxchgTCPMarker)
	}
	args = append(args, strconv.FormatUint(readNonce, 16))
	args = append(args, protocol.SessionMAC(ts.sessionKey, "axchg", readNonce))
	// shardAuthDomain is pre-normalized by parseDomainCSV and "axchg"
	// is already lowercase — skip protocol.AuthDomain + strings.ToLower
	// per query. The shard varies per call (RR from workers/rotor);
	// HMAC/session MAC live in args and are unaffected by suffix choice.
	name := protocol.JoinNameFast(shardAuthDomain, "axchg", args)

	segs, err := resolver.queryStringsNoRetry(name)
	if err != nil {
		return exchangeResult{}, err
	}
	if len(segs) == 0 {
		return exchangeResult{}, errors.New("empty axchg response")
	}

	// First segment is "ACK <writeSeq>" or "ERR ..." / "CLOSED".
	head := segs[0]
	switch {
	case head == "CLOSED":
		return exchangeResult{readClosed: true}, nil
	case head == "ERR seq":
		return exchangeResult{}, errServerSeq
	case strings.HasPrefix(head, "ERR "):
		return exchangeResult{}, errors.New(head)
	case strings.HasPrefix(head, "ACK "):
		acked, perr := strconv.ParseUint(strings.TrimPrefix(head, "ACK "), 16, 64)
		if perr != nil {
			return exchangeResult{}, fmt.Errorf("malformed ACK: %w", perr)
		}
		if acked != writeSeq {
			return exchangeResult{}, fmt.Errorf("axchg ACK mismatch: got %x want %x", acked, writeSeq)
		}

		res := exchangeResult{ackedWriteSeq: acked}
		if len(segs) < 2 {
			res.readEmpty = true
			return res, nil
		}
		readHead := segs[1]
		switch {
		case readHead == "EMPTY":
			res.readEmpty = true
			return res, nil
		case readHead == "CLOSED":
			res.readClosed = true
			return res, nil
		case strings.HasPrefix(readHead, "DATA "):
			parsedSeq, perr := strconv.ParseUint(strings.TrimPrefix(readHead, "DATA "), 16, 64)
			if perr != nil {
				return exchangeResult{}, fmt.Errorf("malformed DATA seq: %w", perr)
			}
			b64 := strings.Join(segs[2:], "")
			ct, derr := base64.StdEncoding.DecodeString(b64)
			if derr != nil {
				return exchangeResult{}, fmt.Errorf("decode axchg payload: %w", derr)
			}
			// Open into a pooled dst buffer; compressor.Decode below returns
			// a fresh slice so `decompressed` doesn't reference the pool
			// buffer after Decode returns. defer ensures the buffer is
			// released on every return path (error, panic, or success)
			// with no chance of a double-put.
			ptBufPtr := gproxy.GetBuf(len(ct))
			defer gproxy.PutBuf(ptBufPtr)
			pt, oerr := gproxy.OpenChunkTo((*ptBufPtr)[:0], ts.aead, gproxy.DirServerToClient, parsedSeq, ct)
			if oerr != nil {
				return exchangeResult{}, fmt.Errorf("decrypt axchg payload: %w", oerr)
			}
			decompressed, derr := ts.compressor.Decode(pt)
			if derr != nil {
				return exchangeResult{}, fmt.Errorf("decompress axchg payload: %w", derr)
			}
			res.readData = decompressed
			res.readSeq = parsedSeq
			return res, nil
		default:
			return exchangeResult{}, fmt.Errorf("unexpected axchg read head: %q", readHead)
		}
	default:
		return exchangeResult{}, fmt.Errorf("unexpected axchg head: %q", head)
	}
}

// agentClose tells the server we're done with cid. The MAC binds the nonce
// so a replay can't free new state; the server treats unknown-cid as a
// successful no-op so retries on DNS timeout are safe.
//
// Wire: cid . nonce . smac . aclose . <shard>
// Shard suffix is picked round-robin from cfg.shardRotor (aclose isn't
// worker-local so there's no per-worker cursor). Session MAC lives in
// args and is unaffected by suffix choice.
func agentClose(cfg config, resolver *txtResolver, ts *tunnelSession, cid string) error {
	nonce := ts.nextNonce()
	args := []string{
		cid,
		strconv.FormatUint(nonce, 16),
		protocol.SessionMAC(ts.sessionKey, "aclose", nonce),
	}
	name := protocol.JoinNameFast(cfg.pickShardAuthDomain(), "aclose", args)
	_, err := resolver.query(name)
	return err
}

// --- Authenticated name builder (used only by apoll, which has no cid yet) -

// authenticatedName builds an apoll-style QNAME. canonicalDomain drives
// the HMAC (the server verifies against its canonical -domain too), and
// shardAuthDomain picks which shard suffix ends the QNAME. For single-
// domain configs the two are equivalent. `command` must already be
// lowercase — JoinNameFast's contract.
func authenticatedName(secret, canonicalDomain, shardAuthDomain, command string, args []string) string {
	ts := protocol.CurrentTimestamp(time.Now())
	token := protocol.AuthToken(secret, canonicalDomain, command, ts, args)
	labels := make([]string, 0, len(args)+3)
	labels = append(labels, args...)
	labels = append(labels, ts, token)
	return protocol.JoinNameFast(shardAuthDomain, command, labels)
}
