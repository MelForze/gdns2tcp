// Command gdns2tcp-client-proxy is the agent that runs inside a target
// network. It long-polls the gdns2tcp server's apoll endpoint for new tunnel
// requests, dials the requested host:port locally, and bridges bytes back to
// the operator through aread/awrite. The operator never talks DNS — they hit
// the server's SOCKS5/TCP listener on port 9050 directly.
package main

import (
	"context"
	"crypto/cipher"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gdns2tcp/internal/codec"
	"gdns2tcp/internal/protocol"
	gproxy "gdns2tcp/internal/proxy"
)

const defaultDNSPort = "53"

type config struct {
	domain    string
	pass      string
	dnsServer string
	dnsPort   string
	tcp       bool
	pollMin   time.Duration
	pollMax   time.Duration
	maxConn   int
	retries   int
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
		return errors.New("pass is required")
	}
	if cfg.dnsServer == "" {
		ip, err := resolveDomainServer(cfg.domain)
		if err != nil {
			return err
		}
		cfg.dnsServer = ip
		fmt.Printf("using DNS server %s:%s resolved from %s\n", cfg.dnsServer, cfg.dnsPort, cfg.domain)
	}
	resolver := newTxtResolver(cfg)
	fmt.Printf("polling %s for tunnel requests (max %d concurrent)\n", cfg.domain, cfg.maxConn)

	var live int64
	delay := cfg.pollMin
	for {
		if int(atomic.LoadInt64(&live)) >= cfg.maxConn {
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
		atomic.AddInt64(&live, 1)
		go func(cid, target string) {
			defer atomic.AddInt64(&live, -1)
			handleTunnel(cfg, resolver, cid, target)
		}(cid, target)
	}
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.domain, "domain", "", "authoritative gdns2tcp domain")
	flag.StringVar(&cfg.pass, "pass", "", "shared encryption secret (must match server's -secret)")
	flag.StringVar(&cfg.dnsServer, "dns-server", "", "DNS server address; empty resolves -domain and uses the first IP")
	flag.StringVar(&cfg.dnsPort, "dns-port", defaultDNSPort, "DNS server port; defaults to 53")
	flag.BoolVar(&cfg.tcp, "tcp", false, "use TCP instead of UDP for DNS queries")
	flag.DurationVar(&cfg.pollMin, "poll-min", 20*time.Millisecond, "minimum apoll/aread interval when active")
	flag.DurationVar(&cfg.pollMax, "poll-max", 200*time.Millisecond, "maximum apoll/aread interval after consecutive idle responses")
	flag.IntVar(&cfg.maxConn, "max-conn", 32, "maximum concurrent local tunnels (1-512)")
	flag.IntVar(&cfg.retries, "retries", 3, "DNS query attempts before failing")
	flag.Parse()

	cfg.domain = strings.TrimSuffix(strings.TrimSpace(cfg.domain), ".")
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
	return cfg
}

func resolveDomainServer(domain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return "", fmt.Errorf("resolve DNS server from domain %s: %w", domain, err)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("domain %s did not resolve", domain)
	}
	return ips[0].String(), nil
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

	// Adaptive sizing (Шаг A). bufSize is the size each upstream.Read aims
	// for; recalculated from EWMA RTT after every axchg round-trip. Stored
	// in microseconds for cheaper atomic Int64.
	tcpMode bool
	bufSize atomic.Int64
	rttEWMA atomic.Int64
}

// updateRTT folds the observed axchg round-trip time into the EWMA and
// rescales bufSize accordingly. Only TCP mode benefits — UDP awrite is hard-
// capped by the 253-char DNS name limit and adaptive sizing would just thrash.
func (ts *tunnelSession) updateRTT(d time.Duration) {
	newSample := d.Microseconds()
	if newSample <= 0 {
		return
	}
	old := ts.rttEWMA.Load()
	// α = 0.2: avg = 0.2 * new + 0.8 * old
	var avg int64
	if old == 0 {
		avg = newSample
	} else {
		avg = (newSample + 4*old) / 5
	}
	ts.rttEWMA.Store(avg)

	if !ts.tcpMode {
		return
	}
	// Scale bufSize from 4 KB (high RTT) up to 16 KB (LAN). The agent's
	// TCP-DNS pool has 60 KB headroom inside one query, so we can grow
	// considerably past the 4 KB starting cap without truncating.
	var newBuf int64
	switch {
	case avg < 5_000: // < 5 ms — LAN
		newBuf = 16000
	case avg < 20_000: // < 20 ms — datacenter-to-datacenter
		newBuf = 8000
	default:
		newBuf = 4000
	}
	ts.bufSize.Store(newBuf)
}

func (ts *tunnelSession) nextNonce() uint64 {
	return ts.nonce.Add(1)
}

// handleTunnel dials the target locally and bridges bytes through the DNS
// tunnel until either side closes.
func handleTunnel(cfg config, resolver *txtResolver, cid, target string) {
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
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
		tcpMode:    cfg.tcp,
	}
	// Initial bufSize matches the prior hardcoded behaviour; Шаг A's
	// updateRTT() rescales it on the fly based on observed axchg RTT.
	initialBuf := maxAwritePlaintextBytes(cfg.domain, cfg.tcp) - 1
	if initialBuf < 1 {
		initialBuf = 1
	}
	ts.bufSize.Store(int64(initialBuf))

	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }

	runBidirectionalTunnel(cfg, resolver, ts, cid, upstream, done, stop)

	_ = upstream.Close()
	_ = agentClose(cfg, resolver, ts, cid)
}

// axchgWorkers controls per-tunnel DNS query parallelism. Each worker can be
// either pumping an awrite chunk through or pulling a fresh aread chunk; the
// axchg command lets a single round-trip carry both.
const axchgWorkers = 16

// readReorderCap bounds the per-cid reorder buffer for op→upstream chunks.
// Same idea as pendingCap in the old pumpOperatorToUpstream: protect against
// a permanently-missing seq leaking memory. Matched to axchgWorkers × 4 so a
// burst of out-of-order arrivals can settle.
const readReorderCap = axchgWorkers * 4

// runBidirectionalTunnel replaces the prior pair of pumpOperatorToUpstream /
// pumpUpstreamToOperator goroutines with a single dispatcher backed by the
// axchg command. Every DNS query carries both directions: workers pick the
// next write job if there is one, otherwise issue a pure-read axchg.
//
// Throughput effect: on interactive traffic (SSH, REPL) each keystroke and
// echo pair fits inside one DNS round-trip instead of two — perceived RTT
// halves. Bulk traffic gets the full pipeline of N concurrent axchgs.
func runBidirectionalTunnel(cfg config, resolver *txtResolver, ts *tunnelSession, cid string, upstream net.Conn, done <-chan struct{}, stop func()) {
	writeJobs := make(chan awriteJob, axchgWorkers)
	readResults := make(chan exchangeResult, axchgWorkers)
	internalStop := make(chan struct{})
	var stopOnce sync.Once
	stopAll := func() {
		stopOnce.Do(func() { close(internalStop) })
		stop()
	}

	var workerWG sync.WaitGroup
	for range axchgWorkers {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			delay := cfg.pollMin
			for {
				var job awriteJob
				haveJob := false
				select {
				case <-done:
					return
				case <-internalStop:
					return
				case job = <-writeJobs:
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
					case job = <-writeJobs:
						timer.Stop()
						haveJob = true
					case <-timer.C:
					}
				}
				var (
					res exchangeResult
					err error
				)
				exchangeStart := time.Now()
				if haveJob {
					res, err = agentExchange(cfg, resolver, ts, cid, job.seq, job.data)
					if job.release != nil {
						job.release()
					}
				} else {
					res, err = agentExchange(cfg, resolver, ts, cid, 0, nil)
				}
				if err != nil {
					fmt.Fprintf(os.Stderr, "axchg cid=%s: %v\n", cid, err)
					stopAll()
					return
				}
				// Шаг A: feed the EWMA only on data-bearing round-trips.
				// Pure-read EMPTY responses inflate the average by the
				// server's idle-poll behaviour, not the network RTT.
				if haveJob || len(res.readData) > 0 {
					ts.updateRTT(time.Since(exchangeStart))
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
		}()
	}

	// Upstream reader: target → writeJobs channel. Blocking Read; a second
	// goroutine watches done/internalStop and pokes the socket with a
	// time-in-the-past deadline so the blocked Read returns immediately.
	// This eliminates the previous 100 ms polling loop which used to add up
	// to ~100 ms tail latency on the first byte from upstream.
	//
	// bufSize reserves one byte of plaintext budget for the compressor's
	// flag prefix; without it an incompressible chunk would overflow the
	// awrite name-length cap.
	go func() {
		select {
		case <-done:
		case <-internalStop:
		}
		_ = upstream.SetReadDeadline(time.Unix(1, 0))
	}()
	// Шаг B: register this tunnel with the batcher so other concurrently
	// active tunnels can co-batch their writes through axchgm. We don't
	// spill our own jobs into the batcher — per-cid in-flight would blow
	// past the server's awriteWindow and the batcher's cross-cid wire
	// budget. The integration point is the cross-tunnel scheduler in
	// runMultiCidScheduler (see registerTunnel below).
	batcher := getMultiCidBatcher(cfg, resolver)
	batcher.registerTunnel(cid, ts, writeJobs, done)
	defer batcher.unregisterTunnel(cid)

	go func() {
		bufSize := int(ts.bufSize.Load())
		if bufSize < 1 {
			bufSize = 1
		}
		var seq uint64
		for {
			buf := gproxy.GetBuf(bufSize)
			n, err := upstream.Read(buf)
			if n > 0 {
				seq++
				// Capture the original full slice so PutBuf can route it
				// back to its size class — the truncated buf[:n] would lose
				// the cap information.
				full := buf
				job := awriteJob{
					seq:     seq,
					data:    buf[:n],
					release: func() { gproxy.PutBuf(full) },
				}
				// Шаг B: when there's no peer tunnel, stick to the
				// per-tunnel queue — single-cid spill would just race the
				// axchgWorkers and fight for the seqAgentIn window. With
				// 2+ tunnels we offer the job to the batcher's bus as a
				// non-blocking secondary path; whichever channel takes it
				// first wins.
				batcher.mu.Lock()
				canBatch := len(batcher.tunnels) >= 2
				batcher.mu.Unlock()
				if canBatch {
					select {
					case writeJobs <- job:
					case batcher.bus <- batchedJob{
						cid: cid, ts: ts, seq: seq,
						data: job.data, release: job.release,
					}:
					case <-done:
						job.release()
						return
					case <-internalStop:
						job.release()
						return
					}
				} else {
					select {
					case writeJobs <- job:
					case <-done:
						job.release()
						return
					case <-internalStop:
						job.release()
						return
					}
				}
			} else {
				// Read returned (0, err) — buf was untouched, return it
				// straight to the pool so it doesn't escape the GC.
				gproxy.PutBuf(buf)
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
				stopAll()
				return
			}
			// Refresh bufSize each loop so Шаг A's RTT-driven scaling can
			// shrink/grow the reader without restarting the goroutine.
			bufSize = int(ts.bufSize.Load())
			if bufSize < 1 {
				bufSize = 1
			}
		}
	}()

	go func() {
		workerWG.Wait()
		close(readResults)
	}()

	// Read reorder + writer: in-order delivery to upstream.
	nextSeq := uint64(1)
	pending := make(map[uint64][]byte, readReorderCap)
	for r := range readResults {
		if r.readClosed {
			stopAll()
			drainExchange(readResults)
			for {
				data, ok := pending[nextSeq]
				if !ok {
					break
				}
				delete(pending, nextSeq)
				if _, err := upstream.Write(data); err != nil {
					return
				}
				nextSeq++
			}
			return
		}
		if r.readEmpty || len(r.readData) == 0 {
			continue
		}
		if r.readSeq < nextSeq {
			continue
		}
		pending[r.readSeq] = r.readData
		if len(pending) > readReorderCap {
			fmt.Fprintf(os.Stderr, "axchg cid=%s: reorder buffer overflow (lost seq %d?), closing\n", cid, nextSeq)
			stopAll()
			drainExchange(readResults)
			return
		}
		for {
			data, ok := pending[nextSeq]
			if !ok {
				break
			}
			delete(pending, nextSeq)
			if _, err := upstream.Write(data); err != nil {
				stopAll()
				drainExchange(readResults)
				return
			}
			nextSeq++
		}
	}
}

func drainExchange(ch <-chan exchangeResult) {
	for range ch {
	}
}

// pumpOperatorToUpstream is retained only for tests that exercise the
// agent-side aread path directly; the live tunnel now runs through
// runBidirectionalTunnel + axchg.
const areadPipeline = 8

// pendingCap bounds the reorder buffer in pumpOperatorToUpstream.
const pendingCap = areadPipeline * 4

type areadResult struct {
	data   []byte
	seq    uint64
	closed bool
	wait   bool
	err    error
}

func pumpOperatorToUpstream(cfg config, resolver *txtResolver, ts *tunnelSession, cid string, upstream net.Conn, done <-chan struct{}) {
	results := make(chan areadResult, areadPipeline)
	stop := make(chan struct{})
	var stopOnce sync.Once
	cancel := func() { stopOnce.Do(func() { close(stop) }) }
	defer cancel()

	var wg sync.WaitGroup
	for range areadPipeline {
		wg.Add(1)
		go func() {
			defer wg.Done()
			delay := cfg.pollMin
			for {
				select {
				case <-done:
					return
				case <-stop:
					return
				default:
				}
				data, seq, closed, wait, err := agentRead(cfg, resolver, ts, cid)
				select {
				case results <- areadResult{data: data, seq: seq, closed: closed, wait: wait, err: err}:
				case <-done:
					return
				case <-stop:
					return
				}
				if err != nil || closed {
					return
				}
				if len(data) == 0 {
					if wait {
						time.Sleep(cfg.pollMin)
						delay = cfg.pollMin
					} else {
						time.Sleep(delay)
						delay *= 2
						if delay > cfg.pollMax {
							delay = cfg.pollMax
						}
					}
				} else {
					delay = cfg.pollMin
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	nextSeq := uint64(1)
	pending := make(map[uint64][]byte, pendingCap)
	for r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "aread cid=%s: %v\n", cid, r.err)
			cancel()
			drain(results)
			return
		}
		if r.closed {
			cancel()
			drain(results)
			// Flush whatever contiguous prefix is buffered before exiting.
			for {
				data, ok := pending[nextSeq]
				if !ok {
					break
				}
				delete(pending, nextSeq)
				if _, err := upstream.Write(data); err != nil {
					return
				}
				nextSeq++
			}
			return
		}
		if len(r.data) == 0 {
			continue
		}
		if r.seq < nextSeq {
			// Duplicate (shouldn't happen since the server increments seq
			// under a single lock, but cheap to defend against).
			continue
		}
		pending[r.seq] = r.data
		if len(pending) > pendingCap {
			fmt.Fprintf(os.Stderr, "aread cid=%s: reorder buffer overflow (lost seq %d?), closing\n", cid, nextSeq)
			cancel()
			drain(results)
			return
		}
		for {
			data, ok := pending[nextSeq]
			if !ok {
				break
			}
			delete(pending, nextSeq)
			if _, err := upstream.Write(data); err != nil {
				cancel()
				drain(results)
				return
			}
			nextSeq++
		}
	}
}

// drain empties a results channel so blocked senders can finish and the wg
// closer goroutine can complete its work after cancel.
func drain(ch <-chan areadResult) {
	for range ch {
	}
}

// --- Шаг B: multi-cid axchgm batcher --------------------------------------
//
// One process-wide singleton owns a bus that per-tunnel upstream-readers
// fall back to whenever their own writeJobs channel is full. The batcher
// coalesces up to axchgmMaxBatch jobs from any cids waiting on the bus into
// a single axchgm DNS round-trip.
//
// Per-tunnel pure-read axchg keeps the read-piggyback latency win for
// interactive traffic; the batcher only fires when there's genuine
// write-side overflow, typically a many-tab browser session.

const (
	// axchgmMaxBatch matches the server cap in internal/dnsserver/proxy.go.
	axchgmMaxBatch = 8
	// batchCollectWindow is how long a worker waits to top up a batch
	// before sending. Trades a tiny tail-latency cost (≤ window) against
	// the DNS-RTT savings from coalescing.
	batchCollectWindow = 2 * time.Millisecond
)

type batchedJob struct {
	cid     string
	ts      *tunnelSession
	seq     uint64
	data    []byte
	release func() // matches awriteJob.release: returns buf to its pool
}

type multiCidBatcher struct {
	cfg      config
	resolver *txtResolver
	bus      chan batchedJob
	stop     chan struct{}

	mu      sync.Mutex
	tunnels map[string]*batcherTunnel // cid → registered tunnel
}

// batcherTunnel records what the scheduler needs to know about a live
// tunnel so it can opportunistically batch its writes with peers'.
type batcherTunnel struct {
	ts        *tunnelSession
	writeJobs chan awriteJob
	done      <-chan struct{}
}

// registerTunnel makes a tunnel visible to the cross-tunnel scheduler. The
// scheduler itself does not poke into writeJobs (that would race with the
// per-tunnel workers); registration just builds the set the scheduler
// consults when other tunnels publish via b.bus.
func (b *multiCidBatcher) registerTunnel(cid string, ts *tunnelSession, writeJobs chan awriteJob, done <-chan struct{}) {
	b.mu.Lock()
	if b.tunnels == nil {
		b.tunnels = make(map[string]*batcherTunnel)
	}
	b.tunnels[cid] = &batcherTunnel{ts: ts, writeJobs: writeJobs, done: done}
	b.mu.Unlock()
}

func (b *multiCidBatcher) unregisterTunnel(cid string) {
	b.mu.Lock()
	delete(b.tunnels, cid)
	b.mu.Unlock()
}

// getMultiCidBatcher returns the per-resolver batcher, initializing it on
// the first call for that resolver. Per-resolver (rather than per-process)
// scoping lets unit tests spin up fresh agents against fresh DNS servers
// without inheriting workers bound to a previous run's now-closed pool.
func getMultiCidBatcher(cfg config, resolver *txtResolver) *multiCidBatcher {
	resolver.batcherOnce.Do(func() {
		resolver.batcher = &multiCidBatcher{
			cfg:      cfg,
			resolver: resolver,
			bus:      make(chan batchedJob, 64),
			stop:     make(chan struct{}),
		}
		for range axchgmMaxBatch {
			go resolver.batcher.runWorker()
		}
	})
	return resolver.batcher
}

// Stop terminates the batcher's workers. Safe to call once; subsequent
// calls panic on close-of-closed-channel. Mainly for test cleanup so
// goroutines don't leak across test runs and bang on closed DNS pools.
func (b *multiCidBatcher) Stop() {
	close(b.stop)
}

func (b *multiCidBatcher) runWorker() {
	// Once the underlying DNS pool starts refusing connections (test cleanup
	// or production server gone), exit instead of flooding stderr. A handful
	// of failures is the normal cost of a transient blip; >consecutiveBatchFailExit
	// means the resolver is dead.
	const consecutiveBatchFailExit = 4
	failures := 0
	for {
		var first batchedJob
		select {
		case <-b.stop:
			return
		case first = <-b.bus:
		}
		batch := []batchedJob{first}
		timer := time.NewTimer(batchCollectWindow)
	collect:
		for len(batch) < axchgmMaxBatch {
			select {
			case j := <-b.bus:
				batch = append(batch, j)
			case <-timer.C:
				break collect
			}
		}
		timer.Stop()
		if len(batch) == 1 {
			// Single job — fall back to plain axchg to keep the read
			// piggyback. Discard the read result; per-tunnel pure-reads
			// will pick it up on the next poll.
			_, err := agentExchange(b.cfg, b.resolver, first.ts, first.cid, first.seq, first.data)
			if first.release != nil {
				first.release()
			}
			if err != nil {
				failures++
				if failures <= consecutiveBatchFailExit {
					fmt.Fprintf(os.Stderr, "axchgm-fallback cid=%s: %v\n", first.cid, err)
				}
				if failures >= consecutiveBatchFailExit {
					return
				}
			} else {
				failures = 0
			}
			continue
		}
		if err := b.runBatch(batch); err != nil {
			failures++
			if failures >= consecutiveBatchFailExit {
				for _, j := range batch {
					if j.release != nil {
						j.release()
					}
				}
				return
			}
		} else {
			failures = 0
		}
		for _, j := range batch {
			if j.release != nil {
				j.release()
			}
		}
	}
}

func (b *multiCidBatcher) runBatch(batch []batchedJob) error {
	args := make([]string, 0, 2+len(batch)*5)
	args = append(args, strconv.Itoa(len(batch)))
	for _, j := range batch {
		compressed := j.ts.compressor.Encode(j.data)
		ct := gproxy.SealChunk(j.ts.aead, gproxy.DirClientToServer, j.seq, compressed)
		enc := strings.ToLower(b32.EncodeToString(ct))
		chunks := codec.ChunkString(enc, 63)
		args = append(args,
			j.cid,
			strconv.FormatUint(j.seq, 10),
			strconv.Itoa(len(chunks)),
		)
		args = append(args, chunks...)
		args = append(args, protocol.SessionMAC(j.ts.sessionKey, "axchgm", j.seq))
	}
	name := protocol.JoinName(b.cfg.domain, "axchgm", args)
	segs, err := b.resolver.queryStringsNoRetry(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "axchgm batch (n=%d): %v\n", len(batch), err)
		return err
	}
	for i, seg := range segs {
		if i >= len(batch) {
			break
		}
		if !strings.HasPrefix(seg, "ACK ") {
			fmt.Fprintf(os.Stderr, "axchgm cid=%s seq=%d: %s\n", batch[i].cid, batch[i].seq, seg)
		}
	}
	return nil
}

const awritePipeline = 16

type awriteJob struct {
	seq     uint64
	data    []byte
	release func() // returns the underlying buffer to the pool; may be nil
}

// pumpUpstreamToOperator reads from upstream and pushes through awrite with
// up to awritePipeline parallel in-flight DNS queries.
func pumpUpstreamToOperator(cfg config, resolver *txtResolver, ts *tunnelSession, cid string, upstream net.Conn, done <-chan struct{}) {
	bufSize := maxAwritePlaintextBytes(cfg.domain, cfg.tcp)
	jobs := make(chan awriteJob, awritePipeline)
	errc := make(chan error, awritePipeline)

	var wgWriters sync.WaitGroup
	for range awritePipeline {
		wgWriters.Add(1)
		go func() {
			defer wgWriters.Done()
			for j := range jobs {
				if err := agentWrite(cfg, resolver, ts, cid, j.seq, j.data); err != nil {
					errc <- err
					return
				}
			}
		}()
	}

	var seq uint64
	for {
		select {
		case <-done:
			close(jobs)
			wgWriters.Wait()
			return
		case err := <-errc:
			close(jobs)
			wgWriters.Wait()
			fmt.Fprintf(os.Stderr, "awrite cid=%s: %v\n", cid, err)
			return
		default:
		}
		_ = upstream.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, bufSize)
		n, err := upstream.Read(buf)
		if n > 0 {
			seq++
			select {
			case jobs <- awriteJob{seq: seq, data: buf[:n]}:
			case err := <-errc:
				close(jobs)
				wgWriters.Wait()
				fmt.Fprintf(os.Stderr, "awrite cid=%s: %v\n", cid, err)
				return
			case <-done:
				close(jobs)
				wgWriters.Wait()
				return
			}
		}
		if err != nil {
			if isTimeout(err) {
				continue
			}
			close(jobs)
			wgWriters.Wait()
			return
		}
	}
}

// maxAwritePlaintextBytes returns the largest raw byte count we can place in
// a single awrite DNS name without exceeding 253 chars. The math accounts for
// the cid (16) + seq (≤20 digits) + smac (8) + "awrite" (6) + domain + dots
// between labels, leaving the rest for base32-encoded ciphertext (= raw × 8/5)
// and subtracts the 16-byte AES-GCM tag from the plaintext budget.
//
// Post session-MAC cutover: the old (ts=8, token=26) labels are gone, freeing
// 26 query chars ≈ +16 bytes plaintext. UDP awrite went from ~76 to ~92.
func maxAwritePlaintextBytes(domain string, tcp bool) int {
	if tcp {
		return 4000
	}
	const (
		dnsNameMax  = 253
		cidLabel    = 16
		seqLabelMax = 20
		smacLabel   = 8
		cmdLabel    = 6
		dotsMargin  = 12
	)
	overhead := cidLabel + seqLabelMax + smacLabel + cmdLabel + len(domain) + dotsMargin
	available := dnsNameMax - overhead
	if available < 32 {
		return 32
	}
	raw := (available * 5) / 8
	raw -= 16
	if raw < 16 {
		raw = 16
	}
	return raw
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

// --- DNS RPC wrappers ------------------------------------------------------

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// agentPoll asks the server "any pending opens?". Returns (cid, target,
// nil) on a hit, ("", "", nil) on EMPTY, or an error.
func agentPoll(cfg config, resolver *txtResolver) (cid, target string, err error) {
	name := authenticatedName(cfg.pass, cfg.domain, "apoll", nil)
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
	rawTarget, err := b32.DecodeString(strings.ToUpper(parts[1]))
	if err != nil {
		return "", "", fmt.Errorf("decode target: %w", err)
	}
	return cid, string(rawTarget), nil
}

// agentRead asks the server for the next op→agent chunk for cid. The returned
// seq is server-assigned and monotonic per-cid; pumpOperatorToUpstream uses
// it to reorder concurrent in-flight reads before writing to upstream.
//
// Wire: cid . nonce . ["tcp"] . smac . aread . domain
func agentRead(cfg config, resolver *txtResolver, ts *tunnelSession, cid string) (data []byte, seq uint64, closed bool, wait bool, err error) {
	nonce := ts.nextNonce()
	args := []string{cid, strconv.FormatUint(nonce, 10)}
	if cfg.tcp {
		args = append(args, "tcp")
	}
	args = append(args, protocol.SessionMAC(ts.sessionKey, "aread", nonce))
	name := protocol.JoinName(cfg.domain, "aread", args)
	segs, err := resolver.queryStrings(name)
	if err != nil {
		return nil, 0, false, false, err
	}
	if len(segs) == 0 {
		return nil, 0, false, false, errors.New("empty aread response")
	}
	head := segs[0]
	switch {
	case head == "EMPTY":
		return nil, 0, false, false, nil
	case head == "WAIT":
		return nil, 0, false, true, nil
	case head == "CLOSED":
		return nil, 0, true, false, nil
	case strings.HasPrefix(head, "ERR "):
		return nil, 0, false, false, errors.New(head)
	case strings.HasPrefix(head, "DATA "):
		parsedSeq, perr := strconv.ParseUint(strings.TrimPrefix(head, "DATA "), 10, 64)
		if perr != nil {
			return nil, 0, false, false, fmt.Errorf("malformed DATA seq: %w", perr)
		}
		b64 := strings.Join(segs[1:], "")
		ct, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, 0, false, false, fmt.Errorf("decode aread payload: %w", err)
		}
		pt, err := gproxy.OpenChunk(ts.aead, gproxy.DirServerToClient, parsedSeq, ct)
		if err != nil {
			return nil, 0, false, false, fmt.Errorf("decrypt aread payload: %w", err)
		}
		decompressed, err := ts.compressor.Decode(pt)
		if err != nil {
			return nil, 0, false, false, fmt.Errorf("decompress aread payload: %w", err)
		}
		return decompressed, parsedSeq, false, false, nil
	default:
		return nil, 0, false, false, fmt.Errorf("unexpected aread head: %q", head)
	}
}

// agentWrite ships a single seq's worth of upstream→operator bytes. The MAC
// is bound to (cmd, seq), so replay protection is inherent in the server's
// seqAgentIn tracking and no extra nonce label is needed.
//
// Wire: cid . seq . chunk1 . chunk2 ... . smac . awrite . domain
func agentWrite(cfg config, resolver *txtResolver, ts *tunnelSession, cid string, seq uint64, plaintext []byte) error {
	compressed := ts.compressor.Encode(plaintext)
	ct := gproxy.SealChunk(ts.aead, gproxy.DirClientToServer, seq, compressed)
	enc := strings.ToLower(b32.EncodeToString(ct))
	dataLabels := codec.ChunkString(enc, 63)
	args := make([]string, 0, 3+len(dataLabels))
	args = append(args, cid, strconv.FormatUint(seq, 10))
	args = append(args, dataLabels...)
	args = append(args, protocol.SessionMAC(ts.sessionKey, "awrite", seq))
	name := protocol.JoinName(cfg.domain, "awrite", args)
	resp, err := resolver.query(name)
	if err != nil {
		return err
	}
	if resp != "OK" {
		return fmt.Errorf("awrite: %s", resp)
	}
	return nil
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
// Wire: cid . writeSeq . [writeChunks...] . [tcp] . readNonce . smac . axchg . domain
func agentExchange(cfg config, resolver *txtResolver, ts *tunnelSession, cid string, writeSeq uint64, writeData []byte) (exchangeResult, error) {
	readNonce := ts.nextNonce()
	args := make([]string, 0, 8)
	args = append(args, cid, strconv.FormatUint(writeSeq, 10))
	if writeSeq > 0 {
		compressed := ts.compressor.Encode(writeData)
		ct := gproxy.SealChunk(ts.aead, gproxy.DirClientToServer, writeSeq, compressed)
		enc := strings.ToLower(b32.EncodeToString(ct))
		args = append(args, codec.ChunkString(enc, 63)...)
	}
	if cfg.tcp {
		args = append(args, "tcp")
	}
	args = append(args, strconv.FormatUint(readNonce, 10))
	args = append(args, protocol.SessionMAC(ts.sessionKey, "axchg", readNonce))
	name := protocol.JoinName(cfg.domain, "axchg", args)

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
	case strings.HasPrefix(head, "ERR "):
		return exchangeResult{}, errors.New(head)
	case strings.HasPrefix(head, "ACK "):
		acked, perr := strconv.ParseUint(strings.TrimPrefix(head, "ACK "), 10, 64)
		if perr != nil {
			return exchangeResult{}, fmt.Errorf("malformed ACK: %w", perr)
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
			parsedSeq, perr := strconv.ParseUint(strings.TrimPrefix(readHead, "DATA "), 10, 64)
			if perr != nil {
				return exchangeResult{}, fmt.Errorf("malformed DATA seq: %w", perr)
			}
			b64 := strings.Join(segs[2:], "")
			ct, derr := base64.StdEncoding.DecodeString(b64)
			if derr != nil {
				return exchangeResult{}, fmt.Errorf("decode axchg payload: %w", derr)
			}
			pt, oerr := gproxy.OpenChunk(ts.aead, gproxy.DirServerToClient, parsedSeq, ct)
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
// Wire: cid . nonce . smac . aclose . domain
func agentClose(cfg config, resolver *txtResolver, ts *tunnelSession, cid string) error {
	nonce := ts.nextNonce()
	args := []string{
		cid,
		strconv.FormatUint(nonce, 10),
		protocol.SessionMAC(ts.sessionKey, "aclose", nonce),
	}
	name := protocol.JoinName(cfg.domain, "aclose", args)
	_, err := resolver.query(name)
	return err
}

// --- Authenticated name builder (used only by apoll, which has no cid yet) -

func authenticatedName(secret, domain, command string, args []string) string {
	ts := protocol.CurrentTimestamp(time.Now())
	token := protocol.AuthToken(secret, domain, command, ts, args)
	labels := make([]string, 0, len(args)+3)
	labels = append(labels, args...)
	labels = append(labels, ts, token)
	return protocol.JoinName(domain, command, labels)
}

// pumpRead is a guard to keep io.Reader imported until tests exercise the
// timeouts directly.
var _ = io.EOF
