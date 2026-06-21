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
	domain        string
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
	flag.StringVar(&cfg.domain, "domain", "", "authoritative gdns2tcp domain")
	flag.StringVar(&cfg.pass, "pass", "", "shared encryption secret (must match server's -secret)")
	flag.StringVar(&cfg.dnsServer, "dns-server", "", "DNS server address; empty resolves -domain and uses the first IP")
	flag.StringVar(&cfg.dnsPort, "dns-port", defaultDNSPort, "DNS server port; defaults to 53")
	flag.BoolVar(&cfg.tcp, "tcp", false, "use TCP instead of UDP for DNS queries")
	flag.DurationVar(&cfg.pollMin, "poll-min", 20*time.Millisecond, "minimum apoll/aread interval when active")
	flag.DurationVar(&cfg.pollMax, "poll-max", 200*time.Millisecond, "maximum apoll/aread interval after consecutive idle responses")
	flag.IntVar(&cfg.maxConn, "max-conn", 32, "maximum concurrent local tunnels (1-512)")
	flag.IntVar(&cfg.retries, "retries", 3, "DNS query attempts before failing")
	flag.DurationVar(&cfg.targetTimeout, "target-dial-timeout", 1*time.Second, "TCP dial timeout when the agent connects to the host the operator's SOCKS5 CONNECT asks for. Lower values speed up port-scan workloads through the tunnel (filtered ports release their cid sooner); raise if you legitimately tunnel to slow upstreams")
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
	if cfg.targetTimeout <= 0 {
		cfg.targetTimeout = 1 * time.Second
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
					gproxy.PutBuf(job.bufPtr)
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
	go func() {
		bufSize := int(ts.bufSize.Load())
		if bufSize < 1 {
			bufSize = 1
		}
		var seq uint64
		for {
			bufPtr := gproxy.GetBuf(bufSize)
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

type awriteJob struct {
	seq    uint64
	data   []byte
	bufPtr *[]byte // pooled buffer backing `data`; PutBuf releases after use
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
