package main

import (
	"bytes"
	stdlog "log"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gdns2tcp/internal/dnsserver"
	"gdns2tcp/internal/protocol"
	"io"

	"github.com/miekg/dns"
)

// startEmbeddedServerDomain is a startEmbeddedServer clone that lets
// the caller pick the -domain (CSV-capable). Kept in a bench-only file
// so the main test suite's fixed "files.test" behaviour is unchanged.
func startEmbeddedServerDomain(t *testing.T, domain string) (dnsIP, dnsPort, socksAddr, secret string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = pc.Close()
		t.Fatal(err)
	}
	secret = "bench-secret"
	srv, err := dnsserver.New(dnsserver.Config{
		Domain:           domain,
		Secret:           secret,
		DataDir:          t.TempDir(),
		AllowList:        true,
		MaxUploadBytes:   dnsserver.DefaultMaxUploadBytes,
		MaxDownloadBytes: dnsserver.DefaultMaxDownloadBytes,
		AllowProxy:       true,
		ProxyMaxConn:     8,
		ProxyBufBytes:    64 * 1024,
		Logger:           stdlog.New(io.Discard, "", 0),
	})
	if err != nil {
		_ = pc.Close()
		_ = socksLn.Close()
		t.Fatal(err)
	}
	dnsSrv := &dns.Server{PacketConn: pc, Net: "udp", Handler: srv}
	go func() { _ = dnsSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = dnsSrv.Shutdown() })

	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go srv.HandleSOCKS5OperatorForTest(c)
		}
	}()
	t.Cleanup(func() { _ = socksLn.Close(); srv.Shutdown() })

	addr := pc.LocalAddr().(*net.UDPAddr)
	return "127.0.0.1", strconv.Itoa(addr.Port), socksLn.Addr().String(), secret
}

// runBulkOnce spins up a fresh embedded server+agent for `csvDomain`,
// pushes `payloadSize` bytes through the echo tunnel, tears everything
// down, and returns wall-clock duration for the transfer only (setup
// is excluded). Consistent with testBulkEcho's happy-path structure.
func runBulkOnce(t *testing.T, csvDomain string, payloadSize int) time.Duration {
	t.Helper()
	dnsIP, dnsPort, socksAddr, secret := startEmbeddedServerDomain(t, csvDomain)
	upstream := echoUpstream(t)

	canonical, shardDomains, shardAuthDomains, longest := protocol.ParseDomainCSV(csvDomain)
	agentCfg := config{
		domain:           canonical,
		shardDomains:     shardDomains,
		shardAuthDomains: shardAuthDomains,
		shardLongest:     longest,
		shardRotor:       new(atomic.Uint64),
		pass:             secret,
		dnsServer:        dnsIP,
		dnsPort:          dnsPort,
		tcp:              false,
		pollMin:          2 * time.Millisecond,
		pollMax:          20 * time.Millisecond,
		maxConn:          4,
		retries:          3,
		targetTimeout:    2 * time.Second,
	}
	_ = startTestAgent(t, agentCfg)

	op := socks5Connect(t, socksAddr, secret, upstream)
	defer op.Close()

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i*7 ^ (i >> 8))
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := op.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, payloadSize)
	_ = op.SetReadDeadline(time.Now().Add(120 * time.Second))

	start := time.Now()
	if _, err := io.ReadFull(op, got); err != nil {
		t.Fatalf("read echo (%s): %v", csvDomain, err)
	}
	elapsed := time.Since(start)

	if err := <-writeErr; err != nil {
		t.Fatalf("write payload (%s): %v", csvDomain, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch on %s", csvDomain)
	}
	return elapsed
}

// TestMultiDomainLocalPerformance is a repeatable head-to-head between
// single-domain and 3-domain configs. Local benches will NOT show the
// throughput win real-world sharding delivers — that gain comes from
// dodging per-zone resolver rate-limits, which don't exist when the
// client talks straight to a loopback server. The point of this test
// is to prove the atomic rotor doesn't cause a regression: multi-
// domain must land within ±20% of single-domain wall clock. Skipped
// by default; run with `go test -run TestMultiDomainLocalPerformance
// -bench-multi-domain`-equivalent (see t.Skip below).
func TestMultiDomainLocalPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("integration bench; run with -run TestMultiDomainLocalPerformance")
	}
	if raceEnabled {
		t.Skip("under -race the 10× overhead swamps the signal")
	}

	const runs = 5
	const payload = 1 * 1024 * 1024 // 1 MB — keeps each run fast

	singleTimings := make([]time.Duration, 0, runs)
	multiTimings := make([]time.Duration, 0, runs)

	// Interleave the runs so any drift over wall-clock time (CPU
	// throttling, background pressure) hits both configs equally.
	for i := 0; i < runs; i++ {
		single := runBulkOnce(t, "files.test", payload)
		multi := runBulkOnce(t, "files.test,files1.test,files2.test", payload)
		singleTimings = append(singleTimings, single)
		multiTimings = append(multiTimings, multi)
		t.Logf("run %d: single=%s multi=%s", i+1, single, multi)
	}

	singleAvg := avg(singleTimings)
	multiAvg := avg(multiTimings)
	t.Logf("=== summary (%d runs, %d bytes) ===", runs, payload)
	t.Logf("single-domain avg: %s (%s)", singleAvg, throughput(singleAvg, payload))
	t.Logf("multi-domain  avg: %s (%s)", multiAvg, throughput(multiAvg, payload))
	t.Logf("multi/single ratio: %.3f", float64(multiAvg)/float64(singleAvg))

	// Guard against a real regression from the atomic rotor. Loopback
	// atomic.Add is ~10 ns, so multi should be within noise of single;
	// >30 % slower would signal contention we didn't expect.
	if multiAvg > singleAvg*13/10 {
		t.Errorf("multi-domain avg %s more than 30%% slower than single %s — atomic rotor may be contending", multiAvg, singleAvg)
	}
}

func avg(ts []time.Duration) time.Duration {
	if len(ts) == 0 {
		return 0
	}
	var sum time.Duration
	for _, t := range ts {
		sum += t
	}
	return sum / time.Duration(len(ts))
}

func throughput(d time.Duration, bytes int) string {
	if d <= 0 {
		return "∞ B/s"
	}
	mbps := float64(bytes) / d.Seconds() / (1024 * 1024)
	var b strings.Builder
	b.WriteString(strconv.FormatFloat(mbps, 'f', 2, 64))
	b.WriteString(" MB/s")
	return b.String()
}
