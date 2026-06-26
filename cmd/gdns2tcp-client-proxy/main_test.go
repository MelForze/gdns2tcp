package main

import (
	"bytes"
	"flag"
	"io"
	stdlog "log"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"gdns2tcp/internal/dnsserver"
	"gdns2tcp/internal/protocol"

	"github.com/miekg/dns"
)

// startEmbeddedServer fires up an in-process gdns2tcp DNS server with the
// reverse SOCKS5 listener wired in. Returns the DNS and SOCKS5 addresses.
func startEmbeddedServer(t *testing.T) (dnsIP, dnsPort, socksAddr string, secret string) {
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

	secret = "agent-test-secret"
	cfg := dnsserver.Config{
		Domain:           "files.test",
		Secret:           secret,
		DataDir:          t.TempDir(),
		AllowList:        true,
		MaxUploadBytes:   dnsserver.DefaultMaxUploadBytes,
		MaxDownloadBytes: dnsserver.DefaultMaxDownloadBytes,
		AllowProxy:       true,
		ProxyMaxConn:     8,
		ProxyBufBytes:    64 * 1024,
		Logger:           stdlog.New(io.Discard, "", 0),
	}
	srv, err := dnsserver.New(cfg)
	if err != nil {
		_ = pc.Close()
		_ = socksLn.Close()
		t.Fatal(err)
	}
	dnsSrv := &dns.Server{PacketConn: pc, Net: "udp", Handler: srv}
	go func() { _ = dnsSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = dnsSrv.Shutdown() })

	// Hand the pre-bound SOCKS5 listener to the server.
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

// echoUpstream is the destination the operator's traffic should land at.
func echoUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						_, _ = conn.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

type testAgent struct {
	cfg      config
	resolver *txtResolver
	stop     chan struct{}

	mu      sync.Mutex
	stopped bool
	wg      sync.WaitGroup
}

func startTestAgent(t *testing.T, cfg config) *testAgent {
	t.Helper()
	a := &testAgent{
		cfg:      cfg,
		resolver: newTxtResolver(cfg),
		stop:     make(chan struct{}),
	}
	a.wg.Add(1)
	go a.pollLoop()
	t.Cleanup(func() { a.stopAndWait(t) })
	return a
}

func (a *testAgent) pollLoop() {
	defer a.wg.Done()
	for {
		select {
		case <-a.stop:
			return
		default:
		}
		cid, target, err := agentPoll(a.cfg, a.resolver)
		if err != nil || cid == "" {
			if !a.sleep(5 * time.Millisecond) {
				return
			}
			continue
		}
		a.startTunnel(cid, target)
	}
}

func (a *testAgent) sleep(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-a.stop:
		return false
	case <-timer.C:
		return true
	}
}

func (a *testAgent) startTunnel(cid, target string) {
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return
	}
	a.wg.Add(1)
	a.mu.Unlock()
	go func() {
		defer a.wg.Done()
		handleTunnel(a.cfg, a.resolver, cid, target)
	}()
}

func (a *testAgent) stopAndWait(t *testing.T) {
	t.Helper()
	a.mu.Lock()
	if !a.stopped {
		a.stopped = true
		close(a.stop)
		a.resolver.close()
	}
	a.mu.Unlock()

	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("agent goroutines did not stop")
	}
}

// TestParseFlagsDefaults pins the agent's defaults.
func TestParseFlagsDefaults(t *testing.T) {
	saved := os.Args
	savedFlag := flag.CommandLine
	t.Cleanup(func() {
		os.Args = saved
		flag.CommandLine = savedFlag
	})
	os.Args = []string{"agent", "-domain", "example.com", "-pass", "k"}
	flag.CommandLine = flag.NewFlagSet("agent", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	cfg := parseFlags()
	if cfg.domain != "example.com" || cfg.pass != "k" {
		t.Fatalf("required flags lost: %+v", cfg)
	}
	if cfg.dnsPort != "53" {
		t.Fatalf("default dns-port drift: %q", cfg.dnsPort)
	}
	if cfg.maxConn != 32 {
		t.Fatalf("default max-conn drift: %d", cfg.maxConn)
	}
}

// TestParseFlagsClamps verifies the runtime sanitization.
func TestParseFlagsClamps(t *testing.T) {
	saved := os.Args
	savedFlag := flag.CommandLine
	t.Cleanup(func() {
		os.Args = saved
		flag.CommandLine = savedFlag
	})
	os.Args = []string{"agent", "-domain", "d", "-pass", "p", "-max-conn", "9999", "-retries", "0", "-dns-port", "", "-poll-min", "-1ms", "-poll-max", "0s"}
	flag.CommandLine = flag.NewFlagSet("agent", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	cfg := parseFlags()
	if cfg.maxConn != 512 {
		t.Fatalf("max-conn should clamp to 512, got %d", cfg.maxConn)
	}
	if cfg.retries < 1 {
		t.Fatalf("retries should clamp to ≥1, got %d", cfg.retries)
	}
	if cfg.dnsPort != "53" {
		t.Fatalf("empty dns-port should default to 53, got %q", cfg.dnsPort)
	}
	if cfg.pollMin != 20*time.Millisecond {
		t.Fatalf("poll-min should default to 20ms, got %s", cfg.pollMin)
	}
	if cfg.pollMax != 200*time.Millisecond {
		t.Fatalf("poll-max should default to 200ms, got %s", cfg.pollMax)
	}
}

func TestParseFlagsPollMaxClampsToPollMin(t *testing.T) {
	saved := os.Args
	savedFlag := flag.CommandLine
	t.Cleanup(func() {
		os.Args = saved
		flag.CommandLine = savedFlag
	})
	os.Args = []string{"agent", "-domain", "d", "-pass", "p", "-poll-min", "75ms", "-poll-max", "50ms"}
	flag.CommandLine = flag.NewFlagSet("agent", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	cfg := parseFlags()
	if cfg.pollMin != 75*time.Millisecond {
		t.Fatalf("poll-min drifted: got %s", cfg.pollMin)
	}
	if cfg.pollMax != cfg.pollMin {
		t.Fatalf("poll-max should clamp to poll-min, got poll-min=%s poll-max=%s", cfg.pollMin, cfg.pollMax)
	}
}

// TestResolveDomainServerError covers the failure path.
func TestResolveDomainServerError(t *testing.T) {
	_, err := resolveDomainServer("nx-domain.invalid.test.")
	if err == nil {
		t.Fatal("expected error for unresolvable domain")
	}
}

// TestAgentPollEmpty: with nothing queued, apoll returns "" target.
func TestAgentPollEmpty(t *testing.T) {
	dnsIP, dnsPort, _, secret := startEmbeddedServer(t)
	cfg := config{
		domain:    "files.test",
		pass:      secret,
		dnsServer: dnsIP,
		dnsPort:   dnsPort,
		retries:   1,
	}
	cid, target, err := agentPoll(cfg, newTxtResolver(cfg))
	if err != nil {
		t.Fatalf("agentPoll: %v", err)
	}
	if cid != "" || target != "" {
		t.Fatalf("expected empty result, got cid=%q target=%q", cid, target)
	}
}

// TestAgentCloseUnknownCid: aclose on a cid the server has never seen still
// returns a clean OK so the agent's defer doesn't surface an error.
func TestAgentCloseUnknownCid(t *testing.T) {
	dnsIP, dnsPort, _, secret := startEmbeddedServer(t)
	cfg := config{
		domain:    "files.test",
		pass:      secret,
		dnsServer: dnsIP,
		dnsPort:   dnsPort,
		retries:   1,
	}
	cid := "0000000000000000"
	ts := &tunnelSession{sessionKey: protocol.DeriveSessionKey(cfg.pass, cid)}
	if err := agentClose(cfg, newTxtResolver(cfg), ts, cid); err != nil {
		t.Fatalf("agentClose: %v", err)
	}
}

// TestIsTimeout covers both branches of the helper.
func TestIsTimeout(t *testing.T) {
	if isTimeout(io.EOF) {
		t.Fatal("non-timeout error reported as timeout")
	}
	// Provoke a real timeout via SetReadDeadline on a Pipe.
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	_ = a.SetReadDeadline(time.Now().Add(-time.Second))
	if _, err := a.Read(make([]byte, 1)); err == nil || !isTimeout(err) {
		t.Fatalf("expected timeout, got %v", err)
	}
}

// TestEndToEndReverseSOCKS5OverTCP runs the full reverse tunnel with the
// agent talking to the DNS server over TCP. This exercises exchangeTCP in
// dnswire.go which is otherwise dead at the unit level.
func TestEndToEndReverseSOCKS5OverTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// Bring up a TCP-listening DNS server. The standard helper only opens
	// UDP, so we inline a small variant.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = tcpLn.Close()
		t.Fatal(err)
	}
	secret := "tcp-tunnel-secret"
	srv, err := dnsserver.New(dnsserver.Config{
		Domain:           "files.test",
		Secret:           secret,
		DataDir:          t.TempDir(),
		AllowList:        true,
		MaxUploadBytes:   dnsserver.DefaultMaxUploadBytes,
		MaxDownloadBytes: dnsserver.DefaultMaxDownloadBytes,
		AllowProxy:       true,
		ProxyMaxConn:     4,
		ProxyBufBytes:    32 * 1024,
		Logger:           stdlog.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	tcpDNSSrv := &dns.Server{Listener: tcpLn, Net: "tcp", Handler: srv}
	go func() { _ = tcpDNSSrv.ActivateAndServe() }()
	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go srv.HandleSOCKS5OperatorForTest(c)
		}
	}()
	t.Cleanup(func() {
		_ = tcpDNSSrv.Shutdown()
		_ = socksLn.Close()
		srv.Shutdown()
	})

	dnsPort := strconv.Itoa(tcpLn.Addr().(*net.TCPAddr).Port)
	upstream := echoUpstream(t)
	upHost, upPortStr, _ := net.SplitHostPort(upstream)
	upPort, _ := strconv.Atoi(upPortStr)

	agentCfg := config{
		domain:    "files.test",
		pass:      secret,
		dnsServer: "127.0.0.1",
		dnsPort:   dnsPort,
		tcp:       true, // <- exercises exchangeTCP
		pollMin:   5 * time.Millisecond,
		pollMax:   50 * time.Millisecond,
		maxConn:   4,
		retries:   3,
	}
	_ = startTestAgent(t, agentCfg)

	op, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	_, _ = op.Write([]byte{0x05, 0x01, 0x02})
	mr := make([]byte, 2)
	_, _ = io.ReadFull(op, mr)
	auth := []byte{0x01, byte(len("gdns2tcp"))}
	auth = append(auth, []byte("gdns2tcp")...)
	auth = append(auth, byte(len(secret)))
	auth = append(auth, []byte(secret)...)
	_, _ = op.Write(auth)
	authStatus := make([]byte, 2)
	_, _ = io.ReadFull(op, authStatus)
	if authStatus[1] != 0x00 {
		t.Fatalf("auth failed: %v", authStatus)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	for _, b := range net.ParseIP(upHost).To4() {
		req = append(req, b)
	}
	req = append(req, byte(upPort>>8), byte(upPort))
	_, _ = op.Write(req)
	rep := make([]byte, 10)
	_, _ = io.ReadFull(op, rep)
	if rep[1] != 0x00 {
		t.Fatalf("connect failed: %v", rep)
	}
	payload := []byte("hello-tcp-mode-tunnel")
	_, _ = op.Write(payload)
	_ = op.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(op, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

// TestEndToEndReverseSOCKS5 exercises the full reverse tunnel:
//  1. server + agent running
//  2. operator connects to server's SOCKS5 with username/password
//  3. operator CONNECTs to the echo upstream
//  4. agent (this process) polls, dials echo, bridges bytes
//  5. operator's payload should come back echoed
func TestEndToEndReverseSOCKS5(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dnsIP, dnsPort, socksAddr, secret := startEmbeddedServer(t)
	upstream := echoUpstream(t)

	agentCfg := config{
		domain:    "files.test",
		pass:      secret,
		dnsServer: dnsIP,
		dnsPort:   dnsPort,
		pollMin:   5 * time.Millisecond,
		pollMax:   50 * time.Millisecond,
		maxConn:   4,
		retries:   3,
	}
	_ = startTestAgent(t, agentCfg)

	// Operator-side SOCKS5 driver.
	upHost, upPortStr, _ := net.SplitHostPort(upstream)
	upPort, _ := strconv.Atoi(upPortStr)
	op, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()

	// Method selection: VER, NMETHODS, METHOD=0x02 (user/pass).
	if _, err := op.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	mr := make([]byte, 2)
	if _, err := io.ReadFull(op, mr); err != nil {
		t.Fatal(err)
	}
	if mr[1] != 0x02 {
		t.Fatalf("expected method 02, got %v", mr)
	}
	// Subnegotiation.
	auth := []byte{0x01, byte(len("gdns2tcp"))}
	auth = append(auth, []byte("gdns2tcp")...)
	auth = append(auth, byte(len(secret)))
	auth = append(auth, []byte(secret)...)
	if _, err := op.Write(auth); err != nil {
		t.Fatal(err)
	}
	authStatus := make([]byte, 2)
	if _, err := io.ReadFull(op, authStatus); err != nil {
		t.Fatal(err)
	}
	if authStatus[1] != 0x00 {
		t.Fatalf("auth failed: %v", authStatus)
	}

	// CONNECT.
	req := []byte{0x05, 0x01, 0x00, 0x01}
	for _, b := range net.ParseIP(upHost).To4() {
		req = append(req, b)
	}
	req = append(req, byte(upPort>>8), byte(upPort))
	if _, err := op.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(op, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0x00 {
		t.Fatalf("connect failed: %v", rep)
	}

	// Send + verify echo.
	payload := []byte("hello-via-reverse-tunnel")
	if _, err := op.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = op.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(op, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}
}

// TestEndToEndReverseSOCKS5BulkStreamReorder pushes a 256 KB deterministic
// payload through the tunnel and verifies byte-perfect echo. The point is to
// stress the new parallel aread (areadPipeline=8) reorder buffer in
// pumpOperatorToUpstream: with N workers issuing concurrent DNS queries,
// chunks frequently arrive out of seq order. Any reorder bug would corrupt
// the stream and trip the bytes.Equal check below.
func TestEndToEndReverseSOCKS5BulkStreamReorder(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	dnsIP, dnsPort, socksAddr, secret := startEmbeddedServer(t)
	upstream := echoUpstream(t)

	agentCfg := config{
		domain:    "files.test",
		pass:      secret,
		dnsServer: dnsIP,
		dnsPort:   dnsPort,
		pollMin:   2 * time.Millisecond,
		pollMax:   20 * time.Millisecond,
		maxConn:   4,
		retries:   3,
	}
	_ = startTestAgent(t, agentCfg)

	upHost, upPortStr, _ := net.SplitHostPort(upstream)
	upPort, _ := strconv.Atoi(upPortStr)
	op, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()

	_, _ = op.Write([]byte{0x05, 0x01, 0x02})
	mr := make([]byte, 2)
	_, _ = io.ReadFull(op, mr)
	auth := []byte{0x01, byte(len("gdns2tcp"))}
	auth = append(auth, []byte("gdns2tcp")...)
	auth = append(auth, byte(len(secret)))
	auth = append(auth, []byte(secret)...)
	_, _ = op.Write(auth)
	authStatus := make([]byte, 2)
	_, _ = io.ReadFull(op, authStatus)
	if authStatus[1] != 0x00 {
		t.Fatalf("auth failed: %v", authStatus)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	for _, b := range net.ParseIP(upHost).To4() {
		req = append(req, b)
	}
	req = append(req, byte(upPort>>8), byte(upPort))
	_, _ = op.Write(req)
	rep := make([]byte, 10)
	_, _ = io.ReadFull(op, rep)
	if rep[1] != 0x00 {
		t.Fatalf("connect failed: %v", rep)
	}

	// Deterministic 256 KB payload so a single-byte corruption is obvious.
	const N = 256 * 1024
	payload := make([]byte, N)
	for i := range payload {
		payload[i] = byte(i*7 ^ (i >> 8))
	}

	// Echo: write all bytes, then read them back. We do these on separate
	// goroutines because operator's TCP buffer would otherwise block writes.
	writeErr := make(chan error, 1)
	go func() {
		_, err := op.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, N)
	_ = op.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(op, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		// Find first divergence — far more useful than "256 KB mismatch".
		for i := range payload {
			if got[i] != payload[i] {
				t.Fatalf("first divergence at byte %d: got %#x want %#x", i, got[i], payload[i])
			}
		}
	}
}

// socks5Connect performs the full SOCKS5 handshake (user/pass auth + CONNECT)
// and returns the ready-to-use connection.
func socks5Connect(t *testing.T, socksAddr, secret, upstream string) net.Conn {
	t.Helper()
	upHost, upPortStr, _ := net.SplitHostPort(upstream)
	upPort, _ := strconv.Atoi(upPortStr)

	op, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = op.Write([]byte{0x05, 0x01, 0x02})
	mr := make([]byte, 2)
	_, _ = io.ReadFull(op, mr)
	auth := []byte{0x01, byte(len("gdns2tcp"))}
	auth = append(auth, []byte("gdns2tcp")...)
	auth = append(auth, byte(len(secret)))
	auth = append(auth, []byte(secret)...)
	_, _ = op.Write(auth)
	authStatus := make([]byte, 2)
	_, _ = io.ReadFull(op, authStatus)
	if authStatus[1] != 0x00 {
		op.Close()
		t.Fatalf("auth failed: %v", authStatus)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	for _, b := range net.ParseIP(upHost).To4() {
		req = append(req, b)
	}
	req = append(req, byte(upPort>>8), byte(upPort))
	_, _ = op.Write(req)
	rep := make([]byte, 10)
	_, _ = io.ReadFull(op, rep)
	if rep[1] != 0x00 {
		op.Close()
		t.Fatalf("connect failed: %v", rep)
	}
	return op
}

// startTCPEmbeddedServer is like startEmbeddedServer but binds a TCP DNS
// listener instead of UDP — required when the agent uses -tcp mode.
func startTCPEmbeddedServer(t *testing.T) (dnsIP, dnsPort, socksAddr string, secret string) {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = tcpLn.Close()
		t.Fatal(err)
	}
	secret = "tcp-bulk-secret"
	srv, err := dnsserver.New(dnsserver.Config{
		Domain:           "files.test",
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
		t.Fatal(err)
	}
	tcpDNSSrv := &dns.Server{Listener: tcpLn, Net: "tcp", Handler: srv}
	go func() { _ = tcpDNSSrv.ActivateAndServe() }()
	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go srv.HandleSOCKS5OperatorForTest(c)
		}
	}()
	t.Cleanup(func() {
		_ = tcpDNSSrv.Shutdown()
		_ = socksLn.Close()
		srv.Shutdown()
	})
	port := strconv.Itoa(tcpLn.Addr().(*net.TCPAddr).Port)
	return "127.0.0.1", port, socksLn.Addr().String(), secret
}

func testBulkEcho(t *testing.T, useTCP bool, payloadSize int) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration")
	}
	var dnsIP, dnsPort, socksAddr, secret string
	if useTCP {
		dnsIP, dnsPort, socksAddr, secret = startTCPEmbeddedServer(t)
	} else {
		dnsIP, dnsPort, socksAddr, secret = startEmbeddedServer(t)
	}
	upstream := echoUpstream(t)

	agentCfg := config{
		domain:        "files.test",
		pass:          secret,
		dnsServer:     dnsIP,
		dnsPort:       dnsPort,
		tcp:           useTCP,
		pollMin:       2 * time.Millisecond,
		pollMax:       20 * time.Millisecond,
		maxConn:       4,
		retries:       3,
		targetTimeout: 2 * time.Second,
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
	if _, err := io.ReadFull(op, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		for i := range payload {
			if got[i] != payload[i] {
				t.Fatalf("first divergence at byte %d: got %#x want %#x", i, got[i], payload[i])
			}
		}
	}
}

func TestEndToEndReverseSOCKS5_2MB_UDP(t *testing.T) {
	testBulkEcho(t, false, 2*1024*1024)
}

func TestEndToEndReverseSOCKS5_2MB_TCP(t *testing.T) {
	testBulkEcho(t, true, 2*1024*1024)
}
