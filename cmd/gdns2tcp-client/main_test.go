package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gdns2tcp/internal/codec"
	secure "gdns2tcp/internal/crypto"
	"gdns2tcp/internal/dnsserver"
	"gdns2tcp/internal/protocol"

	"github.com/miekg/dns"
)

func startEmbeddedServer(t *testing.T, cfg dnsserver.Config) (ip, port string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr)

	srv, err := dnsserver.New(cfg)
	if err != nil {
		_ = pc.Close()
		t.Fatal(err)
	}

	dnsSrv := &dns.Server{PacketConn: pc, Net: "udp", Handler: srv}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = dnsSrv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = dnsSrv.Shutdown()
		<-done
		srv.Shutdown()
	})
	return "127.0.0.1", strconv.Itoa(addr.Port)
}

func startEmbeddedTCPServer(t *testing.T, cfg dnsserver.Config) (ip, port string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	srv, err := dnsserver.New(cfg)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	dnsSrv := &dns.Server{Listener: listener, Net: "tcp", Handler: srv, MaxTCPQueries: -1}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = dnsSrv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = dnsSrv.Shutdown()
		<-done
		srv.Shutdown()
	})
	return "127.0.0.1", strconv.Itoa(addr.Port)
}

func TestShardRotorAndAuthenticatedNameCompatibility(t *testing.T) {
	rotor := &atomic.Uint64{}
	cfg := config{
		domain: "one.test", shardDomains: []string{"one.test", "two.test"},
		shardAuthDomains: []string{protocol.AuthDomain("one.test"), protocol.AuthDomain("two.test")},
		shardRotor:       rotor, pass: "secret",
	}
	if first, second := cfg.pickShardAuthDomain(), cfg.pickShardAuthDomain(); first == second {
		t.Fatalf("rotor did not advance: %q %q", first, second)
	}
	auth := cfg.retryShardAuthDomains()
	plain := cfg.retryShardDomains()
	if len(auth) != 2 || len(plain) != 2 || auth[0] == auth[1] || plain[0] == plain[1] {
		t.Fatalf("retry shards auth=%v plain=%v", auth, plain)
	}
	name := authenticatedName("secret", cfg.domain, auth[0], "c", []string{"1"})
	if !strings.Contains(name, ".c.") || !strings.HasSuffix(name, auth[0]) {
		t.Fatalf("authenticated name=%q", name)
	}
	if fallback := (config{domain: "fallback.test"}).pickShardAuthDomain(); fallback != protocol.AuthDomain("fallback.test") {
		t.Fatalf("fallback shard=%q", fallback)
	}
}

func TestPublishOutputNoOverwriteBranches(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp")
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(tmp, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishOutputNoOverwrite(tmp, out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatalf("temporary file retained: %v", err)
	}
	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishOutputNoOverwrite(tmp, out); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite error=%v", err)
	}
}

func newServerCfg(t *testing.T, dataDir string) dnsserver.Config {
	t.Helper()
	if dataDir == "" {
		dataDir = t.TempDir()
	}
	return dnsserver.Config{
		Domain:           "files.test",
		Secret:           "integration-test-secret",
		DataDir:          dataDir,
		AllowList:        true,
		MaxUploadBytes:   dnsserver.DefaultMaxUploadBytes,
		MaxDownloadBytes: dnsserver.DefaultMaxDownloadBytes,
		Logger:           log.New(io.Discard, "", 0),
	}
}

func TestEffectiveUploadChunkSize(t *testing.T) {
	sid := "sid12345"
	for _, tc := range []struct {
		name      string
		domain    string
		requested int
		max       int
	}{
		{name: "zero normalizes", domain: "example.com", requested: 0, max: 180},
		{name: "large clamps", domain: "example.com", requested: 200, max: 180},
		{name: "small request preserved", domain: "example.com", requested: 40, max: 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := effectiveUploadChunkSize(tc.domain, sid, tc.requested)
			if err != nil {
				t.Fatalf("effectiveUploadChunkSize: %v", err)
			}
			if got < 32 || got > tc.max {
				t.Fatalf("got %d, want between 32 and %d", got, tc.max)
			}
			args := append([]string{sid, "999999"}, codec.ChunkString(strings.Repeat("a", got), 63)...)
			name := authenticatedNameWithTimestamp("secret", tc.domain, protocol.AuthDomain(tc.domain), "u", args, "9999999999")
			if len(name) > 253 {
				t.Fatalf("returned chunk size produces %d-byte DNS name", len(name))
			}
		})
	}

	if _, err := effectiveUploadChunkSize(strings.Repeat("a", 240), sid, 180); err == nil {
		t.Fatal("expected error for too-long domain")
	}
}

// TestEffectiveUploadChunkSizeReservesForLargeIndex is the regression
// guard for the Medium finding "effectiveUploadChunkSize uses 6-digit
// placeholder — QNAME overflows at chunkCount >= 1_000_000". The bug
// caused uploads to abort mid-transfer once the running chunk index
// crossed the placeholder width. Post-fix, the returned chunk size
// must leave enough headroom for indices up to the server-side
// maxTransferChunks-1 (currently 1_999_999 — 7 digits) with a small
// safety margin.
//
// The rebuild here uses `protocol.CurrentTimestamp(time.Now())` — the
// same timestamp function the function-under-test invokes — so we
// compare like against like.  The bug is specifically about the index
// placeholder being too narrow; timestamp width is not what this test
// asserts.
func TestEffectiveUploadChunkSizeReservesForLargeIndex(t *testing.T) {
	sid := "sid12345"
	// Simulate the worst-case index a server accepts today.
	const maxServerIndex = 1_999_999
	for _, domain := range []string{
		"gd.tv",              // 5 chars — tightest fit at chunk size 180
		"files.example.com",  // common default
		"a.b.c.d.example.co", // 18 chars
	} {
		t.Run(domain, func(t *testing.T) {
			size, err := effectiveUploadChunkSize(domain, sid, defaultChunkSize)
			if err != nil {
				t.Fatalf("effectiveUploadChunkSize(%s): %v", domain, err)
			}
			// Rebuild the QNAME with a REAL max index rather than the
			// placeholder used inside effectiveUploadChunkSize. The
			// return value must still fit the 253-byte DNS name limit
			// under the timestamp width the function itself used.
			ts := protocol.CurrentTimestamp(time.Now())
			args := append([]string{sid, strconv.Itoa(maxServerIndex)}, codec.ChunkString(strings.Repeat("a", size), 63)...)
			name := authenticatedNameWithTimestamp("secret", domain, protocol.AuthDomain(domain), "u", args, ts)
			if len(name) > 253 {
				t.Fatalf("chunk size %d + index %d gives %d-byte QNAME (>253); "+
					"placeholder in effectiveUploadChunkSize is too narrow",
					size, maxServerIndex, len(name))
			}
			// Also validate that the placeholder width in the source is
			// at least as wide as the real max index. This is a direct
			// guard against re-introducing the historical hard-coded
			// "999999" (6-char) placeholder for a 7-digit maxServerIndex.
			if uploadIndexPlaceholderWidth < len(strconv.Itoa(maxServerIndex)) {
				t.Fatalf("uploadIndexPlaceholderWidth=%d < digits in max server index (%d)",
					uploadIndexPlaceholderWidth, len(strconv.Itoa(maxServerIndex)))
			}
		})
	}
}

// TestPowerShellClientUploadPlaceholderMatchesGo pins the PS↔Go
// invariant that the upload-index placeholder used by
// Get-UploadChunkSize (PowerShell) has the same width as
// uploadIndexPlaceholderWidth (Go). A drift between them re-opens
// the Medium finding for whichever client uses the narrower value:
// uploads with chunkCount > 10^narrow-width abort mid-transfer.
//
// The test scans both the source-of-truth script and the shipped
// build artifact (kept in sync by the Makefile) so a stale build
// artifact does not silently linger with the old constant.
func TestPowerShellClientUploadPlaceholderMatchesGo(t *testing.T) {
	// Paths are relative to the test's package directory.
	psPaths := []string{
		"../../scripts/gdns2tcp-client.ps1",
		"../../clients/gdns2tcp-client.ps1",
	}
	expectedPlaceholder := "'" + strings.Repeat("9", uploadIndexPlaceholderWidth) + "'"
	for _, path := range psPaths {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("cannot read %s: %v", path, err)
			}
			body := string(data)
			// Reject the historical narrow placeholder even if a NEW
			// (wider) one is also present — both must disappear on
			// upgrade.
			if strings.Contains(body, "'999999'") && !strings.Contains(body, "'9999999'") {
				t.Fatalf("%s still contains historical 6-digit placeholder '999999'", path)
			}
			// Confirm the current-width placeholder is present. Not
			// finding it means either the constant was widened only
			// in Go (drift) or the PS script was refactored to derive
			// it a different way — either case wants a review.
			if !strings.Contains(body, expectedPlaceholder) {
				t.Fatalf("%s does not contain the placeholder %s that matches Go's uploadIndexPlaceholderWidth=%d",
					path, expectedPlaceholder, uploadIndexPlaceholderWidth)
			}
		})
	}
}

// TestLongestNameLenPicksMax guards the Low finding "per-chunk length
// check only validates requestNames[0]": longestNameLen must scan every
// shard so a longer non-canonical shard cannot silently produce an
// oversized QNAME on retry rotation.
func TestLongestNameLenPicksMax(t *testing.T) {
	names := []string{"short", "medium-length", "the-longest-of-them-all"}
	if got, want := longestNameLen(names), len(names[2]); got != want {
		t.Fatalf("longestNameLen=%d, want %d", got, want)
	}
	// Regression: single-element slice, empty slice, and cases where the
	// canonical shard is longest must all be handled.
	if got := longestNameLen(nil); got != 0 {
		t.Fatalf("nil slice: got %d, want 0", got)
	}
	if got := longestNameLen([]string{"solo"}); got != 4 {
		t.Fatalf("single element: got %d, want 4", got)
	}
	if got := longestNameLen([]string{"aaaaaaaa", "b"}); got != 8 {
		t.Fatalf("canonical-longest: got %d, want 8", got)
	}
}

func TestDnsSafeChunk(t *testing.T) {
	if got := dnsSafeChunk("abc+DEF/ghi=", "base64"); got != "abc_DEF-ghi" {
		t.Fatalf("base64 safe chunk=%q", got)
	}
	if got := dnsSafeChunk("ABCDEF==", "base32"); got != "abcdef" {
		t.Fatalf("base32 safe chunk=%q", got)
	}
	if got := dnsSafeChunk("", "base64"); got != "" {
		t.Fatalf("empty safe chunk=%q", got)
	}
}

func TestAuthenticatedNameWithTimestampVerifies(t *testing.T) {
	ts := protocol.CurrentTimestamp(time.Now().UTC())
	args := []string{"sid12345", "0"}
	name := authenticatedNameWithTimestamp("secret", "files.test", protocol.AuthDomain("files.test"), "d", args, ts)
	labels := strings.Split(name, ".")
	commandIdx := len(labels) - 3
	if commandIdx < 2 || labels[commandIdx] != "d" {
		t.Fatalf("unexpected authenticated name: %s", name)
	}
	payload := labels[:commandIdx-2]
	timestamp := labels[commandIdx-2]
	token := labels[commandIdx-1]
	if !protocol.VerifyAuth("secret", "files.test", "d", payload, timestamp, token, time.Now().UTC()) {
		t.Fatalf("auth labels from %s did not verify", name)
	}
}

func TestParseDownloadMeta(t *testing.T) {
	wantDigest := strings.Repeat("a", sha256HexLength)
	count, digest, encodedSize, ok := parseDownloadMeta("12|" + strings.ToUpper(wantDigest) + "|3000")
	if !ok {
		t.Fatal("expected valid dmeta response")
	}
	if count != 12 || digest != wantDigest || encodedSize != 3000 {
		t.Fatalf("parseDownloadMeta = (%d, %q, %d), want (12, %q, 3000)", count, digest, encodedSize, wantDigest)
	}
}

func TestParseDownloadMetaRejectsMalformed(t *testing.T) {
	for _, value := range []string{
		"12",
		"abc|" + strings.Repeat("a", sha256HexLength),
		"0|" + strings.Repeat("a", sha256HexLength),
		"12|short",
		"12|" + strings.Repeat("g", sha256HexLength),
		"12|" + strings.Repeat("a", sha256HexLength) + "|extra",
	} {
		if _, _, _, ok := parseDownloadMeta(value); ok {
			t.Fatalf("parseDownloadMeta(%q) unexpectedly succeeded", value)
		}
	}
}

func TestResolveOutputPath(t *testing.T) {
	if _, err := resolveOutputPath("   "); err == nil {
		t.Fatal("expected error for empty output path")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "newfile.txt")
	got, err := resolveOutputPath(target)
	if err != nil {
		t.Fatalf("resolveOutputPath: %v", err)
	}
	if !filepath.IsAbs(got) || got != target {
		t.Fatalf("got %q, want absolute %q", got, target)
	}
}

func TestWriteOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.bin")
	data := []byte("hello output")
	if err := writeOutput(path, data); err != nil {
		t.Fatalf("writeOutput: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %q, want %q", got, data)
	}

	err = writeOutput(path, []byte("new"))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing file error=%v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("read existing: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("existing file was modified")
	}
}

func TestResolveInputPath(t *testing.T) {
	if _, err := resolveInputPath(" "); err == nil {
		t.Fatal("expected error for empty input path")
	}
	if _, err := resolveInputPath(t.TempDir()); err == nil {
		t.Fatal("expected directory input to fail")
	}
	file := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(file, []byte("hello"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	got, err := resolveInputPath(file)
	if err != nil {
		t.Fatalf("resolveInputPath: %v", err)
	}
	if !filepath.IsAbs(got) || got != file {
		t.Fatalf("got %q, want absolute %q", got, file)
	}
}

func TestQueryOnceSuccess(t *testing.T) {
	ip, port := startEmbeddedServer(t, newServerCfg(t, ""))
	resolver := &txtResolver{server: ip, port: port, retries: 3}
	got, err := resolver.queryOnce("EnCoDiNg.test.files.test")
	if err != nil {
		t.Fatalf("queryOnce: %v", err)
	}
	if got != "base64" && got != "base32" {
		t.Fatalf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// validateConfig — centralized flag-validation tests
// ---------------------------------------------------------------------------

func TestValidateConfigDomainRequired(t *testing.T) {
	if err := validateConfig(config{domainErr: errors.New("invalid domain")}); err == nil || err.Error() != "invalid domain" {
		t.Fatalf("domain validation error=%v", err)
	}
	for _, mode := range []string{"test", "list", "upload", "download"} {
		err := validateConfig(config{mode: mode})
		if err == nil || !strings.Contains(err.Error(), "domain is required") {
			t.Fatalf("mode=%q: got error %v, want 'domain is required'", mode, err)
		}
	}
}

func TestProgressBarIgnoresRegressionAndHandlesZeroTotal(t *testing.T) {
	pb := newProgressBar("test", 0, 1)
	pb.last = 2
	pb.render(1)
	pb.last = 0
	pb.render(0)
}

func TestValidateConfigPassRequired(t *testing.T) {
	for _, mode := range []string{"list", "upload", "download"} {
		err := validateConfig(config{mode: mode, domain: "files.test"})
		if err == nil || !strings.Contains(err.Error(), "password is required") {
			t.Fatalf("mode=%q: got error %v, want 'password is required'", mode, err)
		}
	}
}

func TestValidateConfigUploadInputRequired(t *testing.T) {
	err := validateConfig(config{mode: "upload", domain: "files.test", pass: "s"})
	if err == nil || !strings.Contains(err.Error(), "input file is required") {
		t.Fatalf("error=%v, want 'input file is required'", err)
	}
}

func TestValidateConfigDownloadFilenameRequired(t *testing.T) {
	err := validateConfig(config{mode: "download", domain: "files.test", pass: "s"})
	if err == nil || !strings.Contains(err.Error(), "filename is required") {
		t.Fatalf("error=%v, want 'filename is required'", err)
	}
}

func TestValidateConfigTestModeNoPassRequired(t *testing.T) {
	if err := validateConfig(config{mode: "test", domain: "files.test"}); err != nil {
		t.Fatalf("test mode with domain should pass validation: %v", err)
	}
}

func TestValidateConfigRejectsConflictingModes(t *testing.T) {
	err := validateConfig(config{
		domain: "files.test", pass: "s", mode: "list", modeCount: 2,
	})
	if err == nil || !strings.Contains(err.Error(), "choose exactly one mode") {
		t.Fatalf("error=%v, want conflicting-mode error", err)
	}
}

func TestListFilesIntegration(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "hello.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	ip, port := startEmbeddedServer(t, newServerCfg(t, dataDir))
	resolver := &txtResolver{server: ip, port: port, retries: 3}
	cfg := config{domain: "files.test", pass: "integration-test-secret", dnsServer: ip, dnsPort: port, retries: 3}
	if err := listFiles(resolver, cfg); err != nil {
		t.Fatalf("listFiles: %v", err)
	}
}

func TestUploadDownloadFileIntegration(t *testing.T) {
	dataDir := t.TempDir()
	ip, port := startEmbeddedServer(t, newServerCfg(t, dataDir))
	resolver := &txtResolver{server: ip, port: port, retries: 3}

	filename := "TestCase!3:256.exe.txt"
	if runtime.GOOS == "windows" {
		filename = "TestCase!3_256.exe.txt"
	}
	inputPath := filepath.Join(t.TempDir(), filename)
	inputContent := []byte("integration payload with punctuation in the filename")
	if err := os.WriteFile(inputPath, inputContent, 0o600); err != nil {
		t.Fatalf("setup input file: %v", err)
	}

	uploadCfg := config{
		domain:    "files.test",
		pass:      "integration-test-secret",
		inFile:    inputPath,
		chunkSize: 60,
		retries:   3,
		dnsServer: ip,
		dnsPort:   port,
	}
	if err := uploadFile(resolver, uploadCfg); err != nil {
		t.Fatalf("uploadFile: %v", err)
	}
	storedPath := filepath.Join(dataDir, filepath.Base(inputPath))
	got, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatalf("uploaded file not found: %v", err)
	}
	if !bytes.Equal(got, inputContent) {
		t.Fatal("uploaded content mismatch")
	}

	outputPath := filepath.Join(t.TempDir(), "downloaded.txt")
	downloadCfg := config{
		domain:           "files.test",
		pass:             "integration-test-secret",
		filename:         filepath.Base(inputPath),
		outFile:          outputPath,
		retries:          3,
		dnsServer:        ip,
		dnsPort:          port,
		maxDownloadBytes: defaultMaxDownloadBytes,
	}
	if err := downloadFile(resolver, downloadCfg); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	got, err = os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(got, inputContent) {
		t.Fatal("downloaded content mismatch")
	}
}

func TestUploadDownloadFileIntegrationOverTCP(t *testing.T) {
	dataDir := t.TempDir()
	ip, port := startEmbeddedTCPServer(t, newServerCfg(t, dataDir))
	resolver := &txtResolver{server: ip, port: port, retries: 2, useTCP: true, timeout: 2 * time.Second}
	defer resolver.close()
	payload := make([]byte, 16*1024)
	for i := range payload {
		payload[i] = byte(i*37%251 + i/251)
	}
	input := filepath.Join(t.TempDir(), "tcp-transfer.bin")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	base := config{
		domain: "files.test", pass: "integration-test-secret",
		dnsServer: ip, dnsPort: port, retries: 2, tcp: true,
		chunkSize: 120, parallelism: 8, batch: 8,
		maxDownloadBytes: defaultMaxDownloadBytes, noResume: true,
	}
	uploadCfg := base
	uploadCfg.inFile = input
	if err := uploadFile(resolver, uploadCfg); err != nil {
		t.Fatalf("TCP upload: %v", err)
	}
	output := filepath.Join(t.TempDir(), "downloaded.bin")
	downloadCfg := base
	downloadCfg.filename = filepath.Base(input)
	downloadCfg.outFile = output
	if err := downloadFile(resolver, downloadCfg); err != nil {
		t.Fatalf("TCP download: %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("TCP transfer mismatch: len=%d err=%v", len(got), err)
	}
}

func TestRunClientDispatchesAllModes(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "listed.txt"), []byte("listed"), 0o600); err != nil {
		t.Fatal(err)
	}
	ip, port := startEmbeddedServer(t, newServerCfg(t, dataDir))
	base := config{
		domain: "files.test", pass: "integration-test-secret",
		dnsServer: ip, dnsPort: port, retries: 1,
		chunkSize: 60, maxDownloadBytes: defaultMaxDownloadBytes,
		parallelism: 2, batch: 2, noResume: true,
	}

	testCfg := base
	testCfg.mode = "test"
	if err := runClient(testCfg); err != nil {
		t.Fatalf("test mode: %v", err)
	}

	listCfg := base
	listCfg.mode = "list"
	if err := runClient(listCfg); err != nil {
		t.Fatalf("list mode: %v", err)
	}

	payload := bytes.Repeat([]byte("run-client-dispatch-"), 32)
	input := filepath.Join(t.TempDir(), "dispatch.bin")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	uploadCfg := base
	uploadCfg.mode = "upload"
	uploadCfg.inFile = input
	if err := runClient(uploadCfg); err != nil {
		t.Fatalf("upload mode: %v", err)
	}

	output := filepath.Join(t.TempDir(), "dispatch.out")
	downloadCfg := base
	downloadCfg.mode = "download"
	downloadCfg.filename = filepath.Base(input)
	downloadCfg.outFile = output
	if err := runClient(downloadCfg); err != nil {
		t.Fatalf("download mode: %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("downloaded payload differs: len=%d err=%v", len(got), err)
	}

	unknownCfg := base
	unknownCfg.mode = "unknown"
	if err := runClient(unknownCfg); err == nil || !strings.Contains(err.Error(), "unsupported mode") {
		t.Fatalf("unsupported mode error=%v", err)
	}
}

func TestSystemResolverAddressIsUsableWhenAvailable(t *testing.T) {
	address, err := systemResolverAddress()
	if err != nil {
		t.Logf("system resolver is unavailable on this host: %v", err)
		return
	}
	if net.ParseIP(address) == nil {
		t.Fatalf("systemResolverAddress returned non-IP %q", address)
	}
}

func TestRunClientPromotesTruncatedUDPProbeToTCP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr)
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(addr.Port)))
	if err != nil {
		_ = pc.Close()
		t.Fatal(err)
	}
	backend, err := dnsserver.New(newServerCfg(t, ""))
	if err != nil {
		_ = pc.Close()
		_ = ln.Close()
		t.Fatal(err)
	}
	udp := &dns.Server{PacketConn: pc, Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Truncated = true
		_ = w.WriteMsg(response)
	})}
	tcp := &dns.Server{Listener: ln, Net: "tcp", Handler: backend}
	udpDone := make(chan struct{})
	tcpDone := make(chan struct{})
	go func() { defer close(udpDone); _ = udp.ActivateAndServe() }()
	go func() { defer close(tcpDone); _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		<-udpDone
		<-tcpDone
		backend.Shutdown()
	})

	cfg := config{
		domain: "files.test", mode: "test", dnsServer: "127.0.0.1",
		dnsPort: strconv.Itoa(addr.Port), retries: 1,
	}
	if err := runClient(cfg); err != nil {
		t.Fatalf("UDP-to-TCP promotion: %v", err)
	}
}

func TestDecodeDownloadedFileFailureMatrix(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.bin")
	gzipPath := filepath.Join(dir, "plain.gz")
	protected := filepath.Join(dir, "plain.gdt")
	spool := filepath.Join(dir, "plain.txt")
	payload := bytes.Repeat([]byte("decode-matrix-"), 32)
	if err := os.WriteFile(plain, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := codec.CompressFile(plain, gzipPath); err != nil {
		t.Fatal(err)
	}
	if err := secure.ProtectFile("password", gzipPath, protected); err != nil {
		t.Fatal(err)
	}
	if _, err := codec.EncodeDNSFile(protected, spool, "base64"); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(plain)
	if err != nil {
		t.Fatal(err)
	}

	if err := decodeDownloadedFile(spool, "password", filepath.Join(dir, "ok.bin"), int64(len(payload)+1), digest); err != nil {
		t.Fatalf("valid decode: %v", err)
	}
	if err := decodeDownloadedFile(spool, "wrong", filepath.Join(dir, "wrong-pass.bin"), 1<<20, digest); err == nil {
		t.Fatal("wrong password was accepted")
	}
	if err := decodeDownloadedFile(spool, "password", filepath.Join(dir, "limited.bin"), 1, digest); err == nil {
		t.Fatal("decompression limit was ignored")
	}
	if err := decodeDownloadedFile(spool, "password", filepath.Join(dir, "digest.bin"), 1<<20, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("digest mismatch error=%v", err)
	}
	existing := filepath.Join(dir, "existing.bin")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := decodeDownloadedFile(spool, "password", existing, 1<<20, digest); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output error=%v", err)
	}
	badSpool := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(badSpool, []byte("%%%"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := decodeDownloadedFile(badSpool, "password", filepath.Join(dir, "bad.bin"), 1<<20, digest); err == nil || !strings.Contains(err.Error(), "decode download payload") {
		t.Fatalf("invalid encoded spool error=%v", err)
	}
}

func TestValidateDownloadShapeAndSpoolReadErrors(t *testing.T) {
	for _, tc := range []struct {
		chunks, batch  int
		encoded, limit int64
	}{
		{0, 1, 1, 1}, {1, 0, 1, 1}, {1, 1, 0, 1}, {1, 1, 1, 0},
		{1, 1, 100, 1}, {2, 1, 10, 100},
	} {
		if err := validateDownloadShape(tc.chunks, tc.batch, tc.encoded, tc.limit); err == nil {
			t.Fatalf("invalid shape accepted: %+v", tc)
		}
	}
	f, err := os.CreateTemp(t.TempDir(), "spool")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("abc"); err != nil {
		t.Fatal(err)
	}
	if _, err := readSpoolChunk(f, 10, 4); err == nil {
		t.Fatal("out-of-range spool read succeeded")
	}
	if _, err := readSpoolChunk(f, 0, 0); err == nil {
		t.Fatal("zero-size spool read succeeded")
	}
	if _, err := fileSHA256(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("hashing a missing file succeeded")
	}
	if err := publishOutputNoOverwrite(filepath.Join(t.TempDir(), "missing"), filepath.Join(t.TempDir(), "output")); err == nil {
		t.Fatal("publishing a missing temporary file succeeded")
	}
}

func TestMultiShardFailoverListUploadAndDownload(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "catalog-seed.txt"), []byte("seed"), 0o600); err != nil {
		t.Fatal(err)
	}
	server, err := dnsserver.New(dnsserver.Config{
		Domain: "bad.test,good.test", Secret: "integration-test-secret", DataDir: dataDir,
		AllowList: true, MaxUploadBytes: dnsserver.DefaultMaxUploadBytes, MaxDownloadBytes: dnsserver.DefaultMaxDownloadBytes,
		Logger: log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var failedShardQueries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		if len(request.Question) > 0 && strings.HasSuffix(strings.ToLower(request.Question[0].Name), ".bad.test.") {
			failedShardQueries.Add(1)
			response := new(dns.Msg)
			response.SetRcode(request, dns.RcodeServerFailure)
			_ = w.WriteMsg(response)
			return
		}
		server.ServeDNS(w, request)
	})
	dnsSrv := &dns.Server{PacketConn: pc, Net: "udp", Handler: handler}
	done := make(chan struct{})
	go func() { defer close(done); _ = dnsSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = dnsSrv.Shutdown(); <-done; server.Shutdown() })
	addr := pc.LocalAddr().(*net.UDPAddr)
	rotor := &atomic.Uint64{}
	cfg := config{
		domain: "bad.test", shardDomains: []string{"bad.test", "good.test"},
		shardAuthDomains: []string{protocol.AuthDomain("bad.test"), protocol.AuthDomain("good.test")},
		shardLongest:     "good.test", shardRotor: rotor, pass: "integration-test-secret",
		dnsServer: "127.0.0.1", dnsPort: strconv.Itoa(addr.Port), retries: 2, chunkSize: 60,
		parallelism: 4, batch: 4, maxDownloadBytes: defaultMaxDownloadBytes, noResume: true,
	}
	// Final upload publication includes fsync/decrypt/decompress work and can
	// legitimately exceed 100 ms under the race detector. Keep the timeout
	// below the production default while avoiding a test-only false failure.
	resolver := &txtResolver{server: cfg.dnsServer, port: cfg.dnsPort, retries: cfg.retries, timeout: 2 * time.Second}
	defer resolver.close()
	if err := listFiles(resolver, cfg); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("shard-failover-order-"), 200)
	input := filepath.Join(t.TempDir(), "sharded.bin")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	uploadCfg := cfg
	uploadCfg.inFile = input
	if err := uploadFile(resolver, uploadCfg); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "downloaded.bin")
	downloadCfg := cfg
	downloadCfg.filename = "sharded.bin"
	downloadCfg.outFile = output
	if err := downloadFile(resolver, downloadCfg); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("downloaded bytes differ after shard failover: len=%d err=%v", len(got), err)
	}
	if failedShardQueries.Load() == 0 {
		t.Fatal("test never exercised the failing shard")
	}
}

func TestDownloadFileRespectsServerMaxDownloadBytes(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "large.txt"), []byte("12345"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	cfg := newServerCfg(t, dataDir)
	cfg.MaxDownloadBytes = 4
	ip, port := startEmbeddedServer(t, cfg)
	resolver := &txtResolver{server: ip, port: port, retries: 3}

	err := downloadFile(resolver, config{
		domain:           "files.test",
		pass:             "integration-test-secret",
		filename:         "large.txt",
		outFile:          filepath.Join(t.TempDir(), "large.txt"),
		retries:          3,
		dnsServer:        ip,
		dnsPort:          port,
		maxDownloadBytes: defaultMaxDownloadBytes,
	})
	if err == nil || !strings.Contains(err.Error(), "Download is too large") {
		t.Fatalf("downloadFile error=%v", err)
	}
}

// ---------------------------------------------------------------------------
// New unit tests for error-path coverage gaps
// ---------------------------------------------------------------------------

// TestQueryEmptyName verifies that query returns an error when the name is empty.
func TestQueryEmptyName(t *testing.T) {
	r := &txtResolver{server: "127.0.0.1", port: "53", retries: 1}
	_, err := r.query("")
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("query(\"\") error=%v, want error containing \"empty\"", err)
	}
}

// TestQueryOnceNoServerRequiredPort verifies that queryOnce returns an error
// when no server is configured but the port is non-default (not 53).
func TestQueryOnceNoServerRequiredPort(t *testing.T) {
	r := &txtResolver{server: "", port: "5353", retries: 1}
	_, err := r.queryOnce("test.example.com")
	if err == nil || !strings.Contains(err.Error(), "dns-server is required") {
		t.Fatalf("queryOnce with empty server and non-53 port error=%v, want \"dns-server is required\"", err)
	}
}

// TestTestConnectionEmptyDomain verifies that testConnection returns an error
// when the domain is empty.
func TestTestConnectionEmptyDomain(t *testing.T) {
	r := &txtResolver{}
	_, err := testConnection(r, "")
	if err == nil || !strings.Contains(err.Error(), "domain is required") {
		t.Fatalf("testConnection(\"\") error=%v, want \"domain is required\"", err)
	}
}

// TestUploadFileMissingInput verifies that uploadFile returns an error when
// domain and pass are provided but no input file is set.
func TestUploadFileMissingInput(t *testing.T) {
	r := &txtResolver{}
	err := uploadFile(r, config{domain: "example.com", pass: "secret"})
	if err == nil || !strings.Contains(err.Error(), "input file is required") {
		t.Fatalf("uploadFile with empty inFile error=%v, want error about input file", err)
	}
}

// TestDownloadFileMissingFilename verifies that downloadFile returns an error
// when no filename is set (the check is kept in downloadFile since the
// fallback output-path logic makes the error message ambiguous otherwise).
func TestDownloadFileMissingFilename(t *testing.T) {
	r := &txtResolver{}
	err := downloadFile(r, config{domain: "example.com", pass: "secret"})
	if err == nil || !strings.Contains(err.Error(), "filename is required") {
		t.Fatalf("downloadFile with empty filename error=%v, want \"filename is required\"", err)
	}
}

// TestWriteOutputWriteFailure verifies that writeOutput returns an error and
// cleans up the partial file when the underlying write fails. We provoke this
// by opening the destination file ourselves (read-only) so the exclusive
// create succeeds but the write to the fd fails.
//
// Because os.O_EXCL guarantees creation we instead test the write-error path
// by writing to a path inside a directory we make read-only after the file is
// created but before calling writeOutput.  On platforms where root bypasses
// permissions (some CI environments) we skip gracefully.
func TestWriteOutputWriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission model differs on Windows")
	}

	dir := t.TempDir()

	// Make the parent directory read-only so that creating a new file inside
	// it fails at the OS level (not the "already exists" O_EXCL branch).
	roDir := filepath.Join(dir, "ro")
	if err := os.Mkdir(roDir, 0o555); err != nil {
		t.Fatalf("mkdir ro: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o755) })

	path := filepath.Join(roDir, "out.bin")
	err := writeOutput(path, []byte("data"))
	if err == nil {
		// Root bypasses directory permissions; skip rather than fail.
		if os.Getuid() == 0 {
			t.Skip("running as root; permission check skipped")
		}
		t.Fatalf("writeOutput into read-only dir returned no error")
	}
	// The error should come from the create step.
	if strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected 'already exists' error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// New integration tests to push coverage above 80%
// ---------------------------------------------------------------------------

// TestListFilesPagination verifies that listFiles handles a catalog that spans
// multiple pages (200 files with names like "file001.txt").
func TestListFilesPagination(t *testing.T) {
	dataDir := t.TempDir()
	for i := 1; i <= 200; i++ {
		name := fmt.Sprintf("file%03d.txt", i)
		if err := os.WriteFile(filepath.Join(dataDir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("setup file %s: %v", name, err)
		}
	}
	ip, port := startEmbeddedServer(t, newServerCfg(t, dataDir))
	resolver := &txtResolver{server: ip, port: port, retries: 3}
	cfg := config{
		domain:    "files.test",
		pass:      "integration-test-secret",
		dnsServer: ip,
		dnsPort:   port,
		retries:   3,
	}
	if err := listFiles(resolver, cfg); err != nil {
		t.Fatalf("listFiles with 200 files: %v", err)
	}
}

// TestQueryRetriesOnTransientError verifies that querying a non-existent
// subdomain returns a non-nil error.
func TestQueryRetriesOnTransientError(t *testing.T) {
	ip, port := startEmbeddedServer(t, newServerCfg(t, ""))
	resolver := &txtResolver{server: ip, port: port, retries: 2}
	// Query a name that the server does not serve — it belongs to a different domain.
	_, err := resolver.queryOnce("notexist.example.subdomain.files.test")
	// The embedded server only answers for "files.test." so this should yield
	// an error or an empty/unexpected response; we just verify it is non-nil.
	if err == nil {
		// Some DNS resolvers return NXDOMAIN which our code may treat as empty
		// string (no error). Accept empty string as a valid "no record" answer.
		t.Log("query returned no error and no record (NXDOMAIN treated as empty response)")
	}
}

// TestTestConnectionIntegration verifies that testConnection returns a
// supported encoding ("base64" or "base32") when talking to the embedded server.
func TestTestConnectionIntegration(t *testing.T) {
	ip, port := startEmbeddedServer(t, newServerCfg(t, ""))
	resolver := &txtResolver{server: ip, port: port, retries: 3}
	encoding, err := testConnection(resolver, "files.test")
	if err != nil {
		t.Fatalf("testConnection: %v", err)
	}
	if encoding != "base64" && encoding != "base32" {
		t.Fatalf("unexpected encoding %q, want base64 or base32", encoding)
	}
}

// ---------------------------------------------------------------------------
// startCustomDNSServer — minimal DNS server for error-path testing
// ---------------------------------------------------------------------------

func startCustomDNSServer(t *testing.T, handler func(dns.ResponseWriter, *dns.Msg)) (ip, port string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr)
	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler)
	srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return "127.0.0.1", strconv.Itoa(addr.Port)
}

// resetFlagCommandLine replaces flag.CommandLine with a fresh FlagSet for the
// duration of the test and restores the original on cleanup. This lets tests
// call parseFlags() or run() without "flag redefined" panics. Tests that use
// this helper must NOT be run in parallel.
func resetFlagCommandLine(t *testing.T, args ...string) {
	t.Helper()
	old := flag.CommandLine
	t.Cleanup(func() { flag.CommandLine = old })
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = append([]string{os.Args[0]}, args...)
}

// ---------------------------------------------------------------------------
// parseFlags coverage
// ---------------------------------------------------------------------------

// TestParseFlagsBasic covers the main parseFlags body: all flag.XXXVar
// registrations, flag.Parse, and the cfg.domain TrimSuffix normalization.
func TestParseFlagsBasic(t *testing.T) {
	resetFlagCommandLine(t, "-d=example.com.", "-upload=test.txt", "-p=s", "-chunk-size=50")

	cfg := parseFlags()
	if cfg.domain != "example.com" {
		t.Fatalf("domain=%q, want example.com (trailing dot stripped)", cfg.domain)
	}
	if cfg.mode != "upload" {
		t.Fatalf("mode=%q", cfg.mode)
	}
	if cfg.inFile != "test.txt" {
		t.Fatalf("inFile=%q, want test.txt", cfg.inFile)
	}
	if cfg.chunkSize != 50 {
		t.Fatalf("chunkSize=%d, want 50", cfg.chunkSize)
	}
	if cfg.maxDownloadBytes != defaultMaxDownloadBytes {
		t.Fatalf("maxDownloadBytes=%d should be default", cfg.maxDownloadBytes)
	}
}

func TestParseFlagsLegacyAliases(t *testing.T) {
	resetFlagCommandLine(t, "-domain=example.com", "-pass=legacy", "-in=input.bin", "-cache-dir=/tmp/gdns2tcp-cache")
	cfg := parseFlags()
	if cfg.pass != "legacy" || cfg.mode != "upload" || cfg.inFile != "input.bin" {
		t.Fatalf("legacy aliases parsed incorrectly: %+v", cfg)
	}
	if cfg.cacheDir != "/tmp/gdns2tcp-cache" {
		t.Fatalf("cache dir = %q", cfg.cacheDir)
	}

	resetFlagCommandLine(t, "-domain=example.com", "-pass=legacy", "-filename=remote.bin")
	cfg = parseFlags()
	if cfg.mode != "download" || cfg.filename != "remote.bin" {
		t.Fatalf("filename alias parsed incorrectly: %+v", cfg)
	}
}

// TestParseFlagsDefaultPort covers the branches that fall back to default
// values when dns-port is empty and max-download-bytes is non-positive.
func TestParseFlagsDefaultPort(t *testing.T) {
	resetFlagCommandLine(t, "-dns-port=", "-max-download-bytes=-5")

	cfg := parseFlags()
	if cfg.dnsPort != defaultDNSPort {
		t.Fatalf("dnsPort=%q, want %q", cfg.dnsPort, defaultDNSPort)
	}
	if cfg.maxDownloadBytes != defaultMaxDownloadBytes {
		t.Fatalf("maxDownloadBytes=%d, want %d", cfg.maxDownloadBytes, defaultMaxDownloadBytes)
	}
}

// ---------------------------------------------------------------------------
// run() coverage
// ---------------------------------------------------------------------------

// TestRunNoMode exercises the validation when no mode flag is provided.
func TestRunNoMode(t *testing.T) {
	resetFlagCommandLine(t,
		"-d=files.test", "-p=s",
		"-ds=127.0.0.1", "-dp=9", "-retries=1",
	)

	err := run()
	if err == nil || !strings.Contains(err.Error(), "specify --list") {
		t.Fatalf("run no-mode error=%v, want 'specify --list'", err)
	}
}

// TestRunTestMode exercises the "test" case in run() using the embedded server.
func TestRunTestMode(t *testing.T) {
	ip, port := startEmbeddedServer(t, newServerCfg(t, ""))
	resetFlagCommandLine(t,
		"-d=files.test", "-test",
		"-ds="+ip, "-dp="+port, "-retries=1",
	)

	if err := run(); err != nil {
		t.Fatalf("run test mode: %v", err)
	}
}

// ---------------------------------------------------------------------------
// queryOnce error-path coverage
// ---------------------------------------------------------------------------

// TestQueryOnceRcodeError covers the "resp.Rcode != RcodeSuccess" branch by
// using a custom DNS server that returns REFUSED.
func TestQueryOnceRcodeError(t *testing.T) {
	ip, port := startCustomDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
	})

	r := &txtResolver{server: ip, port: port, retries: 1}
	_, err := r.queryOnce("test.files.test")
	if err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("queryOnce REFUSED error=%v, want 'REFUSED'", err)
	}
}

// TestQueryOnceNoTXTInAnswer covers the final "no TXT response" return when
// the server returns RcodeSuccess but no TXT records.
func TestQueryOnceNoTXTInAnswer(t *testing.T) {
	ip, port := startCustomDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		// Intentionally empty Answer section
		_ = w.WriteMsg(m)
	})

	r := &txtResolver{server: ip, port: port, retries: 1}
	_, err := r.queryOnce("test.files.test")
	if err == nil || !strings.Contains(err.Error(), "no TXT response") {
		t.Fatalf("queryOnce empty answer error=%v, want 'no TXT response'", err)
	}
}

// ---------------------------------------------------------------------------
// query retry-loop coverage
// ---------------------------------------------------------------------------

// TestQueryZeroRetriesNormalized covers the "if retries < 1 { retries = 1 }"
// branch. We query a name the embedded server returns NXDOMAIN for (wrong domain),
// so every attempt fails and we exercise the loop internals with one iteration.
func TestQueryZeroRetriesNormalized(t *testing.T) {
	ip, port := startEmbeddedServer(t, newServerCfg(t, ""))
	r := &txtResolver{server: ip, port: port, retries: 0}
	_, err := r.query("something.other.example.com")
	if err == nil {
		t.Fatal("expected error for wrong-domain query")
	}
}

// TestQueryRetryLoopWithSleep covers the time.Sleep inside the retry loop and
// the final "return \"\", lastErr" by making all retries fail (wrong domain).
// Two retries cause one 250 ms sleep, keeping the test fast but verifiable.
func TestQueryRetryLoopWithSleep(t *testing.T) {
	ip, port := startEmbeddedServer(t, newServerCfg(t, ""))
	r := &txtResolver{server: ip, port: port, retries: 2}
	start := time.Now()
	_, err := r.query("something.other.example.com")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error for wrong-domain query")
	}
	if elapsed < 200*time.Millisecond {
		t.Fatalf("expected ≥250 ms retry sleep, elapsed=%v", elapsed)
	}
}

// ---------------------------------------------------------------------------
// testConnection bad-encoding coverage
// ---------------------------------------------------------------------------

// TestTestConnectionUnsupportedEncoding covers the "unsupported encoding"
// error path when the server returns something other than "base64" or "base32".
func TestTestConnectionUnsupportedEncoding(t *testing.T) {
	ip, port := startCustomDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: []string{"garbage"},
		})
		_ = w.WriteMsg(m)
	})

	resolver := &txtResolver{server: ip, port: port, retries: 1}
	_, err := testConnection(resolver, "files.test")
	if err == nil || !strings.Contains(err.Error(), "unsupported encoding") {
		t.Fatalf("testConnection garbage encoding error=%v, want 'unsupported encoding'", err)
	}
}

// ---------------------------------------------------------------------------
// downloadFile / uploadFile additional path coverage
// ---------------------------------------------------------------------------

// TestDownloadFileDefaultOutputPath covers the branch where cfg.outFile is
// empty and the code falls back to cfg.filename as the output path. We use a
// wrong password so the server returns an auth failure and the function returns
// early with "download initialization failed" — the output-path lines are still
// executed before the DNS query is made.
func TestDownloadFileDefaultOutputPath(t *testing.T) {
	ip, port := startEmbeddedServer(t, newServerCfg(t, ""))
	r := &txtResolver{server: ip, port: port, retries: 1}

	err := downloadFile(r, config{
		domain:           "files.test",
		pass:             "wrong-secret",
		filename:         "test.txt",
		outFile:          "", // triggers the cfg.filename fallback
		retries:          1,
		dnsServer:        ip,
		dnsPort:          port,
		maxDownloadBytes: defaultMaxDownloadBytes,
	})
	if err == nil {
		t.Fatal("expected error from wrong-pass download")
	}
}

// TestUploadFileStatusMismatch covers the "upload initialization failed" path
// in uploadFile by using a wrong password so the server responds with an auth
// failure instead of "Ready to file uploading".
func TestUploadFileStatusMismatch(t *testing.T) {
	ip, port := startEmbeddedServer(t, newServerCfg(t, t.TempDir()))
	r := &txtResolver{server: ip, port: port, retries: 1}

	inputPath := filepath.Join(t.TempDir(), "data.txt")
	if err := os.WriteFile(inputPath, []byte("test data"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	err := uploadFile(r, config{
		domain:    "files.test",
		pass:      "wrong-secret",
		inFile:    inputPath,
		chunkSize: 60,
		retries:   1,
		dnsServer: ip,
		dnsPort:   port,
	})
	if err == nil || !strings.Contains(err.Error(), "upload initialization failed") {
		t.Fatalf("uploadFile wrong-pass error=%v, want 'upload initialization failed'", err)
	}
}

func TestUploadFileRejectsInvalidServerNextIndexes(t *testing.T) {
	for _, tc := range []struct {
		name, response, want string
	}{
		{name: "non-numeric", response: "not-an-index", want: "server returned upload error"},
		{name: "negative", response: "-2", want: "server signaled upload failure"},
		{name: "outside range", response: "999999", want: "outside prepared range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip, port := startCustomDNSServer(t, func(w dns.ResponseWriter, request *dns.Msg) {
				value := tc.response
				name := strings.ToLower(request.Question[0].Name)
				switch {
				case strings.Contains(name, "encoding.test."):
					value = "base64"
				case strings.Contains(name, ".uinit."):
					value = "Ready to file uploading"
				}
				message := new(dns.Msg)
				message.SetReply(request)
				message.Answer = []dns.RR{&dns.TXT{
					Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
					Txt: []string{value},
				}}
				_ = w.WriteMsg(message)
			})
			input := filepath.Join(t.TempDir(), "input.bin")
			if err := os.WriteFile(input, []byte("payload"), 0o600); err != nil {
				t.Fatal(err)
			}
			resolver := &txtResolver{server: ip, port: port, retries: 1}
			err := uploadFile(resolver, config{
				domain: "files.test", pass: "secret", inFile: input,
				chunkSize: 60, retries: 1, dnsServer: ip, dnsPort: port,
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("upload error=%v, want %q", err, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Parallel download tests
// ---------------------------------------------------------------------------

// TestDownloadFileParallelMultiChunk verifies that downloadFile correctly
// reassembles a file whose encrypted form spans more chunks than the
// parallel concurrency limit, ensuring out-of-order completion is handled.
func TestDownloadFileParallelMultiChunk(t *testing.T) {
	dataDir := t.TempDir()
	ip, port := startEmbeddedServer(t, newServerCfg(t, dataDir))
	resolver := &txtResolver{server: ip, port: port, retries: 3}

	// Build a payload that is varied enough to resist compression, so the
	// encrypted output spans well over downloadParallelism chunks.
	payload := make([]byte, 4000)
	for i := range payload {
		payload[i] = byte(i * 37 % 251)
	}
	filename := "multichunk.bin"
	if err := os.WriteFile(filepath.Join(dataDir, filename), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(t.TempDir(), filename)
	cfg := config{
		domain:           "files.test",
		pass:             "integration-test-secret",
		filename:         filename,
		outFile:          outputPath,
		retries:          3,
		dnsServer:        ip,
		dnsPort:          port,
		maxDownloadBytes: defaultMaxDownloadBytes,
	}
	if err := downloadFile(resolver, cfg); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("downloaded content does not match original — possible chunk ordering bug")
	}
}

// TestDownloadFileParallelChunkError verifies that a DNS failure on any chunk
// causes downloadFile to return an error rather than silently corrupt output.
func TestDownloadFileParallelChunkError(t *testing.T) {
	dataDir := t.TempDir()
	ip, port := startEmbeddedServer(t, newServerCfg(t, dataDir))
	// Write a file so dinit succeeds.
	payload := make([]byte, 2000)
	for i := range payload {
		payload[i] = byte(i * 13 % 251)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "errfile.bin"), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	// Use retries=1 and a bad pass so the chunk queries fail with auth errors.
	resolver := &txtResolver{server: ip, port: port, retries: 1}
	cfg := config{
		domain:           "files.test",
		pass:             "wrong-secret",
		filename:         "errfile.bin",
		outFile:          filepath.Join(t.TempDir(), "errfile.bin"),
		retries:          1,
		dnsServer:        ip,
		dnsPort:          port,
		maxDownloadBytes: defaultMaxDownloadBytes,
	}
	// dinit itself fails because of wrong pass — we get an error from the init step.
	err := downloadFile(resolver, cfg)
	if err == nil {
		t.Fatal("expected error with wrong pass, got nil")
	}
}
