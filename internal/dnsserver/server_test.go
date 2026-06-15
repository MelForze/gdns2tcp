package dnsserver

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"gdns2tcp/internal/codec"
	secure "gdns2tcp/internal/crypto"
	"gdns2tcp/internal/protocol"

	"github.com/miekg/dns"
)

const (
	testDomain = "example.test"
	testSecret = "test-secret"
)

func newTestServer(t *testing.T, configure ...func(*Config)) *Server {
	t.Helper()
	cfg := Config{
		Domain:           testDomain,
		Secret:           testSecret,
		DataDir:          t.TempDir(),
		AllowList:        true,
		MaxUploadBytes:   DefaultMaxUploadBytes,
		MaxDownloadBytes: DefaultMaxDownloadBytes,
		Logger:           log.New(io.Discard, "", 0),
	}
	for _, fn := range configure {
		fn(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func signedName(command string, args []string) string {
	ts := protocol.CurrentTimestamp(time.Now().UTC())
	token := protocol.AuthToken(testSecret, testDomain, command, ts, args)
	labels := append([]string{}, args...)
	labels = append(labels, ts, token)
	return protocol.JoinName(testDomain, command, labels)
}

func filenameLabels(t *testing.T, name string) []string {
	t.Helper()
	labels, err := protocol.EncodeFilenameLabels(name)
	if err != nil {
		t.Fatalf("EncodeFilenameLabels(%q): %v", name, err)
	}
	return labels
}

func protectedUploadChunks(t *testing.T, data []byte, encoding string, chunkSize int) []string {
	t.Helper()
	compressed, err := codec.Compress(data)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	protected, err := secure.Protect(testSecret, compressed)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	encoded, err := codec.EncodeDNSPayload(protected, encoding)
	if err != nil {
		t.Fatalf("EncodeDNSPayload: %v", err)
	}
	if strings.EqualFold(encoding, "base32") {
		encoded = strings.ToLower(encoded)
	}
	wire := strings.NewReplacer("+", "_", "/", "-", "=", "").Replace(encoded)
	return codec.ChunkString(wire, chunkSize)
}

func startUpload(t *testing.T, s *Server, sid, filename string, chunks []string, chunkSize int, encoding string) {
	t.Helper()
	args := append([]string{sid, strconv.Itoa(len(chunks)), strconv.Itoa(chunkSize), encoding}, filenameLabels(t, filename)...)
	resp := s.handleTXT(signedName("uinit", args), "127.0.0.1")
	if len(resp) != 1 || resp[0] != "Ready to file uploading" {
		t.Fatalf("uinit %s: %v", sid, resp)
	}
}

func sendUploadChunk(t *testing.T, s *Server, sid string, index int, chunk string) string {
	t.Helper()
	args := append([]string{sid, strconv.Itoa(index)}, codec.ChunkString(chunk, 63)...)
	resp := s.handleTXT(signedName("u", args), "127.0.0.1")
	if len(resp) != 1 {
		t.Fatalf("u chunk %s/%d: %v", sid, index, resp)
	}
	return resp[0]
}

func uploadFileThroughDNS(t *testing.T, s *Server, sid, filename string, data []byte, encoding string, chunkSize int) {
	t.Helper()
	chunks := protectedUploadChunks(t, data, encoding, chunkSize)
	startUpload(t, s, sid, filename, chunks, chunkSize, encoding)
	for i, chunk := range chunks {
		want := strconv.Itoa(i + 1)
		if i == len(chunks)-1 {
			want = "-1"
		}
		if got := sendUploadChunk(t, s, sid, i, chunk); got != want {
			t.Fatalf("chunk %d response=%q, want %q", i, got, want)
		}
	}
}

func startDownload(t *testing.T, s *Server, sid, filename string) int {
	t.Helper()
	args := append([]string{sid}, filenameLabels(t, filename)...)
	resp := s.handleTXT(signedName("dinit", args), "127.0.0.1")
	if len(resp) != 1 {
		t.Fatalf("dinit %s: %v", sid, resp)
	}
	count, err := strconv.Atoi(resp[0])
	if err != nil || count <= 0 {
		t.Fatalf("dinit count=%q", resp[0])
	}
	return count
}

func fetchDownloadChunk(t *testing.T, s *Server, sid string, index int) string {
	t.Helper()
	resp := s.handleTXT(signedName("d", []string{sid, strconv.Itoa(index)}), "127.0.0.1")
	if len(resp) != 1 {
		t.Fatalf("d chunk %s/%d: %v", sid, index, resp)
	}
	return resp[0]
}

func openDownloadedPayload(t *testing.T, encoded string) []byte {
	t.Helper()
	compressed, err := secure.OpenBase64(testSecret, encoded)
	if err != nil {
		t.Fatalf("OpenBase64: %v", err)
	}
	raw, err := codec.DecompressLimit(compressed, DefaultMaxDownloadBytes)
	if err != nil {
		t.Fatalf("DecompressLimit: %v", err)
	}
	return raw
}

func readStoredFile(t *testing.T, s *Server, filename string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(s.dataDir, filename))
	if err != nil {
		t.Fatalf("read stored file %q: %v", filename, err)
	}
	return raw
}

func TestParseCommand(t *testing.T) {
	args, command, ok := parseCommand("sid.0.data.123.token.u.example.test.", "example.test.")
	if !ok {
		t.Fatal("parse failed")
	}
	if command != "u" {
		t.Fatalf("command=%q", command)
	}
	if got := strings.Join(args, ","); got != "sid,0,data,123,token" {
		t.Fatalf("args=%v", args)
	}
}

func TestHasDomainSuffixRequiresLabelBoundary(t *testing.T) {
	if !hasDomainSuffix("file.2.d.example.test.", "example.test.") {
		t.Fatal("expected valid suffix")
	}
	if hasDomainSuffix("badexample.test.", "example.test.") {
		t.Fatal("accepted suffix without label boundary")
	}
}

func TestSafePathRejectsTraversal(t *testing.T) {
	s := newTestServer(t)
	invalid := []string{"", ".", "..", "../x", "x/y", `x\y`, "bad\x00name", "bad\nname"}
	for _, name := range invalid {
		if _, _, err := s.safePathFromFilename(name); err == nil {
			t.Fatalf("safePathFromFilename(%q) succeeded", name)
		}
	}
	for _, name := range []string{"TestCase!3:256.exe.txt", "my_file.txt", "space name.txt"} {
		if _, _, err := s.safePathFromFilename(name); err != nil {
			t.Fatalf("safePathFromFilename(%q): %v", name, err)
		}
	}
}

func TestClientArtifactEndpoints(t *testing.T) {
	clientPath := filepath.Join(t.TempDir(), "gdns2tcp-client.ps1")
	if err := os.WriteFile(clientPath, []byte("client"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, func(cfg *Config) {
		cfg.ClientArtifacts = []ClientArtifactConfig{{Alias: "win", Path: clientPath, Required: true}}
	})
	manifest := s.clientManifest("win", "127.0.0.1")
	if len(manifest) != 1 || manifest[0] == "Client artifact is not configured." {
		t.Fatalf("unexpected manifest: %v", manifest)
	}
	chunk := s.clientChunk("win", []string{"0"}, "127.0.0.1")
	if len(chunk) != 1 || chunk[0] == "" {
		t.Fatalf("unexpected chunk: %v", chunk)
	}
	if got := s.clientManifest("linux-amd64", "127.0.0.1"); got[0] != "Client artifact is not configured." {
		t.Fatalf("unexpected missing artifact response: %v", got)
	}
}

func TestClientIDRemovesPort(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "192.0.2.10:53000")
	if err != nil {
		t.Fatal(err)
	}
	if got := clientID(addr); got != "192.0.2.10" {
		t.Fatalf("clientID=%q", got)
	}
}

func TestPublicTestDoesNotMutateActiveUploadEncoding(t *testing.T) {
	s := newTestServer(t)
	original := bytes.Repeat([]byte("abcdefghij"), 200)
	filename := "roundtrip.bin"
	chunks := protectedUploadChunks(t, original, "base64", 60)
	startUpload(t, s, "uploadbase64", filename, chunks, 60, "base64")

	if got := sendUploadChunk(t, s, "uploadbase64", 0, chunks[0]); got != "1" {
		t.Fatalf("first chunk response=%q", got)
	}
	resp := s.handleTXT("encoding.test.example.test.", "198.51.100.10")
	if len(resp) != 1 || resp[0] != "base32" {
		t.Fatalf("test response=%v", resp)
	}
	for i := 1; i < len(chunks); i++ {
		want := strconv.Itoa(i + 1)
		if i == len(chunks)-1 {
			want = "-1"
		}
		if got := sendUploadChunk(t, s, "uploadbase64", i, chunks[i]); got != want {
			t.Fatalf("chunk %d response=%q, want %q", i, got, want)
		}
	}
	if got := readStoredFile(t, s, filename); !bytes.Equal(got, original) {
		t.Fatalf("stored upload changed: got %d bytes, want %d", len(got), len(original))
	}
}

func TestParallelUploadsDifferentTransferIDs(t *testing.T) {
	s := newTestServer(t)
	first := []byte("first upload payload")
	second := bytes.Repeat([]byte("second upload payload "), 30)
	chunksA := protectedUploadChunks(t, first, "base64", 60)
	chunksB := protectedUploadChunks(t, second, "base32", 60)

	startUpload(t, s, "uploadone", "one.txt", chunksA, 60, "base64")
	startUpload(t, s, "uploadtwo", "two.txt", chunksB, 60, "base32")

	for i := 0; i < len(chunksA) || i < len(chunksB); i++ {
		if i < len(chunksA) {
			_ = sendUploadChunk(t, s, "uploadone", i, chunksA[i])
		}
		if i < len(chunksB) {
			_ = sendUploadChunk(t, s, "uploadtwo", i, chunksB[i])
		}
	}
	if got := readStoredFile(t, s, "one.txt"); !bytes.Equal(got, first) {
		t.Fatalf("one.txt mismatch")
	}
	if got := readStoredFile(t, s, "two.txt"); !bytes.Equal(got, second) {
		t.Fatalf("two.txt mismatch")
	}
}

func TestParallelDownloadsDifferentTransferIDs(t *testing.T) {
	s := newTestServer(t)
	first := []byte("first download payload")
	second := bytes.Repeat([]byte("second download payload "), 20)
	if err := os.WriteFile(filepath.Join(s.dataDir, "one.txt"), first, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dataDir, "two.txt"), second, 0o600); err != nil {
		t.Fatal(err)
	}

	countA := startDownload(t, s, "downloadone", "one.txt")
	countB := startDownload(t, s, "downloadtwo", "two.txt")
	var encodedA, encodedB strings.Builder
	for i := 0; i < countA || i < countB; i++ {
		if i < countA {
			encodedA.WriteString(fetchDownloadChunk(t, s, "downloadone", i))
		}
		if i < countB {
			encodedB.WriteString(fetchDownloadChunk(t, s, "downloadtwo", i))
		}
	}
	if got := openDownloadedPayload(t, encodedA.String()); !bytes.Equal(got, first) {
		t.Fatalf("first download mismatch")
	}
	if got := openDownloadedPayload(t, encodedB.String()); !bytes.Equal(got, second) {
		t.Fatalf("second download mismatch")
	}
}

func TestFilenameRoundTripSpecialNames(t *testing.T) {
	names := []string{
		"TestCase!3:256.exe.txt",
		"my_file.txt",
		"space name.txt",
		"unicode-\u041f\u0440\u0438\u0432\u0435\u0442.txt",
	}
	for i, name := range names {
		t.Run(name, func(t *testing.T) {
			if runtime.GOOS == "windows" && strings.Contains(name, ":") {
				t.Skip("colon is not a valid Windows filesystem character")
			}
			s := newTestServer(t)
			body := []byte(fmt.Sprintf("payload for %s", name))
			uploadFileThroughDNS(t, s, fmt.Sprintf("uploadsid%d", i), name, body, "base64", 70)

			if got := readStoredFile(t, s, name); !bytes.Equal(got, body) {
				t.Fatalf("stored file mismatch")
			}
			downloadSID := fmt.Sprintf("downloadsid%d", i)
			count := startDownload(t, s, downloadSID, name)
			var encoded strings.Builder
			for chunk := 0; chunk < count; chunk++ {
				encoded.WriteString(fetchDownloadChunk(t, s, downloadSID, chunk))
			}
			if got := openDownloadedPayload(t, encoded.String()); !bytes.Equal(got, body) {
				t.Fatalf("downloaded file mismatch")
			}
		})
	}
}

func TestAuthenticatedCommandsRejectMissingOrBadToken(t *testing.T) {
	s := newTestServer(t)
	if got := s.handleTXT("c.example.test.", "127.0.0.1"); got[0] != authFailedResponse {
		t.Fatalf("unauth catalog=%v", got)
	}
	labels := filenameLabels(t, "file.txt")
	if got := s.handleTXT(protocol.JoinName(testDomain, "dinit", append([]string{"downloadsid"}, labels...)), "127.0.0.1"); got[0] != authFailedResponse {
		t.Fatalf("unauth dinit=%v", got)
	}
	args := append([]string{"uploadsid", "1", "60", "base64"}, labels...)
	name := signedName("uinit", args)
	name = strings.Replace(name, ".uinit.", ".badtoken.uinit.", 1)
	if got := s.handleTXT(name, "127.0.0.1"); got[0] != authFailedResponse {
		t.Fatalf("bad auth uinit=%v", got)
	}
}

func TestExpiredUploadCleanupRemovesPartialFile(t *testing.T) {
	s := newTestServer(t)
	filename := "partial.txt"
	chunks := protectedUploadChunks(t, []byte("partial payload"), "base64", 80)
	startUpload(t, s, "expireme", filename, chunks, 80, "base64")

	path := filepath.Join(s.dataDir, filename)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("partial file missing before cleanup: %v", err)
	}
	s.mu.Lock()
	state := s.uploads["expireme"]
	state.expires = time.Now().Add(-time.Minute)
	s.uploads["expireme"] = state
	s.cleanupExpiredLocked(time.Now())
	_, exists := s.uploads["expireme"]
	s.mu.Unlock()

	if exists {
		t.Fatal("expired upload state still present")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("partial file still exists: %v", err)
	}
}

func TestUploadInitRejectsUnsafeSizes(t *testing.T) {
	s := newTestServer(t)
	args := append([]string{"hugetotal", strconv.Itoa(maxTransferChunks + 1), "60", "base64"}, filenameLabels(t, "huge.txt")...)
	if got := s.handleTXT(signedName("uinit", args), "127.0.0.1"); got[0] != "Incorrect file length format." {
		t.Fatalf("huge total response=%v", got)
	}

	s = newTestServer(t, func(cfg *Config) {
		cfg.MaxUploadBytes = 8
	})
	args = append([]string{"toobigsid", "2", "60", "base64"}, filenameLabels(t, "too-big.txt")...)
	if got := s.handleTXT(signedName("uinit", args), "127.0.0.1"); got[0] != "Upload is too large for this server policy." {
		t.Fatalf("too large response=%v", got)
	}
}

func TestDownloadMaxSize(t *testing.T) {
	s := newTestServer(t, func(cfg *Config) {
		cfg.MaxDownloadBytes = 4
	})
	if err := os.WriteFile(filepath.Join(s.dataDir, "large.txt"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"downloadlarge"}, filenameLabels(t, "large.txt")...)
	if got := s.handleTXT(signedName("dinit", args), "127.0.0.1"); got[0] != "Download is too large for this server policy." {
		t.Fatalf("download large response=%v", got)
	}
}

func TestDownloadRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	s := newTestServer(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(s.dataDir, "link.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	args := append([]string{"symlinkid"}, filenameLabels(t, "link.txt")...)
	if got := s.handleTXT(signedName("dinit", args), "127.0.0.1"); got[0] != "Invalid filename." {
		t.Fatalf("symlink escape response=%v", got)
	}
}

// mockWriter implements dns.ResponseWriter for testing.
type mockWriter struct {
	remote net.Addr
	msg    *dns.Msg
}

func (m *mockWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (m *mockWriter) RemoteAddr() net.Addr        { return m.remote }
func (m *mockWriter) WriteMsg(msg *dns.Msg) error { m.msg = msg; return nil }
func (m *mockWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockWriter) Close() error                { return nil }
func (m *mockWriter) TsigStatus() error           { return nil }
func (m *mockWriter) TsigTimersOnly(bool)         {}
func (m *mockWriter) Hijack()                     {}

func TestDomain(t *testing.T) {
	s := newTestServer(t)
	if got := s.Domain(); got != "example.test." {
		t.Fatalf("Domain()=%q, want %q", got, "example.test.")
	}
}

func TestServeDNS(t *testing.T) {
	s := newTestServer(t)
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	// No question → RcodeFormatError
	t.Run("NoQuestion", func(t *testing.T) {
		req := new(dns.Msg)
		req.Id = dns.Id()
		w := &mockWriter{remote: remote}
		s.ServeDNS(w, req)
		if w.msg == nil || w.msg.Rcode != dns.RcodeFormatError {
			t.Fatalf("expected RcodeFormatError, got %v", w.msg)
		}
	})

	// Non-TXT question → RcodeNameError
	t.Run("NonTXTQuestion", func(t *testing.T) {
		req := new(dns.Msg)
		req.Id = dns.Id()
		req.Question = []dns.Question{{Name: "example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		w := &mockWriter{remote: remote}
		s.ServeDNS(w, req)
		if w.msg == nil || w.msg.Rcode != dns.RcodeNameError {
			t.Fatalf("expected RcodeNameError, got %v", w.msg)
		}
	})

	// Wrong domain TXT → RcodeNameError
	t.Run("WrongDomainTXT", func(t *testing.T) {
		req := new(dns.Msg)
		req.Id = dns.Id()
		req.Question = []dns.Question{{Name: "encoding.test.other.domain.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}
		w := &mockWriter{remote: remote}
		s.ServeDNS(w, req)
		if w.msg == nil || w.msg.Rcode != dns.RcodeNameError {
			t.Fatalf("expected RcodeNameError, got %v", w.msg)
		}
	})

	// Valid TXT for test command → Answer contains "base64" or "base32"
	t.Run("ValidTXTTestCommand", func(t *testing.T) {
		req := new(dns.Msg)
		req.Id = dns.Id()
		req.Question = []dns.Question{{Name: "encoding.test.example.test.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}}
		w := &mockWriter{remote: remote}
		s.ServeDNS(w, req)
		if w.msg == nil || len(w.msg.Answer) == 0 {
			t.Fatal("expected answer")
		}
		txt, ok := w.msg.Answer[0].(*dns.TXT)
		if !ok || len(txt.Txt) == 0 {
			t.Fatal("expected TXT record in answer")
		}
		got := txt.Txt[0]
		if got != "base64" && got != "base32" {
			t.Fatalf("expected base64 or base32, got %q", got)
		}
	})
}

func TestHandleTXTCommandBranches(t *testing.T) {
	s := newTestServer(t)

	if got := s.handleTXT("lazy.example.test.", "127.0.0.1"); !strings.Contains(got[0], "disabled") {
		t.Fatalf("lazy: expected disabled, got %v", got)
	}
	if got := s.handleTXT("base64.example.test.", "127.0.0.1"); !strings.Contains(got[0], "disabled") {
		t.Fatalf("base64: expected disabled, got %v", got)
	}
	if got := s.handleTXT("client.example.test.", "127.0.0.1"); got[0] != "Client artifact is not configured." {
		t.Fatalf("client: %v", got)
	}
	if got := s.handleTXT("client-linux-amd64.example.test.", "127.0.0.1"); got[0] != "Client artifact is not configured." {
		t.Fatalf("client-linux-amd64: %v", got)
	}
	if got := s.handleTXT("unknown_command.example.test.", "127.0.0.1"); got[0] != "Unknown gdns2tcp command." {
		t.Fatalf("unknown_command: %v", got)
	}
}

func TestTestConnectionEncoding(t *testing.T) {
	s := newTestServer(t)

	if got := s.handleTXT("EnCoDiNg.test.example.test.", "127.0.0.1"); len(got) != 1 || got[0] != "base64" {
		t.Fatalf("mixed-case: %v", got)
	}
	if got := s.handleTXT("encoding.test.example.test.", "127.0.0.1"); len(got) != 1 || got[0] != "base32" {
		t.Fatalf("lowercase: %v", got)
	}
	if got := s.handleTXT(".test.example.test.", "127.0.0.1"); len(got) != 1 || got[0] != "Empty request. Please repeat." {
		t.Fatalf("empty arg: %v", got)
	}
}

func TestCatalogAuth(t *testing.T) {
	s := newTestServer(t)
	// No auth (just command, no token labels)
	if got := s.handleTXT("c.example.test.", "127.0.0.1"); got[0] != authFailedResponse {
		t.Fatalf("catalog no auth: %v", got)
	}
}

func TestCatalogListingDisabled(t *testing.T) {
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowList = false
	})
	if got := s.handleTXT(signedName("c", nil), "127.0.0.1"); got[0] != "Listing disabled." {
		t.Fatalf("listing disabled: %v", got)
	}
}

func TestCatalogEmpty(t *testing.T) {
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowList = true
	})
	if got := s.handleTXT(signedName("c", nil), "127.0.0.1"); got[0] != "" {
		t.Fatalf("empty catalog: %v", got)
	}
}

func TestCatalogSinglePage(t *testing.T) {
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowList = true
	})
	if err := os.WriteFile(filepath.Join(s.dataDir, "alpha.txt"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dataDir, "beta.txt"), []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := s.handleTXT(signedName("c", nil), "127.0.0.1")
	if len(got) != 1 {
		t.Fatalf("expected 1 response, got %v", got)
	}
	if !strings.Contains(got[0], ",") {
		t.Fatalf("expected comma-separated list, got %q", got[0])
	}
}

func TestCatalogPagination(t *testing.T) {
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowList = true
	})
	for i := 1; i <= 100; i++ {
		name := fmt.Sprintf("file%03d.txt", i)
		if err := os.WriteFile(filepath.Join(s.dataDir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Page 0 with no explicit page arg should return "Catalog contains N pages."
	got0 := s.handleTXT(signedName("c", nil), "127.0.0.1")
	if len(got0) != 1 || !strings.HasPrefix(got0[0], "Catalog contains ") {
		t.Fatalf("expected multi-page notice, got %v", got0)
	}
	// Requesting page 0 explicitly should return data
	got1 := s.handleTXT(signedName("c", []string{"0"}), "127.0.0.1")
	if len(got1) != 1 || got1[0] == "" {
		t.Fatalf("expected page 0 data, got %v", got1)
	}
}

func TestDownloadChunkTransferNotFound(t *testing.T) {
	s := newTestServer(t)
	if got := s.handleTXT(signedName("d", []string{"unknownsid1", "0"}), "127.0.0.1"); got[0] != "Transfer not found." {
		t.Fatalf("expected Transfer not found., got %v", got)
	}
}

func TestDownloadChunkWrongIndex(t *testing.T) {
	s := newTestServer(t)
	data := []byte("some download data")
	if err := os.WriteFile(filepath.Join(s.dataDir, "dl.txt"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sid := "downloadsid2"
	startDownload(t, s, sid, "dl.txt")
	if got := s.handleTXT(signedName("d", []string{sid, "-1"}), "127.0.0.1"); got[0] != "Wrong chunk number." {
		t.Fatalf("expected Wrong chunk number., got %v", got)
	}
}

func TestFinishUploadDecodeError(t *testing.T) {
	s := newTestServer(t)
	sid := "decodesid1"
	// 1 chunk, chunkSize 63, base64 encoding, but actual data is garbage (not valid base64)
	badChunk := "!!!notvalidbase64!!!"
	// We need a valid uinit first; bypass signedName helpers by constructing state manually.
	// Use startUpload with 1 chunk, then send bad data directly.
	args := append([]string{sid, "1", "63", "base64"}, filenameLabels(t, "decodeerr.txt")...)
	resp := s.handleTXT(signedName("uinit", args), "127.0.0.1")
	if len(resp) != 1 || resp[0] != "Ready to file uploading" {
		t.Fatalf("uinit: %v", resp)
	}
	// Send the final (only) chunk with bad content. sendUploadChunk fatals on unexpected response count,
	// so call handleTXT directly.
	chunkArgs := append([]string{sid, "0"}, codec.ChunkString(badChunk, 63)...)
	got := s.handleTXT(signedName("u", chunkArgs), "127.0.0.1")
	if len(got) != 1 || !strings.Contains(strings.ToLower(got[0]), "decode error") {
		t.Fatalf("expected decode error, got %v", got)
	}
}

func TestFinishUploadDecryptError(t *testing.T) {
	s := newTestServer(t)
	sid := "decryptsid1"
	data := bytes.Repeat([]byte("hello"), 10)
	compressed, err := codec.Compress(data)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	// Protect with wrong secret
	protected, err := secure.Protect("wrong-secret", compressed)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	encoded, err := codec.EncodeDNSPayload(protected, "base64")
	if err != nil {
		t.Fatalf("EncodeDNSPayload: %v", err)
	}
	wire := strings.NewReplacer("+", "_", "/", "-", "=", "").Replace(encoded)
	chunks := codec.ChunkString(wire, 60)

	args := append([]string{sid, strconv.Itoa(len(chunks)), "60", "base64"}, filenameLabels(t, "decrypterr.txt")...)
	resp := s.handleTXT(signedName("uinit", args), "127.0.0.1")
	if len(resp) != 1 || resp[0] != "Ready to file uploading" {
		t.Fatalf("uinit: %v", resp)
	}
	for i, chunk := range chunks {
		chunkArgs := append([]string{sid, strconv.Itoa(i)}, codec.ChunkString(chunk, 63)...)
		got := s.handleTXT(signedName("u", chunkArgs), "127.0.0.1")
		if len(got) != 1 {
			t.Fatalf("chunk %d: %v", i, got)
		}
		if i == len(chunks)-1 {
			if got[0] != "Upload decryption error." {
				t.Fatalf("expected Upload decryption error., got %q", got[0])
			}
		}
	}
}

func TestFinishUploadSizeLimit(t *testing.T) {
	// MaxUploadBytes=10 → maxWireLength=20. With chunkSize=20 the policy allows
	// at most 1 chunk ((20+19)/20 = 1). We send exactly 1 chunk whose encrypted
	// payload decompresses to 100 bytes, which exceeds the 10-byte limit.
	s := newTestServer(t, func(cfg *Config) {
		cfg.MaxUploadBytes = 10
	})
	sid := "sizelimitsid1"
	data := bytes.Repeat([]byte("x"), 100)

	// Build the wire payload manually so we can control chunk count.
	compressed, err := codec.Compress(data)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	protected, err := secure.Protect(testSecret, compressed)
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	encoded, err := codec.EncodeDNSPayload(protected, "base64")
	if err != nil {
		t.Fatalf("EncodeDNSPayload: %v", err)
	}
	wire := strings.NewReplacer("+", "_", "/", "-", "=", "").Replace(encoded)

	// Use a large chunk size so everything fits in exactly 1 chunk.
	const chunkSize = codec.TXTChunkSize
	chunks := codec.ChunkString(wire, chunkSize)
	if len(chunks) != 1 {
		// If the payload splits into more than 1 chunk at TXTChunkSize the
		// policy check in uinit (maxWireLength/chunkSize) would reject it.
		// Join into a single oversized chunk instead.
		joined := strings.Join(chunks, "")
		chunks = []string{joined}
	}

	args := append([]string{sid, "1", strconv.Itoa(len(chunks[0])), "base64"}, filenameLabels(t, "toolarge.txt")...)
	resp := s.handleTXT(signedName("uinit", args), "127.0.0.1")
	if len(resp) != 1 || resp[0] != "Ready to file uploading" {
		t.Fatalf("uinit: %v", resp)
	}

	chunkArgs := append([]string{sid, "0"}, codec.ChunkString(chunks[0], 63)...)
	got := s.handleTXT(signedName("u", chunkArgs), "127.0.0.1")
	if len(got) != 1 {
		t.Fatalf("final chunk: %v", got)
	}
	if got[0] != "Upload decompression error." && got[0] != "Upload is too large for this server policy." {
		t.Fatalf("expected size limit error, got %q", got[0])
	}
}

func TestCleanupExpiredDownload(t *testing.T) {
	s := newTestServer(t)
	data := []byte("cleanup test")
	if err := os.WriteFile(filepath.Join(s.dataDir, "cleanup.txt"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sid := "cleanupsid1"
	startDownload(t, s, sid, "cleanup.txt")

	s.mu.Lock()
	state := s.downloads[sid]
	state.expires = time.Now().Add(-time.Minute)
	s.downloads[sid] = state
	s.cleanupExpiredLocked(time.Now())
	_, exists := s.downloads[sid]
	s.mu.Unlock()

	if exists {
		t.Fatal("expired download still present after cleanup")
	}
}

func TestNewErrors(t *testing.T) {
	// Empty secret → error
	_, err := New(Config{
		Domain:  testDomain,
		Secret:  "",
		DataDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected error for empty secret")
	}

	// Nonexistent dataDir → error
	_, err = New(Config{
		Domain:  testDomain,
		Secret:  testSecret,
		DataDir: filepath.Join(t.TempDir(), "nonexistent"),
	})
	if err == nil {
		t.Fatal("expected error for nonexistent dataDir")
	}

	// dataDir is a file → error mentioning "not a directory"
	f := filepath.Join(t.TempDir(), "afile.txt")
	if err2 := os.WriteFile(f, []byte("x"), 0o600); err2 != nil {
		t.Fatal(err2)
	}
	_, err = New(Config{
		Domain:  testDomain,
		Secret:  testSecret,
		DataDir: f,
	})
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("expected 'not a directory' error, got %v", err)
	}
}

func TestSafeDouble(t *testing.T) {
	if got := safeDouble(10); got != 20 {
		t.Fatalf("safeDouble(10)=%d, want 20", got)
	}
	if got := safeDouble(math.MaxInt64); got != math.MaxInt64 {
		t.Fatalf("safeDouble(MaxInt64)=%d, want MaxInt64", got)
	}
}

func TestClientIDNilAddr(t *testing.T) {
	if got := clientID(nil); got != "unknown" {
		t.Fatalf("clientID(nil)=%q, want %q", got, "unknown")
	}
}

func TestNormalizeDomainErrors(t *testing.T) {
	if _, err := normalizeDomain(""); err == nil {
		t.Fatal("expected error for empty domain")
	}
	longLabel := strings.Repeat("a", 64)
	if _, err := normalizeDomain(longLabel + ".test"); err == nil {
		t.Fatalf("expected error for label > 63 chars")
	}
}

// ---------------------------------------------------------------------------
// New targeted tests to push coverage above 80%
// ---------------------------------------------------------------------------

func TestUploadInitInvalidChunkSize(t *testing.T) {
	s := newTestServer(t)
	// chunkSize > TXTChunkSize (254) should be rejected
	args := append([]string{"uploadsid99", "5", "999", "base64"}, filenameLabels(t, "file.txt")...)
	got := s.handleTXT(signedName("uinit", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Incorrect chunk length format." {
		t.Fatalf("expected 'Incorrect chunk length format.', got %v", got)
	}
	// chunkSize <= 0 should also be rejected
	args2 := append([]string{"uploadsid100", "5", "0", "base64"}, filenameLabels(t, "file2.txt")...)
	got2 := s.handleTXT(signedName("uinit", args2), "127.0.0.1")
	if len(got2) != 1 || got2[0] != "Incorrect chunk length format." {
		t.Fatalf("expected 'Incorrect chunk length format.' for zero chunkSize, got %v", got2)
	}
}

func TestUploadInitInvalidEncoding(t *testing.T) {
	s := newTestServer(t)
	args := append([]string{"uploadsid101", "5", "60", "rot13"}, filenameLabels(t, "file.txt")...)
	got := s.handleTXT(signedName("uinit", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Incorrect upload encoding." {
		t.Fatalf("expected 'Incorrect upload encoding.', got %v", got)
	}
}

func TestUploadInitFileAlreadyExists(t *testing.T) {
	s := newTestServer(t)
	filename := "existing.txt"
	if err := os.WriteFile(filepath.Join(s.dataDir, filename), []byte("preexisting"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"uploadsid102", "5", "60", "base64"}, filenameLabels(t, filename)...)
	got := s.handleTXT(signedName("uinit", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Error. File already exist." {
		t.Fatalf("expected 'Error. File already exist.', got %v", got)
	}
}

func TestUploadInitInvalidSID(t *testing.T) {
	s := newTestServer(t)
	// "!!bad" is not a valid SID (contains invalid chars); after ToLower it's still "!!bad"
	args := append([]string{"!!bad", "5", "60", "base64"}, filenameLabels(t, "file.txt")...)
	got := s.handleTXT(signedName("uinit", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Invalid transfer id." {
		t.Fatalf("expected 'Invalid transfer id.', got %v", got)
	}
}

func TestUploadInitDuplicateSID(t *testing.T) {
	s := newTestServer(t)
	sid := "dupuploadsid1"
	chunks := protectedUploadChunks(t, []byte("hello"), "base64", 60)
	startUpload(t, s, sid, "dup.txt", chunks, 60, "base64")

	// Second uinit with the same SID should fail
	args := append([]string{sid, "5", "60", "base64"}, filenameLabels(t, "dup2.txt")...)
	got := s.handleTXT(signedName("uinit", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Transfer already exists." {
		t.Fatalf("expected 'Transfer already exists.', got %v", got)
	}
}

func TestUploadChunkSIDNotFound(t *testing.T) {
	s := newTestServer(t)
	args := append([]string{"unknownsid99", "0"}, codec.ChunkString("somedata", 63)...)
	got := s.handleTXT(signedName("u", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Upload is not initialized." {
		t.Fatalf("expected 'Upload is not initialized.', got %v", got)
	}
}

func TestUploadChunkWrongIndex(t *testing.T) {
	s := newTestServer(t)
	sid := "wrongidxsid1"
	chunks := protectedUploadChunks(t, []byte("hello world"), "base64", 60)
	startUpload(t, s, sid, "wrongidx.txt", chunks, 60, "base64")

	// Send chunk 5 instead of 0; expect the current nextIndex (0) returned
	args := append([]string{sid, "5"}, codec.ChunkString(chunks[0], 63)...)
	got := s.handleTXT(signedName("u", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "0" {
		t.Fatalf("expected '0' (nextIndex), got %v", got)
	}
}

func TestUploadChunkTooLong(t *testing.T) {
	s := newTestServer(t)
	sid := "toolongsid1"
	// chunkSize=5, so a chunk of 6 chars should be rejected
	chunks := protectedUploadChunks(t, []byte("hi"), "base64", 5)
	startUpload(t, s, sid, "toolong.txt", chunks, 5, "base64")

	oversized := strings.Repeat("a", 6)
	args := append([]string{sid, "0"}, codec.ChunkString(oversized, 63)...)
	got := s.handleTXT(signedName("u", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Incorrect chunk length format." {
		t.Fatalf("expected 'Incorrect chunk length format.', got %v", got)
	}
}

func TestDownloadInitInvalidSID(t *testing.T) {
	s := newTestServer(t)
	args := append([]string{"!!badsid"}, filenameLabels(t, "file.txt")...)
	got := s.handleTXT(signedName("dinit", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Invalid transfer id." {
		t.Fatalf("expected 'Invalid transfer id.', got %v", got)
	}
}

func TestDownloadInitDuplicateSID(t *testing.T) {
	s := newTestServer(t)
	if err := os.WriteFile(filepath.Join(s.dataDir, "dup.txt"), []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	sid := "dupdownsid1"
	startDownload(t, s, sid, "dup.txt")

	// Second dinit with the same SID
	args := append([]string{sid}, filenameLabels(t, "dup.txt")...)
	got := s.handleTXT(signedName("dinit", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Transfer already exists." {
		t.Fatalf("expected 'Transfer already exists.', got %v", got)
	}
}

func TestDownloadInitNonExistentFile(t *testing.T) {
	s := newTestServer(t)
	args := append([]string{"downnofile1"}, filenameLabels(t, "notexist.txt")...)
	got := s.handleTXT(signedName("dinit", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Error open file." {
		t.Fatalf("expected 'Error open file.', got %v", got)
	}
}

func TestDownloadChunkAuthFail(t *testing.T) {
	s := newTestServer(t)
	// Call handleTXT with an unsigned "d" query (no auth token)
	unsignedName := protocol.JoinName(testDomain, "d", []string{"chunksid", "0"})
	got := s.handleTXT(unsignedName, "127.0.0.1")
	if len(got) != 1 || got[0] != authFailedResponse {
		t.Fatalf("expected authFailedResponse, got %v", got)
	}
}

func TestClientChunkMissingNumber(t *testing.T) {
	clientPath := filepath.Join(t.TempDir(), "gdns2tcp-client.ps1")
	if err := os.WriteFile(clientPath, []byte("client-payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, func(cfg *Config) {
		cfg.ClientArtifacts = []ClientArtifactConfig{{Alias: "win", Path: clientPath, Required: true}}
	})
	got := s.clientChunk("win", []string{}, "127.0.0.1")
	if len(got) != 1 || got[0] != "Missing chunk number." {
		t.Fatalf("expected 'Missing chunk number.', got %v", got)
	}
}

func TestClientChunkInvalidIndex(t *testing.T) {
	clientPath := filepath.Join(t.TempDir(), "gdns2tcp-client.ps1")
	if err := os.WriteFile(clientPath, []byte("client-payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, func(cfg *Config) {
		cfg.ClientArtifacts = []ClientArtifactConfig{{Alias: "win", Path: clientPath, Required: true}}
	})
	got := s.clientChunk("win", []string{"-1"}, "127.0.0.1")
	if len(got) != 1 || got[0] != "Incorrect chunk number." {
		t.Fatalf("expected 'Incorrect chunk number.', got %v", got)
	}
}

func TestResolveExistingPathWithinDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink behavior differs on Windows")
	}
	s := newTestServer(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(s.dataDir, "escape.txt")
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, err := s.resolveExistingPathWithinDataDir(linkPath)
	if err == nil {
		t.Fatal("expected error for symlink escaping data dir, got nil")
	}
}

func TestSplitAuthenticatedArgs(t *testing.T) {
	// nil args → ok=false
	if _, _, _, ok := splitAuthenticatedArgs(nil); ok {
		t.Fatal("nil args: expected ok=false")
	}
	// only one element → ok=false
	if _, _, _, ok := splitAuthenticatedArgs([]string{"only_one"}); ok {
		t.Fatal("single element: expected ok=false")
	}
	// empty token → ok=false
	if _, _, _, ok := splitAuthenticatedArgs([]string{"a", ""}); ok {
		t.Fatal("empty token: expected ok=false")
	}
	// three elements: payload=["payload"], ts="ts", token="token"
	payload, ts, token, ok := splitAuthenticatedArgs([]string{"payload", "ts", "token"})
	if !ok {
		t.Fatal("three elements: expected ok=true")
	}
	if len(payload) != 1 || payload[0] != "payload" {
		t.Fatalf("three elements: payload=%v, want [payload]", payload)
	}
	if ts != "ts" {
		t.Fatalf("three elements: ts=%q, want %q", ts, "ts")
	}
	if token != "token" {
		t.Fatalf("three elements: token=%q, want %q", token, "token")
	}
	// two elements (no payload): payload is empty, ts="ts", token="token"
	payload2, ts2, token2, ok2 := splitAuthenticatedArgs([]string{"ts", "token"})
	if !ok2 {
		t.Fatal("two elements: expected ok=true")
	}
	if len(payload2) != 0 {
		t.Fatalf("two elements: payload=%v, want empty", payload2)
	}
	if ts2 != "ts" {
		t.Fatalf("two elements: ts=%q, want %q", ts2, "ts")
	}
	if token2 != "token" {
		t.Fatalf("two elements: token=%q, want %q", token2, "token")
	}
}

func TestPrepareClientArtifactEmptyAlias(t *testing.T) {
	_, err := New(Config{
		Domain:          testDomain,
		Secret:          testSecret,
		DataDir:         t.TempDir(),
		ClientArtifacts: []ClientArtifactConfig{{Alias: "", Path: ""}},
	})
	if err == nil || !strings.Contains(err.Error(), "alias is required") {
		t.Fatalf("expected 'alias is required' error, got %v", err)
	}
}

func TestFinishUploadWriteError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file close behavior differs on Windows")
	}
	s := newTestServer(t)
	sid := "writefailsid"
	data := bytes.Repeat([]byte("abcdef"), 10)
	chunks := protectedUploadChunks(t, data, "base64", 60)
	startUpload(t, s, sid, "writefail.txt", chunks, 60, "base64")

	// Send all chunks except the last
	for i := 0; i < len(chunks)-1; i++ {
		want := strconv.Itoa(i + 1)
		if got := sendUploadChunk(t, s, sid, i, chunks[i]); got != want {
			t.Fatalf("chunk %d response=%q, want %q", i, got, want)
		}
	}

	// Close the underlying file so the Write in finishUpload fails
	s.mu.Lock()
	state := s.uploads[sid]
	state.file.Close()
	s.uploads[sid] = state
	s.mu.Unlock()

	// Send the final chunk; finishUpload will attempt Write on the closed file
	finalIdx := len(chunks) - 1
	chunkArgs := append([]string{sid, strconv.Itoa(finalIdx)}, codec.ChunkString(chunks[finalIdx], 63)...)
	got := s.handleTXT(signedName("u", chunkArgs), "127.0.0.1")
	if len(got) != 1 || got[0] != "Cannot write file." {
		t.Fatalf("expected 'Cannot write file.', got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Download cache tests
// ---------------------------------------------------------------------------

// cacheKey resolves the cache key for a file as the server stores it:
// filepath.EvalSymlinks resolves macOS /var → /private/var and similar.
func cacheKey(t *testing.T, s *Server, filename string) string {
	t.Helper()
	raw := filepath.Join(s.dataDir, filename)
	real, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", raw, err)
	}
	return real
}

func TestDownloadCacheHit(t *testing.T) {
	s := newTestServer(t)
	data := []byte("cache-hit test payload")
	filename := "cacheme.txt"
	if err := os.WriteFile(filepath.Join(s.dataDir, filename), data, 0o600); err != nil {
		t.Fatal(err)
	}
	key := cacheKey(t, s, filename)

	// First dinit — cache miss, populates entry.
	count1 := startDownload(t, s, "cachehit-sid1", filename)

	s.mu.Lock()
	_, cached := s.downloadCache[key]
	cacheSize := len(s.downloadCache)
	s.mu.Unlock()

	if !cached {
		t.Fatal("expected cache entry after first dinit")
	}
	if cacheSize != 1 {
		t.Fatalf("cache size = %d, want 1", cacheSize)
	}

	// Second dinit with a different SID — cache hit, must return same chunk count.
	count2 := startDownload(t, s, "cachehit-sid2", filename)
	if count1 != count2 {
		t.Fatalf("chunk counts differ: sid1=%d sid2=%d", count1, count2)
	}

	// Both transfers must decode to the same original content.
	var b1, b2 strings.Builder
	for i := 0; i < count1; i++ {
		b1.WriteString(fetchDownloadChunk(t, s, "cachehit-sid1", i))
		b2.WriteString(fetchDownloadChunk(t, s, "cachehit-sid2", i))
	}
	if got := openDownloadedPayload(t, b1.String()); !bytes.Equal(got, data) {
		t.Fatal("first download content mismatch")
	}
	if got := openDownloadedPayload(t, b2.String()); !bytes.Equal(got, data) {
		t.Fatal("second (cached) download content mismatch")
	}
}

func TestDownloadCacheMtimeInvalidation(t *testing.T) {
	s := newTestServer(t)
	filename := "mtime-test.txt"
	if err := os.WriteFile(filepath.Join(s.dataDir, filename), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := cacheKey(t, s, filename)

	startDownload(t, s, "mtimesid01", filename)

	s.mu.Lock()
	firstMtime := s.downloadCache[key].mtime
	s.mu.Unlock()

	// Overwrite the file and advance its mtime past filesystem resolution.
	updatedData := []byte("updated content that is different from original")
	if err := os.WriteFile(filepath.Join(s.dataDir, filename), updatedData, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(filepath.Join(s.dataDir, filename), future, future); err != nil {
		t.Fatal(err)
	}

	count2 := startDownload(t, s, "mtimesid02", filename)

	s.mu.Lock()
	secondMtime := s.downloadCache[key].mtime
	s.mu.Unlock()

	if firstMtime.Equal(secondMtime) {
		t.Fatal("cache mtime unchanged after file modification — stale entry would be served")
	}

	var b strings.Builder
	for i := 0; i < count2; i++ {
		b.WriteString(fetchDownloadChunk(t, s, "mtimesid02", i))
	}
	if got := openDownloadedPayload(t, b.String()); !bytes.Equal(got, updatedData) {
		t.Fatalf("got %q after mtime change, want %q", got, updatedData)
	}
}

func TestDownloadCacheEviction(t *testing.T) {
	s := newTestServer(t)

	// Write and initiate downloads for maxDownloadCacheEntries+1 distinct files.
	total := maxDownloadCacheEntries + 1
	firstKey := ""
	for i := 0; i < total; i++ {
		name := fmt.Sprintf("evict%02d.txt", i)
		if err := os.WriteFile(filepath.Join(s.dataDir, name), []byte(fmt.Sprintf("payload %d", i)), 0o600); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstKey = cacheKey(t, s, name)
		}
		startDownload(t, s, fmt.Sprintf("evictsid%03d", i), name)
	}

	s.mu.Lock()
	_, firstStillCached := s.downloadCache[firstKey]
	cacheSize := len(s.downloadCache)
	orderLen := len(s.downloadCacheOrder)
	s.mu.Unlock()

	if firstStillCached {
		t.Fatal("expected first file to be evicted (FIFO) when cap exceeded")
	}
	if cacheSize > maxDownloadCacheEntries {
		t.Fatalf("cache size %d exceeds cap %d", cacheSize, maxDownloadCacheEntries)
	}
	if orderLen != cacheSize {
		t.Fatalf("downloadCacheOrder length %d != cache map size %d", orderLen, cacheSize)
	}
}
