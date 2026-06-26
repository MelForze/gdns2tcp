package dnsserver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gdns2tcp/internal/codec"
	secure "gdns2tcp/internal/crypto"
	"gdns2tcp/internal/protocol"
	gproxy "gdns2tcp/internal/proxy"

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

// sessionAreadArgs builds the [cid, nonce, ("x-tcp")?, smac] args slice that
// proxyAgentRead expects after the session-MAC cutover. The MAC is keyed
// by (cmd, nonce) so each request is replay-protected by the server's
// per-cid sliding window.
func sessionAreadArgs(cid string, key [32]byte, nonce uint64, tcp bool) []string {
	args := []string{cid, strconv.FormatUint(nonce, 16)}
	if tcp {
		args = append(args, gproxy.AxchgTCPMarker)
	}
	return append(args, protocol.SessionMAC(key, "aread", nonce))
}

// sessionAwriteArgs builds the awrite args slice. The MAC binds to (awrite,
// seq); seq doubles as the per-cid awrite ordering key.
func sessionAwriteArgs(cid string, key [32]byte, seq uint64, dataLabels []string) []string {
	args := make([]string, 0, 3+len(dataLabels))
	args = append(args, cid, strconv.FormatUint(seq, 16))
	args = append(args, dataLabels...)
	return append(args, protocol.SessionMAC(key, "awrite", seq))
}

func sessionAcloseArgs(cid string, key [32]byte, nonce uint64) []string {
	return []string{
		cid,
		strconv.FormatUint(nonce, 16),
		protocol.SessionMAC(key, "aclose", nonce),
	}
}

func sessionAreadName(cid string, key [32]byte, nonce uint64, tcp bool) string {
	return protocol.JoinName(testDomain, "aread", sessionAreadArgs(cid, key, nonce, tcp))
}

func sessionAwriteName(cid string, key [32]byte, seq uint64, dataLabels []string) string {
	return protocol.JoinName(testDomain, "awrite", sessionAwriteArgs(cid, key, seq, dataLabels))
}

func sessionAcloseName(cid string, key [32]byte, nonce uint64) string {
	return protocol.JoinName(testDomain, "aclose", sessionAcloseArgs(cid, key, nonce))
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

func fetchDownloadMeta(t *testing.T, s *Server, sid string) (int, string) {
	t.Helper()
	resp := s.handleTXT(signedName("dmeta", []string{sid}), "127.0.0.1")
	if len(resp) != 1 {
		t.Fatalf("dmeta %s: %v", sid, resp)
	}
	parts := strings.Split(resp[0], "|")
	if len(parts) != 2 {
		t.Fatalf("dmeta malformed: %q", resp[0])
	}
	count, err := strconv.Atoi(parts[0])
	if err != nil || count <= 0 {
		t.Fatalf("dmeta count=%q", parts[0])
	}
	return count, parts[1]
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

func TestDownloadCacheContentInvalidationWithSameMtime(t *testing.T) {
	s := newTestServer(t)
	filename := "hash-test.txt"
	path := filepath.Join(s.dataDir, filename)
	fixed := time.Unix(1_700_000_000, 0)
	originalData := []byte("payload-version-0001")
	updatedData := []byte("payload-version-0002")
	if len(originalData) != len(updatedData) {
		t.Fatal("test payloads must have identical sizes")
	}
	if err := os.WriteFile(path, originalData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	key := cacheKey(t, s, filename)

	startDownload(t, s, "hashsid01", filename)
	s.mu.Lock()
	firstDigest := s.downloadCache[key].sha256
	firstMtime := s.downloadCache[key].mtime
	s.mu.Unlock()

	if err := os.WriteFile(path, updatedData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, fixed, fixed); err != nil {
		t.Fatal(err)
	}

	count := startDownload(t, s, "hashsid02", filename)
	s.mu.Lock()
	secondDigest := s.downloadCache[key].sha256
	secondMtime := s.downloadCache[key].mtime
	s.mu.Unlock()

	if !firstMtime.Equal(secondMtime) {
		t.Fatalf("test setup failed: mtimes differ: %v vs %v", firstMtime, secondMtime)
	}
	if firstDigest == secondDigest {
		t.Fatal("cache digest unchanged after same-size same-mtime content modification")
	}
	var b strings.Builder
	for i := 0; i < count; i++ {
		b.WriteString(fetchDownloadChunk(t, s, "hashsid02", i))
	}
	if got := openDownloadedPayload(t, b.String()); !bytes.Equal(got, updatedData) {
		t.Fatalf("got %q after same-mtime content change, want %q", got, updatedData)
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

func fetchDownloadBatch(t *testing.T, s *Server, sid string, from, count int) []string {
	t.Helper()
	return s.handleTXT(signedName("db", []string{sid, strconv.Itoa(from), strconv.Itoa(count)}), "127.0.0.1")
}

// TestDownloadBatchEqualsPerChunk verifies that the batched `db` endpoint
// returns exactly the same chunks (in order) as repeated single-chunk `d`
// queries would, both for an interior batch and for the last partial batch.
func TestDownloadBatchEqualsPerChunk(t *testing.T) {
	s := newTestServer(t)
	filename := "batched.bin"
	// 16 KB of incompressible random bytes → ~75 base64 chunks of 254 bytes.
	payload := make([]byte, 16*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dataDir, filename), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	count := startDownload(t, s, "batchsid-aaaa", filename)
	if count < 10 {
		t.Skipf("payload produced only %d chunks; test needs ≥ 10 to be meaningful", count)
	}

	// Interior batch of size 7 starting at index 3.
	from, batchSize := 3, 7
	batch := fetchDownloadBatch(t, s, "batchsid-aaaa", from, batchSize)
	if len(batch) != batchSize {
		t.Fatalf("interior batch returned %d strings, want %d", len(batch), batchSize)
	}
	for i := 0; i < batchSize; i++ {
		got := fetchDownloadChunk(t, s, "batchsid-aaaa", from+i)
		if batch[i] != got {
			t.Fatalf("chunk %d: batch=%q want %q", from+i, batch[i], got)
		}
	}

	// Last partial batch — request more than available, server should clamp.
	tail := fetchDownloadBatch(t, s, "batchsid-aaaa", count-3, 16)
	if len(tail) != 3 {
		t.Fatalf("partial batch returned %d strings, want 3", len(tail))
	}
	for i := 0; i < 3; i++ {
		got := fetchDownloadChunk(t, s, "batchsid-aaaa", count-3+i)
		if tail[i] != got {
			t.Fatalf("tail chunk %d: batch=%q want %q", count-3+i, tail[i], got)
		}
	}
}

func TestDownloadMetaReturnsSourceDigest(t *testing.T) {
	s := newTestServer(t)
	const filename = "meta.bin"
	payload := []byte("download metadata source bytes")
	if err := os.WriteFile(filepath.Join(s.dataDir, filename), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	sid := "metasid-aaaa"
	count := startDownload(t, s, sid, filename)
	metaCount, digest := fetchDownloadMeta(t, s, sid)
	if metaCount != count {
		t.Fatalf("dmeta count=%d want %d", metaCount, count)
	}
	sum := sha256.Sum256(payload)
	if digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("dmeta digest=%q want %x", digest, sum)
	}
}

// TestDownloadBatchAuthFail rejects unsigned db queries.
func TestDownloadBatchAuthFail(t *testing.T) {
	s := newTestServer(t)
	unsignedName := protocol.JoinName(testDomain, "db", []string{"batchsid-aaaa", "0", "8"})
	got := s.handleTXT(unsignedName, "127.0.0.1")
	if len(got) != 1 || got[0] != authFailedResponse {
		t.Fatalf("expected authFailedResponse, got %v", got)
	}
}

// TestDownloadBatchOutOfRange rejects from >= chunk count.
func TestDownloadBatchOutOfRange(t *testing.T) {
	s := newTestServer(t)
	filename := "small.bin"
	if err := os.WriteFile(filepath.Join(s.dataDir, filename), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	count := startDownload(t, s, "rangesid-bbbb", filename)
	got := fetchDownloadBatch(t, s, "rangesid-bbbb", count, 4)
	if len(got) != 1 || got[0] != "Wrong chunk number." {
		t.Fatalf("expected wrong-chunk-number response, got %v", got)
	}
}

// newClientArtifactServer prepares a server with a >32 KB random-bytes client
// artifact so the bootstrap chunking has enough chunks to exercise batching.
func newClientArtifactServer(t *testing.T) (*Server, int) {
	t.Helper()
	clientPath := filepath.Join(t.TempDir(), "gdns2tcp-client.ps1")
	payload := make([]byte, 32*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, func(cfg *Config) {
		cfg.ClientArtifacts = []ClientArtifactConfig{{Alias: "win", Path: clientPath, Required: true}}
	})
	chunks := len(s.clientArtifacts["win"].chunks)
	if chunks < 20 {
		t.Fatalf("artifact only produced %d chunks; bump payload size", chunks)
	}
	return s, chunks
}

// TestClientBatchEqualsPerChunk: clb-<alias> returns the same chunks (in
// order) as a sequence of cl-<alias> queries — for both an interior batch and
// the last partial batch at the end of the artifact. The first character
// string is the per-batch SHA-256 digest of the concatenated chunks; the
// bootstrap script uses it to verify each batch before accepting it.
func TestClientBatchEqualsPerChunk(t *testing.T) {
	s, total := newClientArtifactServer(t)

	from, batchSize := 4, 9
	batch := s.clientBatch("win", []string{strconv.Itoa(from), strconv.Itoa(batchSize)}, "127.0.0.1")
	if len(batch) != batchSize+1 {
		t.Fatalf("interior batch returned %d strings, want %d (sha + %d chunks)", len(batch), batchSize+1, batchSize)
	}
	if !strings.HasPrefix(batch[0], "s:") {
		t.Fatalf("interior batch missing s:<sha> prefix; got %q", batch[0])
	}
	expectedSum := sha256.Sum256([]byte(strings.Join(batch[1:], "")))
	if batch[0] != "s:"+hex.EncodeToString(expectedSum[:]) {
		t.Fatalf("interior batch sha mismatch: got %q, want s:%x", batch[0], expectedSum)
	}
	for i := 0; i < batchSize; i++ {
		got := s.clientChunk("win", []string{strconv.Itoa(from + i)}, "127.0.0.1")
		if len(got) != 1 || got[0] != batch[i+1] {
			t.Fatalf("chunk %d: batch=%q want %q", from+i, batch[i+1], got)
		}
	}

	tail := s.clientBatch("win", []string{strconv.Itoa(total - 3), "16"}, "127.0.0.1")
	if len(tail) != 4 {
		t.Fatalf("partial batch returned %d strings, want 4 (sha + 3 chunks)", len(tail))
	}
	if !strings.HasPrefix(tail[0], "s:") {
		t.Fatalf("tail batch missing s:<sha> prefix; got %q", tail[0])
	}
	tailSum := sha256.Sum256([]byte(strings.Join(tail[1:], "")))
	if tail[0] != "s:"+hex.EncodeToString(tailSum[:]) {
		t.Fatalf("tail batch sha mismatch: got %q, want s:%x", tail[0], tailSum)
	}
	for i := 0; i < 3; i++ {
		got := s.clientChunk("win", []string{strconv.Itoa(total - 3 + i)}, "127.0.0.1")
		if len(got) != 1 || got[0] != tail[i+1] {
			t.Fatalf("tail chunk %d: batch=%q want %q", total-3+i, tail[i+1], got)
		}
	}
}

// TestClientBatchMissingArgs and TestClientBatchOutOfRange cover the two
// distinct error paths in clientBatch validation.
func TestClientBatchMissingArgs(t *testing.T) {
	s, _ := newClientArtifactServer(t)
	got := s.clientBatch("win", []string{"0"}, "127.0.0.1")
	if len(got) != 1 || got[0] != "Missing chunk number." {
		t.Fatalf("expected missing-chunk-number, got %v", got)
	}
}

func TestClientBatchOutOfRange(t *testing.T) {
	s, total := newClientArtifactServer(t)
	got := s.clientBatch("win", []string{strconv.Itoa(total), "4"}, "127.0.0.1")
	if len(got) != 1 || got[0] != "Incorrect chunk number." {
		t.Fatalf("expected incorrect-chunk-number, got %v", got)
	}
}

// TestClientBatchUnknownAlias verifies the artifact-not-configured response is
// returned for an unknown alias (mirrors clientChunk behaviour).
func TestClientBatchUnknownAlias(t *testing.T) {
	s, _ := newClientArtifactServer(t)
	got := s.clientBatch("nonexistent", []string{"0", "4"}, "127.0.0.1")
	if len(got) != 1 || got[0] != "Client artifact is not configured." {
		t.Fatalf("expected not-configured response, got %v", got)
	}
}

// ----- Proxy tests -----

// proxyTestServer builds a Server with AllowProxy=true and the test secret.
func proxyTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.ProxyMaxConn = 4
		cfg.ProxyBufBytes = 64 * 1024
	})
}

// echoTCPServer spins up a TCP echo server on a free port and returns its
// address. Calls t.Cleanup to close the listener.
func echoTCPServer(t *testing.T) string {
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

// TestReverseDisabledByDefault: with AllowProxy=false, all four agent endpoints
// short-circuit with the disabled message before any state lookup.
func TestReverseDisabledByDefault(t *testing.T) {
	s := newTestServer(t) // AllowProxy stays false
	for _, cmd := range []string{"apoll", "aread", "awrite", "aclose"} {
		got := s.handleTXT(signedName(cmd, []string{"0123456789abcdef"}), "127.0.0.1")
		if len(got) != 1 || got[0] != "Proxy is disabled." {
			t.Fatalf("%s should be disabled, got %v", cmd, got)
		}
	}
}

// TestReverseAgentAuthFail: requests with a bogus authenticator are rejected.
// apoll still uses per-minute HMAC; aread/awrite/aclose use the per-cid
// session MAC. A handler-level cid lookup runs before the MAC check, so we
// register a real cid first to reach the auth path on the read commands.
func TestReverseAgentAuthFail(t *testing.T) {
	s := proxyTestServer(t)

	// apoll — unsigned name has no ts/token labels, AuthToken verification
	// rejects.
	unsignedApoll := protocol.JoinName(testDomain, "apoll", []string{"0123456789abcdef"})
	if got := s.handleTXT(unsignedApoll, "127.0.0.1"); len(got) != 1 || got[0] != authFailedResponse {
		t.Fatalf("apoll unsigned should auth-fail, got %v", got)
	}

	// Register a real cid so the session-MAC-bearing commands can resolve it.
	op, _ := net.Pipe()
	t.Cleanup(func() { _ = op.Close() })
	cid, _, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}

	const badMAC = "aaaaaaaa"
	cases := []struct {
		cmd  string
		args []string
	}{
		{"aread", []string{cid, "1", badMAC}},
		{"awrite", []string{cid, "1", "deadbeef", badMAC}},
		{"aclose", []string{cid, "1", badMAC}},
	}
	for _, c := range cases {
		name := protocol.JoinName(testDomain, c.cmd, c.args)
		got := s.handleTXT(name, "127.0.0.1")
		if len(got) != 1 || got[0] != authFailedResponse {
			t.Fatalf("%s with bad MAC should auth-fail, got %v", c.cmd, got)
		}
	}
}

// TestReverseApollOnEmpty: with no pending tunnels the apoll handler returns
// EMPTY, exercising the no-state path.
func TestReverseApollOnEmpty(t *testing.T) {
	s := proxyTestServer(t)
	got := s.handleTXT(signedName("apoll", nil), "127.0.0.1")
	if len(got) != 1 || got[0] != "EMPTY" {
		t.Fatalf("expected EMPTY on idle apoll, got %v", got)
	}
}

// TestApollAuthFailLoggingClockDrift pins that an apoll with a timestamp
// outside the ±VerifyAuthWindowMinutes window logs a clock-drift diagnostic
// (with sign + direction hint), not a "wrong secret" line. This is the path
// admins hit when the VPS clock has skewed past the tolerance; an unhelpful
// "auth fail" message would send them down the "did I typo the secret?"
// rabbit hole instead of running ntpdate.
func TestApollAuthFailLoggingClockDrift(t *testing.T) {
	var logBuf syncBuf
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.Logger = log.New(&logBuf, "", 0)
	})

	// Forge an apoll with a timestamp 30 minutes in the past — well outside
	// the ±15-minute window. The MAC will be invalid (we computed it for
	// the wrong minute), but that's fine: we exercise the drift-detection
	// path which fires before the MAC compare.
	now := time.Now().UTC()
	staleTS := protocol.CurrentTimestamp(now.Add(-30 * time.Minute))
	staleToken := protocol.AuthToken(testSecret, s.authDomain, "apoll", staleTS, nil)
	got := s.handleTXT(protocol.JoinName(testDomain, "apoll", []string{staleTS, staleToken}), "203.0.113.42")
	if len(got) != 1 || got[0] != authFailedResponse {
		t.Fatalf("expected auth-fail response, got %v", got)
	}

	out := logBuf.String()
	if !strings.Contains(out, "203.0.113.42") {
		t.Fatalf("auth-fail log missing client IP: %q", out)
	}
	if !strings.Contains(out, "clock drift") {
		t.Fatalf("auth-fail log missing clock drift hint: %q", out)
	}
	if !strings.Contains(out, "ntpdate") && !strings.Contains(out, "chrony") {
		t.Fatalf("auth-fail log missing NTP fix hint: %q", out)
	}
}

// TestApollAuthFailLoggingBadSecret: timestamp inside the window but MAC
// wrong → log says "clocks are fine, check -pass" instead of clock-drift.
func TestApollAuthFailLoggingBadSecret(t *testing.T) {
	var logBuf syncBuf
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.Logger = log.New(&logBuf, "", 0)
	})

	now := time.Now().UTC()
	ts := protocol.CurrentTimestamp(now)
	wrongToken := protocol.AuthToken("WRONG_SECRET", s.authDomain, "apoll", ts, nil)
	got := s.handleTXT(protocol.JoinName(testDomain, "apoll", []string{ts, wrongToken}), "203.0.113.43")
	if len(got) != 1 || got[0] != authFailedResponse {
		t.Fatalf("expected auth-fail response, got %v", got)
	}

	out := logBuf.String()
	if !strings.Contains(out, "203.0.113.43") {
		t.Fatalf("auth-fail log missing client IP: %q", out)
	}
	if !strings.Contains(out, "clocks are fine") {
		t.Fatalf("auth-fail log should hint at -pass mismatch, got: %q", out)
	}
	if strings.Contains(out, "clock drift") {
		t.Fatalf("auth-fail log should NOT cry clock drift (timestamp is current), got: %q", out)
	}
}

// TestApollAuthFailLogRateLimit confirms repeated fails from the same IP
// produce one line per minute, not one per request. A misconfigured agent
// loops at ~1 apoll/sec; without rate-limiting that's 60 identical lines/min.
func TestApollAuthFailLogRateLimit(t *testing.T) {
	var logBuf syncBuf
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.Logger = log.New(&logBuf, "", 0)
	})

	now := time.Now().UTC()
	staleTS := protocol.CurrentTimestamp(now.Add(-30 * time.Minute))
	staleToken := protocol.AuthToken(testSecret, s.authDomain, "apoll", staleTS, nil)
	name := protocol.JoinName(testDomain, "apoll", []string{staleTS, staleToken})

	// Hit the server 10× in quick succession from the same client IP.
	for range 10 {
		_ = s.handleTXT(name, "203.0.113.99")
	}

	lines := strings.Count(logBuf.String(), "203.0.113.99")
	if lines != 1 {
		t.Fatalf("expected exactly 1 log line per IP per minute, got %d", lines)
	}
}

// TestReverseEndToEndEcho exercises the full reverse loop:
//  1. operator connects via TCP SOCKS5 to the server (with -secret as password)
//  2. server enqueues the target and replies with SOCKS5 success
//  3. test acts as the agent: polls apoll, dials the echo server, pumps bytes
//     back via awrite while pumping operator's bytes forward via aread
//  4. operator sends a payload, expects it echoed
func TestReverseEndToEndEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}

	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.ProxyMaxConn = 4
		cfg.ProxyBufBytes = 64 * 1024
	})
	upstream := echoTCPServer(t)

	// Start the server's SOCKS5 listener on a random port.
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socksLn.Close() })
	s.reverse.mu.Lock()
	s.reverse.socksLn = socksLn
	s.reverse.mu.Unlock()
	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go s.handleSOCKS5Operator(c)
		}
	}()

	// Spin up the simulated agent goroutine. It long-polls apoll, services any
	// OPEN by dialing upstream + bridging bytes via aread/awrite.
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		for {
			select {
			case <-agentDone:
				return
			default:
			}
			resp := s.handleTXT(signedName("apoll", nil), "127.0.0.1")
			if len(resp) == 0 || resp[0] == "EMPTY" {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			parts := strings.SplitN(resp[0], " ", 3)
			if len(parts) != 3 || parts[0] != "OPEN" {
				return
			}
			cid := parts[1]
			rawTarget, _ := base32.StdEncoding.WithPadding(base32.NoPadding).
				DecodeString(strings.ToUpper(parts[2]))
			sessionKey := protocol.DeriveSessionKey(testSecret, cid)
			upConn, err := net.Dial("tcp", string(rawTarget))
			if err != nil {
				_ = s.handleTXT(sessionAcloseName(cid, sessionKey, 1), "127.0.0.1")
				return
			}
			aead, _ := gproxy.SessionAEAD(testSecret, cid)
			go agentTunnelLoop(t, s, cid, sessionKey, aead, upConn)
		}
	}()

	// Operator: dial SOCKS5, authenticate, request CONNECT to the upstream.
	host, portStr, _ := net.SplitHostPort(upstream)
	upPort, _ := strconv.Atoi(portStr)
	op, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()

	// SOCKS5 user/pass handshake.
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
	auth := []byte{0x01, byte(len("gdns2tcp"))}
	auth = append(auth, []byte("gdns2tcp")...)
	auth = append(auth, byte(len(testSecret)))
	auth = append(auth, []byte(testSecret)...)
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

	// CONNECT request.
	req := []byte{0x05, 0x01, 0x00, 0x01}
	for _, b := range net.ParseIP(host).To4() {
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

	// Send a payload through the tunnel; expect it back.
	payload := []byte("hello-reverse-tunnel")
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

// agentTunnelLoop simulates an agent's per-cid pumps: aread (op→agent) drains
// into upstream TCP, and upstream→op direction is pushed via awrite.
func agentTunnelLoop(t *testing.T, s *Server, cid string, sessionKey [32]byte, aead interface{}, up net.Conn) {
	t.Helper()
	compressor, err := gproxy.GetCompressor()
	if err != nil {
		t.Errorf("GetCompressor: %v", err)
		return
	}
	var nonceCtr atomic.Uint64
	// Inbound (op→agent → upstream) pump.
	go func() {
		for {
			n := nonceCtr.Add(1)
			resp := s.handleTXT(sessionAreadName(cid, sessionKey, n, false), "127.0.0.1")
			if len(resp) == 0 {
				return
			}
			head := resp[0]
			if head == "EMPTY" || head == "WAIT" {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if head == "CLOSED" {
				_ = up.Close()
				return
			}
			if !strings.HasPrefix(head, "DATA ") {
				return
			}
			seq, _ := strconv.ParseUint(strings.TrimPrefix(head, "DATA "), 16, 64)
			b64 := strings.Join(resp[1:], "")
			ct, _ := base64.StdEncoding.DecodeString(b64)
			plaintext, err := gproxy.OpenChunk(aead.(gproxyAEAD), gproxy.DirServerToClient, seq, ct)
			if err != nil {
				return
			}
			decompressed, err := compressor.Decode(plaintext)
			if err != nil {
				return
			}
			if _, err := up.Write(decompressed); err != nil {
				return
			}
		}
	}()
	// Outbound (upstream → agent → op) pump.
	buf := make([]byte, 4096)
	var seq uint64
	for {
		n, err := up.Read(buf)
		if n > 0 {
			seq++
			ct := gproxy.SealChunk(aead.(gproxyAEAD), gproxy.DirClientToServer, seq, compressor.Encode(buf[:n]))
			enc := base32.StdEncoding.WithPadding(base32.NoPadding)
			labels := codec.ChunkString(strings.ToLower(enc.EncodeToString(ct)), 63)
			r := s.handleTXT(sessionAwriteName(cid, sessionKey, seq, labels), "127.0.0.1")
			if len(r) != 1 || r[0] != "OK" {
				return
			}
		}
		if err != nil {
			nonce := nonceCtr.Add(1)
			_ = s.handleTXT(sessionAcloseName(cid, sessionKey, nonce), "127.0.0.1")
			return
		}
	}
}

// gproxyAEAD is the cipher.AEAD subset the test pump needs. Avoiding a
// crypto/cipher import here keeps the test signal-to-noise low.
type gproxyAEAD interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, ad []byte) []byte
	Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
}

// TestReverseAwriteUnknownCid covers the early-out path in awrite.
func TestReverseAwriteUnknownCid(t *testing.T) {
	s := proxyTestServer(t)
	got := s.handleTXT(signedName("awrite", []string{"0000000000000000", "1", "aa"}), "127.0.0.1")
	if len(got) != 1 || got[0] != "ERR unknown cid" {
		t.Fatalf("expected unknown-cid, got %v", got)
	}
}

// TestReverseAcloseIdempotent: closing twice is fine.
func TestReverseAcloseIdempotent(t *testing.T) {
	s := proxyTestServer(t)
	got := s.handleTXT(signedName("aclose", []string{"0000000000000000"}), "127.0.0.1")
	if len(got) != 1 || got[0] != "OK" {
		t.Fatalf("aclose on unknown cid: %v", got)
	}
}

func TestReverseCloseFreesCapacityImmediately(t *testing.T) {
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.ProxyMaxConn = 1
		cfg.ProxyBufBytes = 64 * 1024
	})
	op1, peer1 := net.Pipe()
	t.Cleanup(func() {
		_ = op1.Close()
		_ = peer1.Close()
	})
	cid1, rc1, err := s.reverseEnqueueOpen("127.0.0.1:80", op1)
	if err != nil {
		t.Fatal(err)
	}
	opFull, peerFull := net.Pipe()
	t.Cleanup(func() {
		_ = opFull.Close()
		_ = peerFull.Close()
	})
	if _, _, err := s.reverseEnqueueOpen("127.0.0.1:81", opFull); err == nil {
		t.Fatal("expected capacity error before closing the first tunnel")
	}

	s.reverseCloseConn(cid1, rc1, "test close frees slot")

	op2, peer2 := net.Pipe()
	t.Cleanup(func() {
		_ = op2.Close()
		_ = peer2.Close()
	})
	cid2, rc2, err := s.reverseEnqueueOpen("127.0.0.1:82", op2)
	if err != nil {
		t.Fatalf("second tunnel should fit after close: %v", err)
	}
	s.reverseCloseConn(cid2, rc2, "test cleanup")
}

// TestSOCKS5ReadConnectATYPVariants verifies the parser handles IPv4, IPv6
// and domain ATYP forms equivalently.
func TestSOCKS5ReadConnectATYPVariants(t *testing.T) {
	build := func(atyp byte, addr []byte, port uint16) []byte {
		req := []byte{0x05, 0x01, 0x00, atyp}
		if atyp == 0x03 {
			req = append(req, byte(len(addr)))
		}
		req = append(req, addr...)
		req = append(req, byte(port>>8), byte(port&0xFF))
		return req
	}
	cases := []struct {
		name string
		req  []byte
		want string
	}{
		{"ipv4", build(0x01, []byte{10, 0, 0, 1}, 443), "10.0.0.1:443"},
		{"domain", build(0x03, []byte("example.com"), 80), "example.com:80"},
		{"ipv6", build(0x04, net.ParseIP("2001:db8::1").To16(), 8080), "[2001:db8::1]:8080"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, w := net.Pipe()
			go func() {
				_, _ = w.Write(c.req)
				_ = w.Close()
			}()
			got, err := socks5ReadConnect(r)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

// TestServeSOCKS5DisabledErrors when AllowProxy is off.
func TestServeSOCKS5DisabledErrors(t *testing.T) {
	s := newTestServer(t) // AllowProxy stays false
	if err := s.ServeSOCKS5("127.0.0.1:0"); err == nil {
		t.Fatal("expected error when proxy is disabled")
	}
}

// TestServeSOCKS5BadAddress surfaces the listen failure cleanly.
func TestServeSOCKS5BadAddress(t *testing.T) {
	s := proxyTestServer(t)
	if err := s.ServeSOCKS5("not-an-address"); err == nil {
		t.Fatal("expected listen error for malformed address")
	}
}

// TestServeSOCKS5FirstAcceptWatchdog: when nobody connects to the SOCKS5
// listener within the watchdog window AND the bind is non-loopback, the
// server logs a one-shot firewall-diagnostic hint.
func TestServeSOCKS5FirstAcceptWatchdog(t *testing.T) {
	window := 80 * time.Millisecond

	// Bind to 127.0.0.1:0 so we get an ephemeral port deterministically, then
	// rewrite the host to a non-loopback that maps to a real interface on the
	// test box (so the watchdog isn't suppressed by the loopback short-circuit).
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	host := pickNonLoopbackIPv4(t)
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var logBuf syncBuf
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.ProxyMaxConn = 2
		cfg.ProxyBufBytes = 4 * 1024
		cfg.ProxyWatchdogWindow = window
		cfg.Logger = log.New(&logBuf, "", 0)
	})
	// Pre-arm the agentReady channel so ServeSOCKS5 proceeds to bind.
	s.reverse.noteAgent("127.0.0.1:0")

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- s.ServeSOCKS5(addr) }()
	t.Cleanup(func() { s.proxyShutdown(); <-serveErrCh })

	// Window + slack. The watchdog logs once and returns.
	time.Sleep(window + 300*time.Millisecond)

	out := logBuf.String()
	if !strings.Contains(out, "WARNING: no SOCKS5 connections") {
		t.Fatalf("expected watchdog warning in logs, got:\n%s", out)
	}
	if !strings.Contains(out, "iptables") {
		t.Fatalf("expected firewall-hint guidance in logs, got:\n%s", out)
	}
}

// TestServeSOCKS5WatchdogSilentOnLoopback: when the bind host is 127.0.0.1
// the watchdog is suppressed (loopback can't be firewall-blocked).
func TestServeSOCKS5WatchdogSilentOnLoopback(t *testing.T) {
	window := 50 * time.Millisecond

	var logBuf syncBuf
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.ProxyMaxConn = 2
		cfg.ProxyBufBytes = 4 * 1024
		cfg.ProxyWatchdogWindow = window
		cfg.Logger = log.New(&logBuf, "", 0)
	})
	s.reverse.noteAgent("127.0.0.1:0")

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- s.ServeSOCKS5("127.0.0.1:0") }()
	t.Cleanup(func() { s.proxyShutdown(); <-serveErrCh })

	time.Sleep(window + 200*time.Millisecond)
	if strings.Contains(logBuf.String(), "WARNING: no SOCKS5 connections") {
		t.Fatalf("watchdog should be silent on loopback bind, got:\n%s", logBuf.String())
	}
}

// TestServeSOCKS5WatchdogSilentAfterAccept: once at least one Accept fires,
// the watchdog must NOT warn, even when bind is non-loopback.
func TestServeSOCKS5WatchdogSilentAfterAccept(t *testing.T) {
	window := 200 * time.Millisecond

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	host := pickNonLoopbackIPv4(t)
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var logBuf syncBuf
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.ProxyMaxConn = 2
		cfg.ProxyBufBytes = 4 * 1024
		cfg.ProxyWatchdogWindow = window
		cfg.Logger = log.New(&logBuf, "", 0)
	})
	s.reverse.noteAgent("127.0.0.1:0")

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- s.ServeSOCKS5(addr) }()
	t.Cleanup(func() { s.proxyShutdown(); <-serveErrCh })

	// Wait a tick for the listener to be up, then make a probe Accept happen.
	time.Sleep(40 * time.Millisecond)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	_ = c.Close()

	time.Sleep(window + 200*time.Millisecond)
	if strings.Contains(logBuf.String(), "WARNING: no SOCKS5 connections") {
		t.Fatalf("watchdog should not warn after Accept fired, got:\n%s", logBuf.String())
	}
}

// TestInterfaceNameForIPv4 covers the success + miss branches of the
// helper that decorates the watchdog warning with an interface name.
func TestInterfaceNameForIPv4(t *testing.T) {
	// Miss: a malformed string returns "".
	if got := interfaceNameForIPv4("not-an-ip"); got != "" {
		t.Fatalf("expected miss on bad input, got %q", got)
	}
	// Miss: an IPv6 input returns "" (To4 is nil).
	if got := interfaceNameForIPv4("::1"); got != "" {
		t.Fatalf("expected miss on IPv6 input, got %q", got)
	}
	// Miss: an IPv4 nobody is bound to.
	if got := interfaceNameForIPv4("203.0.113.42"); got != "" {
		t.Fatalf("expected miss on unbound IPv4, got %q", got)
	}
	// Success: the IP of a real non-loopback interface on this host. Skip if
	// the box has none (rare; e.g. a sandboxed CI runner).
	host := pickNonLoopbackIPv4(t)
	got := interfaceNameForIPv4(host)
	if got == "" {
		t.Fatalf("expected interface name for own IP %q, got empty", host)
	}
}

// syncBuf is a tiny mutex-wrapped writer used to capture server logs across
// goroutines without tripping -race on bytes.Buffer.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// pickNonLoopbackIPv4 finds an IPv4 bound to a non-loopback interface, or
// skips the test if none is available (e.g. an isolated CI runner).
func pickNonLoopbackIPv4(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("net.Interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil && !v4.IsLoopback() {
				return v4.String()
			}
		}
	}
	t.Skip("no non-loopback IPv4 interface available")
	return ""
}

// TestReverseCleanupExpiredLocked: backdates a cid's expires field and asks
// the GC to walk; the conn should disappear.
func TestReverseCleanupExpiredLocked(t *testing.T) {
	s := proxyTestServer(t)
	op, _ := net.Pipe()
	t.Cleanup(func() { _ = op.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	rc.mu.Lock()
	rc.expires = time.Now().Add(-time.Hour)
	rc.mu.Unlock()
	s.proxyCleanupExpiredLocked(time.Now())
	s.reverse.mu.Lock()
	_, exists := s.reverse.conns[cid]
	s.reverse.mu.Unlock()
	if exists {
		t.Fatal("cleanup left an idle-expired cid in the map")
	}
}

func TestReverseCleanupDropsExpiredPending(t *testing.T) {
	s := proxyTestServer(t)
	op, peer := net.Pipe()
	t.Cleanup(func() {
		_ = op.Close()
		_ = peer.Close()
	})
	_, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	rc.mu.Lock()
	rc.expires = time.Now().Add(-time.Hour)
	rc.mu.Unlock()

	s.proxyCleanupExpiredLocked(time.Now())

	got := s.handleTXT(signedName("apoll", nil), "127.0.0.1")
	if len(got) != 1 || got[0] != "EMPTY" {
		t.Fatalf("expired pending tunnel should not be returned by apoll, got %v", got)
	}
	s.reverse.mu.Lock()
	conns := len(s.reverse.conns)
	pending := len(s.reverse.pending)
	pendCids := len(s.reverse.pendCids)
	s.reverse.mu.Unlock()
	if conns != 0 || pending != 0 || pendCids != 0 {
		t.Fatalf("cleanup left reverse indexes populated: conns=%d pending=%d pendCids=%d", conns, pending, pendCids)
	}
}

// TestReverseSocks5AuthRejectsBadPassword exercises the user/pass auth path
// when the password mismatches.
func TestReverseSocks5AuthRejectsBadPassword(t *testing.T) {
	s := proxyTestServer(t)
	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socksLn.Close() })
	go func() {
		c, err := socksLn.Accept()
		if err != nil {
			return
		}
		s.handleSOCKS5Operator(c)
	}()

	conn, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte{0x05, 0x01, 0x02}) // user/pass method
	mr := make([]byte, 2)
	_, _ = io.ReadFull(conn, mr)
	// Submit wrong password.
	_, _ = conn.Write([]byte{0x01, byte(len("gdns2tcp"))})
	_, _ = conn.Write([]byte("gdns2tcp"))
	_, _ = conn.Write([]byte{0x05, 'w', 'r', 'o', 'n', 'g'})
	status := make([]byte, 2)
	if _, err := io.ReadFull(conn, status); err != nil {
		t.Fatal(err)
	}
	if status[1] == 0x00 {
		t.Fatal("server accepted wrong password")
	}
}

func TestSocks5NoAuthSelect(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	go func() {
		_, _ = b.Write([]byte{0x05, 0x01, 0x00})
		resp := make([]byte, 2)
		_, _ = io.ReadFull(b, resp)
	}()
	if err := socks5NoAuthSelect(a); err != nil {
		t.Fatalf("no-auth select: %v", err)
	}
}

func TestSocks5NoAuthSelectRejectsNoMethod(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	go func() {
		_, _ = b.Write([]byte{0x05, 0x01, 0x02})
		resp := make([]byte, 2)
		_, _ = io.ReadFull(b, resp)
	}()
	if err := socks5NoAuthSelect(a); err == nil {
		t.Fatal("expected error when no-auth method not offered")
	}
}

func TestSocks5NoAuthSelectBadVersion(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	go func() {
		_, _ = b.Write([]byte{0x04, 0x01, 0x00})
	}()
	if err := socks5NoAuthSelect(a); err == nil {
		t.Fatal("expected error for SOCKS4 version")
	}
}

// TestSignalOneReaderWakesExactlyOne pins the long-poll fairness fix:
// when N workers are parked on awaitReadData and operator writes a single
// chunk, exactly one worker wakes up. The rest stay parked so they don't
// fire wasted DNS round-trips. Without the fix all N would wake up,
// drain into N concurrent axchgs, and N-1 of them would see EMPTY.
func TestSignalOneReaderWakesExactlyOne(t *testing.T) {
	s := proxyTestServer(t)
	op, _ := net.Pipe()
	t.Cleanup(func() { _ = op.Close() })
	_, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.reverse.mu.Lock()
	if len(s.reverse.pending) > 0 {
		s.reverse.pending = s.reverse.pending[1:]
	}
	s.reverse.mu.Unlock()

	const N = 8
	woke := make(chan int, N)
	var wg sync.WaitGroup
	for i := range N {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Long-poll window must outlast our signal+grace period.
			if rc.awaitReadData(2 * time.Second) {
				woke <- id
			}
		}(i)
	}

	// Give the goroutines time to park.
	time.Sleep(50 * time.Millisecond)
	rc.mu.Lock()
	if got := len(rc.readWaiters); got != N {
		rc.mu.Unlock()
		t.Fatalf("expected %d parked waiters, got %d", N, got)
	}
	// Simulate "operator bytes arrived" — wake one.
	rc.signalOneReaderLocked()
	rc.mu.Unlock()

	// Exactly one wake should fire within a tight window. The remaining
	// N-1 stay parked until their individual timeout (2s above).
	select {
	case <-woke:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no worker woke after signalOneReaderLocked")
	}

	// Confirm no second wake within the window — pin the "exactly one"
	// semantics.
	select {
	case extra := <-woke:
		t.Fatalf("expected exactly one wake, second worker (id=%d) also woke", extra)
	case <-time.After(150 * time.Millisecond):
	}

	// Cleanup: close the tunnel to unblock the remaining parked workers
	// (they'll wake via closeAllReadersLocked).
	s.reverseCloseConn(s.cidForReverseConn(rc), rc, "test cleanup")
	wg.Wait()
}

// TestProxyAgentExchangePureRead covers the simplest axchg path: pure read,
// no write. The server should return ACK 0 + EMPTY.
func TestProxyAgentExchangePureRead(t *testing.T) {
	s := proxyTestServer(t)
	op, _ := net.Pipe()
	t.Cleanup(func() { _ = op.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.reverse.mu.Lock()
	if len(s.reverse.pending) > 0 {
		s.reverse.pending = s.reverse.pending[1:]
	}
	s.reverse.mu.Unlock()

	nonce := uint64(1)
	smac := protocol.SessionMAC(rc.sessionKey, "axchg", nonce)
	args := []string{cid, "0", strconv.FormatUint(nonce, 16), smac}
	resp := s.proxyAgentExchange(args, time.Now().UTC())
	if len(resp) < 2 || resp[0] != "ACK 0" || resp[1] != "EMPTY" { // 0 is "0" in both bases
		t.Fatalf("expected [ACK 0, EMPTY], got %v", resp)
	}
}

// TestProxyAgentExchangeWriteAndRead exercises the full duplex code path:
// one chunk going upstream→operator, one chunk coming op→upstream. Both
// directions must complete in a single DNS round-trip's worth of args.
func TestProxyAgentExchangeWriteAndRead(t *testing.T) {
	s := proxyTestServer(t)
	op, opRemote := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = opRemote.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.reverse.mu.Lock()
	if len(s.reverse.pending) > 0 {
		s.reverse.pending = s.reverse.pending[1:]
	}
	s.reverse.mu.Unlock()

	// Seed op→agent buffer so the read side has something to return.
	rc.mu.Lock()
	rc.opToAgent.Write([]byte("op-side-bytes"))
	rc.mu.Unlock()

	// Write-side chunk: seal "agent-bytes" as seq=1.
	seal := func(seq uint64, data []byte) string {
		ct := gproxy.SealChunk(rc.aead, gproxy.DirClientToServer, seq, rc.compressor.Encode(data))
		return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ct))
	}
	enc1 := seal(1, []byte("agent-bytes"))

	// applyAxchgWrite synchronously calls operator.Write, so the pipe reader
	// has to drain on a goroutine — otherwise proxyAgentExchange blocks
	// forever on net.Pipe's "wait for reader" semantics.
	gotCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 32)
		_ = opRemote.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := opRemote.Read(buf)
		gotCh <- string(buf[:n])
	}()

	nonce := uint64(1)
	smac := protocol.SessionMAC(rc.sessionKey, "axchg", nonce)
	args := []string{cid, "1", enc1, strconv.FormatUint(nonce, 16), smac}
	resp := s.proxyAgentExchange(args, time.Now().UTC())
	if len(resp) < 2 {
		t.Fatalf("expected at least 2 segs, got %v", resp)
	}
	if resp[0] != "ACK 1" {
		t.Fatalf("expected ACK 1, got %v", resp)
	}
	if !strings.HasPrefix(resp[1], "DATA ") {
		t.Fatalf("expected DATA, got %v", resp[1:])
	}

	if got := <-gotCh; got != "agent-bytes" {
		t.Fatalf("operator got %q want %q", got, "agent-bytes")
	}
}

func TestProxyAgentReadWAIT(t *testing.T) {
	s := proxyTestServer(t)
	op, _ := net.Pipe()
	t.Cleanup(func() { _ = op.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.reverse.mu.Lock()
	if len(s.reverse.pending) > 0 {
		s.reverse.pending = s.reverse.pending[1:]
	}
	s.reverse.mu.Unlock()

	now := time.Now().UTC()
	resp := s.proxyAgentRead(sessionAreadArgs(cid, rc.sessionKey, 1, false), now)
	if len(resp) == 0 || resp[0] != "WAIT" {
		t.Fatalf("expected WAIT, got %v", resp)
	}
}

func TestProxyAgentReadTCPHint(t *testing.T) {
	s := proxyTestServer(t)
	op, opRemote := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = opRemote.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.reverse.mu.Lock()
	if len(s.reverse.pending) > 0 {
		s.reverse.pending = s.reverse.pending[1:]
	}
	s.reverse.mu.Unlock()

	rc.mu.Lock()
	rc.opToAgent.Write(bytes.Repeat([]byte("x"), 4000))
	rc.mu.Unlock()

	now := time.Now().UTC()
	resp := s.proxyAgentRead(sessionAreadArgs(cid, rc.sessionKey, 1, true), now)
	if len(resp) < 2 || !strings.HasPrefix(resp[0], "DATA ") {
		t.Fatalf("expected DATA, got %v", resp)
	}
}

func TestProxyAgentWriteWindowedSeq(t *testing.T) {
	s := proxyTestServer(t)
	op, opRemote := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = opRemote.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.reverse.mu.Lock()
	if len(s.reverse.pending) > 0 {
		s.reverse.pending = s.reverse.pending[1:]
	}
	s.reverse.mu.Unlock()

	seal := func(seq uint64, data []byte) string {
		ct := gproxy.SealChunk(rc.aead, gproxy.DirClientToServer, seq, rc.compressor.Encode(data))
		return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ct))
	}

	now := time.Now().UTC()
	enc2 := seal(2, []byte("second"))
	resp2 := s.proxyAgentWrite(sessionAwriteArgs(cid, rc.sessionKey, 2, []string{enc2}), now)
	if resp2[0] != "OK" {
		t.Fatalf("seq 2 out-of-order: got %v", resp2)
	}

	enc1 := seal(1, []byte("first"))
	go func() {
		_ = s.proxyAgentWrite(sessionAwriteArgs(cid, rc.sessionKey, 1, []string{enc1}), now)
	}()

	buf := make([]byte, 20)
	n, _ := opRemote.Read(buf)
	got := string(buf[:n])
	if got != "first" {
		t.Fatalf("expected 'first', got %q", got)
	}
	n, _ = opRemote.Read(buf)
	got = string(buf[:n])
	if got != "second" {
		t.Fatalf("expected 'second', got %q", got)
	}
}

// TestProxyAgentWriteDuplicateSeqNoDoubleDelivery pins the dup-write race
// fix. Two concurrent awrite calls deliver the same seq with identical
// ciphertext (verbatim packet replay scenario). The operator socket must
// see the payload exactly once: the first write goes through; the second
// finds seqAgentIn already advanced under rc.mu and fast-paths to ACK
// without re-storing the chunk into oooWrite.
func TestProxyAgentWriteDuplicateSeqNoDoubleDelivery(t *testing.T) {
	s := proxyTestServer(t)
	op, opRemote := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = opRemote.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.reverse.mu.Lock()
	if len(s.reverse.pending) > 0 {
		s.reverse.pending = s.reverse.pending[1:]
	}
	s.reverse.mu.Unlock()

	// Drain operator pipe so the synchronous writev inside the handler
	// doesn't deadlock. Collect every byte that lands; we'll assert
	// length at the end.
	gotCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		_ = opRemote.SetReadDeadline(time.Now().Add(2 * time.Second))
		total := []byte{}
		for {
			n, err := opRemote.Read(buf)
			if n > 0 {
				total = append(total, buf[:n]...)
			}
			if err != nil {
				break
			}
			if len(total) >= 5 {
				// "first" is 5 bytes; give one extra read window to
				// catch any spurious duplicate.
				_ = opRemote.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			}
		}
		gotCh <- total
	}()

	enc := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(
		gproxy.SealChunk(rc.aead, gproxy.DirClientToServer, 1, rc.compressor.Encode([]byte("first"))),
	))
	args := sessionAwriteArgs(cid, rc.sessionKey, 1, []string{enc})
	now := time.Now().UTC()

	// Fire two identical awrites in parallel. With the seqAgentIn advance
	// race fixed, exactly one wins; the other sees seq <= seqAgentIn and
	// returns OK without touching the operator socket.
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			_ = s.proxyAgentWrite(args, now)
		}()
	}
	wg.Wait()

	_ = op.Close() // unblock the reader goroutine via EOF
	got := <-gotCh
	if string(got) != "first" {
		t.Fatalf("operator got %q (len=%d); expected exactly one delivery of \"first\"", string(got), len(got))
	}
}

// TestProxyAgentWriteWindowDeep exercises the OOO window with a longer
// out-of-order burst (seqs 5,4,3,2,1) to pin the post-bump awriteWindow=32
// behaviour: all five must land in order on the operator's socket once the
// head of the window arrives.
func TestProxyAgentWriteWindowDeep(t *testing.T) {
	s := proxyTestServer(t)
	op, opRemote := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = opRemote.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.reverse.mu.Lock()
	if len(s.reverse.pending) > 0 {
		s.reverse.pending = s.reverse.pending[1:]
	}
	s.reverse.mu.Unlock()

	seal := func(seq uint64, data []byte) string {
		ct := gproxy.SealChunk(rc.aead, gproxy.DirClientToServer, seq, rc.compressor.Encode(data))
		return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(ct))
	}

	now := time.Now().UTC()
	chunks := []string{"", "first", "second", "third", "fourth", "fifth"}

	// Push seq 5..2 first; each is buffered in oooWrite because seqAgentIn=0.
	for _, seq := range []uint64{5, 4, 3, 2} {
		enc := seal(seq, []byte(chunks[seq]))
		resp := s.proxyAgentWrite(sessionAwriteArgs(cid, rc.sessionKey, seq, []string{enc}), now)
		if resp[0] != "OK" {
			t.Fatalf("seq %d should be queued, got %v", seq, resp)
		}
	}

	// Submit seq 1 in the background; the handler drains all five in order.
	enc1 := seal(1, []byte(chunks[1]))
	go func() { _ = s.proxyAgentWrite(sessionAwriteArgs(cid, rc.sessionKey, 1, []string{enc1}), now) }()

	for _, want := range chunks[1:] {
		buf := make([]byte, 32)
		_ = opRemote.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := opRemote.Read(buf)
		if err != nil {
			t.Fatalf("read %q: %v", want, err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("expected %q, got %q", want, got)
		}
	}
}

// TestProxyAgentWriteWindowExhaustion: a seq past `awriteWindow + seqAgentIn`
// must be rejected with `ERR seq`. Pins the upper bound now that the window
// has grown to 32 — beyond it, the server still pushes back.
func TestProxyAgentWriteWindowExhaustion(t *testing.T) {
	s := proxyTestServer(t)
	op, _ := net.Pipe()
	t.Cleanup(func() { _ = op.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.reverse.mu.Lock()
	if len(s.reverse.pending) > 0 {
		s.reverse.pending = s.reverse.pending[1:]
	}
	s.reverse.mu.Unlock()

	// seq = window + 1 is the first illegal one: seqAgentIn is 0, the cutoff
	// is `seqAgentIn + awriteWindow` (= 512), so 513 must trip the rejection.
	overSeq := uint64(awriteWindow + 1)
	enc := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(
		gproxy.SealChunk(rc.aead, gproxy.DirClientToServer, overSeq, rc.compressor.Encode([]byte("x"))),
	))
	now := time.Now().UTC()
	resp := s.proxyAgentWrite(sessionAwriteArgs(cid, rc.sessionKey, overSeq, []string{enc}), now)
	if len(resp) != 1 || resp[0] != "ERR seq" {
		t.Fatalf("expected ERR seq for seq=%d > window, got %v", overSeq, resp)
	}
}

// TestReverseShutdown closes every live cid + the SOCKS5 listener so the
// outer process can exit cleanly.
func TestReverseShutdown(t *testing.T) {
	s := proxyTestServer(t)
	// Enqueue one tunnel directly so there is state to clean up.
	op, _ := net.Pipe()
	t.Cleanup(func() { _ = op.Close() })
	_, _, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.proxyShutdown()
	s.proxyShutdown()
	s.reverse.mu.Lock()
	defer s.reverse.mu.Unlock()
	if len(s.reverse.conns) != 0 {
		t.Fatalf("shutdown left %d conns", len(s.reverse.conns))
	}
}
