package dnsserver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	t.Cleanup(s.Shutdown)
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
		want := strconv.Itoa(i) // ack = index of accepted chunk
		if i == len(chunks)-1 {
			want = "-1" // last chunk triggers finalization
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
	if len(parts) != 2 && len(parts) != 3 {
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

func TestClientArtifactStreamsExactBase64AndDetectsChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-client.bin")
	payload := make([]byte, 2<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, func(cfg *Config) {
		cfg.ClientArtifacts = []ClientArtifactConfig{{Alias: "large", Path: path, Required: true}}
	})
	artifact := s.clientArtifacts["large"]
	if artifact.chunkCount == 0 || artifact.encodedSize != int64(base64.StdEncoding.EncodedLen(len(payload))) {
		t.Fatalf("artifact shape=%+v", artifact)
	}
	from := artifact.chunkCount / 2
	got := s.clientBatch("large", []string{strconv.Itoa(from), "11"}, "127.0.0.1")
	if len(got) != 12 {
		t.Fatalf("batch strings=%d, want 12", len(got))
	}
	encoded := base64.StdEncoding.EncodeToString(payload)
	start := from * clientChunkSize
	end := start + 11*clientChunkSize
	if end > len(encoded) {
		end = len(encoded)
	}
	if strings.Join(got[1:], "") != encoded[start:end] {
		t.Fatal("streamed artifact batch differs from legacy Base64 bytes")
	}

	changed := bytes.Repeat([]byte{0x5a}, len(payload))
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if got := s.clientManifest("large", "127.0.0.1"); got[0] != "Client artifact is not configured." {
		t.Fatalf("changed artifact manifest=%v", got)
	}
	if got := s.clientChunk("large", []string{"0"}, "127.0.0.1"); got[0] != "Client artifact is not configured." {
		t.Fatalf("changed artifact chunk=%v", got)
	}
}

func TestClientArtifactSizeLimitBeforeHashing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized-client.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(4097); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	_, err = New(Config{
		Domain: "example.test", Secret: "test-secret", DataDir: t.TempDir(),
		MaxClientArtifactBytes: 4096,
		ClientArtifacts:        []ClientArtifactConfig{{Alias: "large", Path: path, Required: true}},
	})
	if err == nil || !strings.Contains(err.Error(), "limit is 4096") {
		t.Fatalf("oversized required artifact error=%v", err)
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

	if got := sendUploadChunk(t, s, "uploadbase64", 0, chunks[0]); got != "0" {
		t.Fatalf("first chunk response=%q", got)
	}
	resp := s.handleTXT("encoding.test.example.test.", "198.51.100.10")
	if len(resp) != 1 || resp[0] != "base32" {
		t.Fatalf("test response=%v", resp)
	}
	for i := 1; i < len(chunks); i++ {
		want := strconv.Itoa(i) // ack = chunk index
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

	s.mu.Lock()
	state := s.uploads["expireme"]
	spoolPath := state.spoolPath
	if _, err := os.Stat(spoolPath); err != nil {
		s.mu.Unlock()
		t.Fatalf("partial spool missing before cleanup: %v", err)
	}
	state.expires = time.Now().Add(-time.Minute)
	s.uploads["expireme"] = state
	s.cleanupExpiredLocked(time.Now())
	_, exists := s.uploads["expireme"]
	s.mu.Unlock()

	if exists {
		t.Fatal("expired upload state still present")
	}
	if _, err := os.Stat(spoolPath); !os.IsNotExist(err) {
		t.Fatalf("partial spool still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.dataDir, filename)); !os.IsNotExist(err) {
		t.Fatalf("incomplete upload was published as final file: %v", err)
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

	// A name in the dynamic zone exists for TXT, so other types are
	// authoritative NODATA rather than NXDOMAIN. This prevents a recursive
	// resolver from negatively caching the name across record types.
	t.Run("NonTXTQuestion", func(t *testing.T) {
		req := new(dns.Msg)
		req.Id = dns.Id()
		req.Question = []dns.Question{{Name: "example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		w := &mockWriter{remote: remote}
		s.ServeDNS(w, req)
		if w.msg == nil || w.msg.Rcode != dns.RcodeSuccess || len(w.msg.Answer) != 0 {
			t.Fatalf("expected authoritative NODATA, got %v", w.msg)
		}
		if !w.msg.Authoritative {
			t.Fatal("in-zone NODATA response is missing AA")
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
		if w.msg.Authoritative {
			t.Fatal("out-of-zone NXDOMAIN must not claim authority")
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
		if !w.msg.Authoritative {
			t.Fatal("valid in-zone TXT response is missing AA")
		}
		txt, ok := w.msg.Answer[0].(*dns.TXT)
		if !ok || len(txt.Txt) == 0 {
			t.Fatal("expected TXT record in answer")
		}
		if txt.Hdr.Ttl != 0 {
			t.Fatalf("dynamic TXT TTL=%d, want 0 to prevent recursive caching", txt.Hdr.Ttl)
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
	if got := s.handleTXT("0123456789abcdef.encoding.test.example.test.", "127.0.0.1"); len(got) != 1 || got[0] != "base32" {
		t.Fatalf("cache-busted probe: %v", got)
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

// TestUploadInitReplayReturnsCompletionResult asserts that a duplicate
// `uinit` for the same sid+fingerprint issued AFTER the first pass has
// already produced a completion returns the actual finish result —
// notably a diagnostic string when finishUpload failed — rather than a
// blanket "Error. File already exist." that used to make a failed
// upload look like a successful one to the client.
//
// Regression guard for the Medium finding in the 2026-08-17 review:
// "uploadInit returns 'Error. File already exist.' instead of
// completion.result".
func TestUploadInitReplayReturnsCompletionResult(t *testing.T) {
	s := newTestServer(t)
	sid := "replaysid1"
	// Force finishUpload to fail: send garbage as the final (only) chunk so
	// codec.DecodeDNSFile bails with "Upload decode error.".
	badChunk := "!!!notvalidbase64!!!"
	filename := "replaycompletion.txt"

	initArgs := append([]string{sid, "1", "63", "base64"}, filenameLabels(t, filename)...)
	initResp := s.handleTXT(signedName("uinit", initArgs), "127.0.0.1")
	if len(initResp) != 1 || initResp[0] != "Ready to file uploading" {
		t.Fatalf("initial uinit: %v", initResp)
	}
	chunkArgs := append([]string{sid, "0"}, codec.ChunkString(badChunk, 63)...)
	chunkResp := s.handleTXT(signedName("u", chunkArgs), "127.0.0.1")
	if len(chunkResp) != 1 {
		t.Fatalf("final chunk: %v", chunkResp)
	}
	firstResult := chunkResp[0]
	if !strings.Contains(strings.ToLower(firstResult), "decode error") {
		t.Fatalf("expected first pass to record a decode error, got %q", firstResult)
	}

	// Replay uinit with the same sid+fingerprint AFTER the completion has
	// been recorded. The client-side effect of the old bug was a false
	// "File already exist." — user thinks server has the file, but it does
	// not, and no diagnostic is surfaced. Post-fix: the replay must report
	// the actual finish result so the caller can distinguish success (-1)
	// from failure diagnostics.
	replayResp := s.handleTXT(signedName("uinit", initArgs), "127.0.0.1")
	if len(replayResp) != 1 {
		t.Fatalf("replay uinit: %v", replayResp)
	}
	if replayResp[0] != firstResult {
		t.Fatalf("uinit replay returned %q; want the recorded finish result %q", replayResp[0], firstResult)
	}
	// Explicitly guard against the historical false-positive string so a
	// well-meaning refactor cannot re-introduce the same regression.
	if replayResp[0] == "Error. File already exist." {
		t.Fatalf("uinit replay returned the historical false-positive %q — must instead return the recorded completion result", replayResp[0])
	}
}

// TestUploadInitReplayAfterSuccessKeepsHistoricalMessage documents the
// wire-compat guarantee that a uinit replay after a *successful*
// completion still returns the historical "Error. File already exist."
// — the client's uinit parser only understands "Ready to file
// uploading" and treats every other string as an error, so returning
// the "-1" success sentinel from a legacy retry would confuse the
// error path.  Only FAILURE completions expose their real diagnostic
// (see TestUploadInitReplayReturnsCompletionResult).
func TestUploadInitReplayAfterSuccessKeepsHistoricalMessage(t *testing.T) {
	s := newTestServer(t)
	sid := "replaysid2"
	data := []byte("replay-success-payload")
	chunks := protectedUploadChunks(t, data, "base64", 60)
	filename := "replaysuccess.txt"

	initArgs := append([]string{sid, strconv.Itoa(len(chunks)), "60", "base64"}, filenameLabels(t, filename)...)
	if resp := s.handleTXT(signedName("uinit", initArgs), "127.0.0.1"); len(resp) != 1 || resp[0] != "Ready to file uploading" {
		t.Fatalf("uinit: %v", resp)
	}
	var lastResp string
	for i, chunk := range chunks {
		chunkArgs := append([]string{sid, strconv.Itoa(i)}, codec.ChunkString(chunk, 63)...)
		got := s.handleTXT(signedName("u", chunkArgs), "127.0.0.1")
		if len(got) != 1 {
			t.Fatalf("chunk %d: %v", i, got)
		}
		lastResp = got[0]
	}
	if lastResp != "-1" {
		t.Fatalf("expected success sentinel '-1' from final chunk, got %q", lastResp)
	}
	replay := s.handleTXT(signedName("uinit", initArgs), "127.0.0.1")
	if len(replay) != 1 || replay[0] != "Error. File already exist." {
		t.Fatalf("post-success uinit replay: got %v; want [\"Error. File already exist.\"] for client wire-compat", replay)
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
	if _, err := New(Config{Domain: strings.Repeat("a", 64) + ".test", Secret: testSecret, DataDir: t.TempDir()}); err == nil {
		t.Fatal("expected invalid domain error")
	}
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

	cacheParent := filepath.Join(t.TempDir(), "cache-parent-file")
	if err := os.WriteFile(cacheParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{
		Domain: testDomain, Secret: testSecret, DataDir: t.TempDir(),
		CacheDir: filepath.Join(cacheParent, "child"),
	})
	if err == nil || !strings.Contains(err.Error(), "create cache dir") {
		t.Fatalf("expected cache directory creation error, got %v", err)
	}

	func() {
		oldWD, chdirErr := os.Getwd()
		if chdirErr != nil {
			t.Fatal(chdirErr)
		}
		if chdirErr = os.Chdir(t.TempDir()); chdirErr != nil {
			t.Fatal(chdirErr)
		}
		defer func() { _ = os.Chdir(oldWD) }()
		s, newErr := New(Config{Domain: testDomain, Secret: testSecret, DataDir: "", CacheDir: t.TempDir()})
		if newErr != nil {
			t.Fatalf("default data directory: %v", newErr)
		}
		s.Shutdown()
	}()
}

func TestDownloadCacheReadAndEvictionErrorBranches(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	if _, err := s.readCacheChunk("missing", 0, now); err == nil {
		t.Fatal("missing cache chunk succeeded")
	}

	s.downloadCache["missing-spool"] = downloadCacheEntry{
		spoolPath: filepath.Join(t.TempDir(), "missing"), encodedSize: 1,
		chunkCount: 1, lastAccess: now, expires: now.Add(time.Hour),
	}
	s.downloadCacheOrder = []string{"missing-spool"}
	if _, err := s.readCacheChunks("missing-spool", 0, 1, now); err == nil {
		t.Fatal("missing spool read succeeded")
	}
	if _, err := s.readCacheChunks("missing-spool", -1, 1, now); err == nil {
		t.Fatal("invalid cache range succeeded")
	}

	short := filepath.Join(t.TempDir(), "short")
	if err := os.WriteFile(short, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s.downloadCache["short"] = downloadCacheEntry{
		spoolPath: short, encodedSize: 10, chunkCount: 1,
		lastAccess: now, lastMetaSave: now, expires: now.Add(time.Hour),
	}
	if _, err := s.readCacheChunk("short", 0, now); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short cache read error=%v", err)
	}
	s.releaseCacheLocked("absent")

	activePath := filepath.Join(t.TempDir(), "active")
	inactivePath := filepath.Join(t.TempDir(), "inactive")
	_ = os.WriteFile(activePath, []byte("a"), 0o600)
	_ = os.WriteFile(inactivePath, []byte("b"), 0o600)
	s.downloadCache = map[string]downloadCacheEntry{
		"active":   {spoolPath: activePath, encodedSize: 10, active: 1, expires: now.Add(time.Hour)},
		"inactive": {spoolPath: inactivePath, encodedSize: 10, expires: now.Add(time.Hour)},
	}
	s.downloadCacheOrder = []string{"stale-order-key", "active", "inactive"}
	s.downloadCacheBytes = 20
	s.cacheMaxBytes = 1
	s.evictDownloadCacheLocked(now)
	if _, ok := s.downloadCache["inactive"]; ok {
		t.Fatal("inactive cache entry was not evicted")
	}
	if _, ok := s.downloadCache["active"]; !ok {
		t.Fatal("active cache entry was evicted")
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
		t.Fatalf("expected conflicting uinit to be rejected, got %v", got)
	}
}

func TestUploadFinalChunkTombstoneIsIdempotent(t *testing.T) {
	s := newTestServer(t)
	sid := "uploadtombstone1"
	data := []byte("a completed final chunk may be retried after a lost DNS reply")
	chunks := protectedUploadChunks(t, data, "base64", 60)
	startUpload(t, s, sid, "tombstone.txt", chunks, 60, "base64")
	for index := 0; index < len(chunks)-1; index++ {
		if got := sendUploadChunk(t, s, sid, index, chunks[index]); got != strconv.Itoa(index) {
			t.Fatalf("chunk %d response=%q", index, got)
		}
	}
	finalIndex := len(chunks) - 1
	if got := sendUploadChunk(t, s, sid, finalIndex, chunks[finalIndex]); got != "-1" {
		t.Fatalf("first final chunk response=%q", got)
	}
	if got := sendUploadChunk(t, s, sid, finalIndex, chunks[finalIndex]); got != "-1" {
		t.Fatalf("duplicate final chunk response=%q, want -1", got)
	}
	stored, err := os.ReadFile(filepath.Join(s.dataDir, "tombstone.txt"))
	if err != nil || !bytes.Equal(stored, data) {
		t.Fatalf("published upload changed after duplicate final chunk: %q, %v", stored, err)
	}
	sameInit := append([]string{sid, strconv.Itoa(len(chunks)), "60", "base64"}, filenameLabels(t, "tombstone.txt")...)
	if got := s.handleTXT(signedName("uinit", sameInit), "127.0.0.1"); got[0] != "Error. File already exist." {
		t.Fatalf("completed same-fingerprint uinit=%v", got)
	}
	conflictInit := append([]string{sid, strconv.Itoa(len(chunks)), "60", "base64"}, filenameLabels(t, "other.txt")...)
	if got := s.handleTXT(signedName("uinit", conflictInit), "127.0.0.1"); got[0] != "Transfer already exists." {
		t.Fatalf("completed conflicting uinit=%v", got)
	}
}

func TestUploadConcurrentFinalChunksShareCompletion(t *testing.T) {
	s := newTestServer(t)
	sid := "parallelfinal01"
	data := []byte("parallel final chunk completion")
	chunks := protectedUploadChunks(t, data, "base64", 60)
	startUpload(t, s, sid, "parallel-final.txt", chunks, 60, "base64")
	for index := 0; index < len(chunks)-1; index++ {
		if got := sendUploadChunk(t, s, sid, index, chunks[index]); got != strconv.Itoa(index) {
			t.Fatalf("chunk %d response=%q", index, got)
		}
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var hookOnce sync.Once
	s.finishUploadHook = func() {
		hookOnce.Do(func() { close(entered) })
		<-release
	}
	final := len(chunks) - 1
	results := make(chan string, 2)
	go func() { results <- sendUploadChunk(t, s, sid, final, chunks[final]) }()
	<-entered
	go func() { results <- sendUploadChunk(t, s, sid, final, chunks[final]) }()
	close(release)
	first, second := <-results, <-results
	if first != "-1" || second != "-1" {
		t.Fatalf("parallel final responses=(%q,%q), want identical success", first, second)
	}
	stored, err := os.ReadFile(filepath.Join(s.dataDir, "parallel-final.txt"))
	if err != nil || !bytes.Equal(stored, data) {
		t.Fatalf("published data=%q, err=%v", stored, err)
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

func TestUploadChunkOutOfOrderAccepted(t *testing.T) {
	s := newTestServer(t)
	sid := "outofordersid"
	data := []byte("out of order upload works")
	chunks := protectedUploadChunks(t, data, "base64", 60)
	if len(chunks) < 2 {
		t.Skip("need at least 2 chunks")
	}
	startUpload(t, s, sid, "outoforder.txt", chunks, 60, "base64")

	// Send chunk 1 before chunk 0 — server buffers it.
	if got := sendUploadChunk(t, s, sid, 1, chunks[1]); got != "1" {
		t.Fatalf("out-of-order chunk 1 response=%q, want ack \"1\"", got)
	}
	// Now send chunk 0 — server flushes both (0 then 1).
	// If there are only 2 chunks, this completes the upload.
	for i := 0; i < len(chunks); i++ {
		if i == 1 {
			continue // already sent
		}
		got := sendUploadChunk(t, s, sid, i, chunks[i])
		if i == len(chunks)-1 {
			if got != "-1" {
				t.Fatalf("final chunk %d response=%q, want \"-1\"", i, got)
			}
		} else {
			if got != strconv.Itoa(i) {
				t.Fatalf("chunk %d response=%q, want %q", i, got, strconv.Itoa(i))
			}
		}
	}
	if stored := readStoredFile(t, s, "outoforder.txt"); !bytes.Equal(stored, data) {
		t.Fatalf("stored data mismatch")
	}
}

func TestUploadChunkOutOfRangeRejected(t *testing.T) {
	s := newTestServer(t)
	sid := "outofrangesid"
	chunks := protectedUploadChunks(t, []byte("hello world"), "base64", 60)
	startUpload(t, s, sid, "outofrange.txt", chunks, 60, "base64")

	// Index beyond total — rejected.
	args := append([]string{sid, "999"}, codec.ChunkString(chunks[0], 63)...)
	got := s.handleTXT(signedName("u", args), "127.0.0.1")
	if len(got) != 1 || got[0] != "Wrong chunk number." {
		t.Fatalf("expected 'Wrong chunk number.', got %v", got)
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
	if len(got) != 1 || got[0] != "1" {
		t.Fatalf("expected idempotent dinit count, got %v", got)
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

func TestPrepareClientArtifactOptionalAndValidationBranches(t *testing.T) {
	s := newTestServer(t, func(cfg *Config) { cfg.MaxClientArtifactBytes = 4 })
	if err := s.prepareClientArtifact(ClientArtifactConfig{Alias: "bad.alias", Path: "ignored"}); err == nil {
		t.Fatal("artifact alias containing a dot was accepted")
	}
	if err := s.prepareClientArtifact(ClientArtifactConfig{Alias: "unused", Path: ""}); err != nil {
		t.Fatalf("empty optional artifact path: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if err := s.prepareClientArtifact(ClientArtifactConfig{Alias: "optional", Path: missing}); err != nil {
		t.Fatalf("missing optional artifact: %v", err)
	}
	if err := s.prepareClientArtifact(ClientArtifactConfig{Alias: "required", Path: missing, Required: true}); err == nil {
		t.Fatal("missing required artifact was accepted")
	}
	dir := t.TempDir()
	if err := s.prepareClientArtifact(ClientArtifactConfig{Alias: "directory", Path: dir}); err != nil {
		t.Fatalf("optional directory artifact: %v", err)
	}
	if err := s.prepareClientArtifact(ClientArtifactConfig{Alias: "requireddir", Path: dir, Required: true}); err == nil {
		t.Fatal("required directory artifact was accepted")
	}
	large := filepath.Join(t.TempDir(), "large.bin")
	if err := os.WriteFile(large, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.prepareClientArtifact(ClientArtifactConfig{Alias: "large", Path: large}); err != nil {
		t.Fatalf("oversized optional artifact: %v", err)
	}
	if _, ok := s.clientArtifacts["large"]; ok {
		t.Fatal("oversized optional artifact was published")
	}
}

func TestSaveCacheMetaSuccessAndMissingDirectory(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC().Truncate(time.Nanosecond)
	entry := downloadCacheEntry{
		spoolPath: filepath.Join(s.cacheDir, "payload.bin"), mtime: now,
		size: 10, sha256: strings.Repeat("a", 64), encodedSize: 16,
		chunkCount: 1, lastAccess: now, expires: now.Add(time.Hour),
	}
	if err := s.saveCacheMeta(entry, "cache-key"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(s.cacheDir, "cache-key.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta diskCacheMeta
	if err := json.Unmarshal(raw, &meta); err != nil || meta.Key != "cache-key" || meta.Spool != "payload.bin" {
		t.Fatalf("saved metadata=%+v err=%v", meta, err)
	}
	s.cacheDir = filepath.Join(t.TempDir(), "removed")
	if err := s.saveCacheMeta(entry, "unwritable"); err == nil {
		t.Fatal("expected metadata temp-file creation error")
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
		want := strconv.Itoa(i) // ack = chunk index
		if got := sendUploadChunk(t, s, sid, i, chunks[i]); got != want {
			t.Fatalf("chunk %d response=%q, want %q", i, got, want)
		}
	}

	// Close the underlying spool so accepting the final chunk fails.
	s.mu.Lock()
	state := s.uploads[sid]
	state.spool.Close()
	s.uploads[sid] = state
	s.mu.Unlock()

	// Send the final chunk; writeAll on the closed spool will fail.
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

// cacheKey resolves the content-addressed cache key used by the streaming
// spool cache.  The source digest is intentionally part of the key so an
// active transfer can keep serving the old bytes while a modified source gets
// a new cache entry.
func cacheKey(t *testing.T, s *Server, filename string) string {
	t.Helper()
	raw := filepath.Join(s.dataDir, filename)
	real, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", raw, err)
	}
	_, digest, err := hashFile(real)
	if err != nil {
		t.Fatalf("hashFile(%q): %v", real, err)
	}
	return downloadCacheKey(real, digest)
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
	updatedKey := cacheKey(t, s, filename)

	s.mu.Lock()
	secondMtime := s.downloadCache[updatedKey].mtime
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
	updatedKey := cacheKey(t, s, filename)
	s.mu.Lock()
	secondDigest := s.downloadCache[updatedKey].sha256
	secondMtime := s.downloadCache[updatedKey].mtime
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
	payload := []byte("same-sized eviction payload")
	quota := cacheBuildReservation(int64(len(payload)))
	s := newTestServer(t, func(cfg *Config) { cfg.CacheMaxBytes = quota })
	for _, name := range []string{"evict-first.txt", "evict-second.txt"} {
		if err := os.WriteFile(filepath.Join(s.dataDir, name), payload, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	firstKey := cacheKey(t, s, "evict-first.txt")
	secondKey := cacheKey(t, s, "evict-second.txt")
	startDownload(t, s, "evictsid001", "evict-first.txt")
	args := append([]string{"evictsid002"}, filenameLabels(t, "evict-second.txt")...)
	blocked := s.handleTXT(signedName("dinit", args), "127.0.0.1")
	if len(blocked) != 1 || blocked[0] != "Server download preparation error." {
		t.Fatalf("second active build exceeded hard quota: %v", blocked)
	}

	// Expiring the first transfer makes its LRU spool eligible, after which the
	// same request can reserve build space without exceeding the hard quota.
	s.mu.Lock()
	state := s.downloads["evictsid001"]
	state.expires = time.Now().Add(-time.Minute)
	s.downloads["evictsid001"] = state
	s.cleanupExpiredLocked(time.Now())
	s.mu.Unlock()
	startDownload(t, s, "evictsid002", "evict-second.txt")
	s.mu.Lock()
	_, firstStillCached := s.downloadCache[firstKey]
	_, secondStillCached := s.downloadCache[secondKey]
	s.mu.Unlock()
	if firstStillCached {
		t.Fatal("inactive LRU cache entry should be evicted under byte quota")
	}
	if !secondStillCached {
		t.Fatal("active cache entry must not be evicted")
	}
}

func TestDownloadCacheSingleflightIncludesSnapshotAndQuota(t *testing.T) {
	payload := bytes.Repeat([]byte("singleflight-cache"), 4096)
	quota := cacheBuildReservation(int64(len(payload)))
	s := newTestServer(t, func(cfg *Config) { cfg.CacheMaxBytes = quota })
	path := filepath.Join(s.dataDir, "singleflight.bin")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	const callers = 8
	type result struct {
		key string
		err error
	}
	results := make(chan result, callers)
	start := make(chan struct{})
	for range callers {
		go func() {
			<-start
			key, _, err := s.prepareDownloadCache(path, info, time.Now().UTC())
			results <- result{key: key, err: err}
		}()
	}
	close(start)
	var key string
	for range callers {
		got := <-results
		if got.err != nil {
			t.Fatalf("concurrent cache preparation: %v", got.err)
		}
		if key == "" {
			key = got.key
		} else if got.key != key {
			t.Fatalf("singleflight returned different keys: %q and %q", key, got.key)
		}
	}
	s.mu.Lock()
	entry := s.downloadCache[key]
	reserved := s.downloadCacheReserved
	builds := len(s.downloadCacheBuilds)
	s.mu.Unlock()
	if entry.active != callers || reserved != 0 || builds != 0 {
		t.Fatalf("cache state after singleflight: active=%d reserved=%d builds=%d", entry.active, reserved, builds)
	}
}

func TestNewReconcilesOrphanTransferSpools(t *testing.T) {
	dataDir := t.TempDir()
	cacheDir := filepath.Join(dataDir, "cache")
	if err := os.Mkdir(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		filepath.Join(cacheDir, ".gdns2tcp-source-dead"),
		filepath.Join(cacheDir, "orphan.b64"),
		filepath.Join(dataDir, ".gdns2tcp-upload-dead.wire"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("orphan"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := newTestServer(t, func(cfg *Config) {
		cfg.DataDir = dataDir
		cfg.CacheDir = cacheDir
	})
	_ = s
	for _, path := range paths {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("orphan %s was not reconciled: %v", path, err)
		}
	}
}

func TestLoadDownloadCacheDropsMalformedMissingAndExpiredMetadata(t *testing.T) {
	dataDir := t.TempDir()
	cacheDir := filepath.Join(dataDir, "cache")
	if err := os.Mkdir(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	writeEntry := func(key string, spoolExists bool, expires time.Time) {
		t.Helper()
		spool := key + ".b64"
		if spoolExists {
			if err := os.WriteFile(filepath.Join(cacheDir, spool), []byte("encoded"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		meta := diskCacheMeta{Key: key, Spool: spool, MTimeUnixNs: now.UnixNano(), Size: 3, SHA256: "abc", EncodedSize: 7, ChunkCount: 1, LastAccess: now.UnixNano(), Expires: expires.UnixNano()}
		raw, _ := json.Marshal(meta)
		if err := os.WriteFile(filepath.Join(cacheDir, key+".json"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeEntry("valid", true, now.Add(time.Hour))
	writeEntry("missing", false, now.Add(time.Hour))
	writeEntry("expired", true, now.Add(-time.Hour))
	if err := os.WriteFile(filepath.Join(cacheDir, "malformed.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, func(cfg *Config) {
		cfg.DataDir = dataDir
		cfg.CacheDir = cacheDir
	})
	s.mu.Lock()
	_, valid := s.downloadCache["valid"]
	loadedBytes := s.downloadCacheBytes
	s.mu.Unlock()
	if !valid || loadedBytes != 7 {
		t.Fatalf("valid=%v loaded bytes=%d", valid, loadedBytes)
	}
	for _, name := range []string{"missing.json", "expired.json", "expired.b64", "malformed.json"} {
		if _, err := os.Stat(filepath.Join(cacheDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid cache file %s retained: %v", name, err)
		}
	}
}

func TestEvictDownloadCacheSkipsStaleOrderAndStopsWhenAllActive(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	s.mu.Lock()
	s.cacheMaxBytes = 1
	s.downloadCache = map[string]downloadCacheEntry{
		"active": {encodedSize: 10, active: 1, expires: now.Add(time.Hour)},
	}
	s.downloadCacheBytes = 10
	s.downloadCacheOrder = []string{"missing", "active"}
	s.evictDownloadCacheLocked(now)
	_, retained := s.downloadCache["active"]
	s.mu.Unlock()
	if !retained {
		t.Fatal("active cache entry was evicted")
	}
}

func TestDownloadBatchDebouncesCacheMetadataWrites(t *testing.T) {
	s := newTestServer(t)
	filename := "meta-debounce.bin"
	if err := os.WriteFile(filepath.Join(s.dataDir, filename), bytes.Repeat([]byte("x"), 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	startDownload(t, s, "metawritesid", filename)
	s.mu.Lock()
	state := s.downloads["metawritesid"]
	entry := s.downloadCache[state.cacheKey]
	beforeSave := entry.lastMetaSave
	s.mu.Unlock()
	if got := fetchDownloadBatch(t, s, "metawritesid", 0, 4); len(got) == 0 {
		t.Fatal("empty download batch")
	}
	s.mu.Lock()
	afterSave := s.downloadCache[state.cacheKey].lastMetaSave
	s.mu.Unlock()
	if !afterSave.Equal(beforeSave) {
		t.Fatalf("metadata was rewritten inside debounce interval: before=%v after=%v", beforeSave, afterSave)
	}
}

func TestDownloadChunkAndBatchReportMissingCacheSpool(t *testing.T) {
	s := newTestServer(t)
	filename := "missing-spool.bin"
	if err := os.WriteFile(filepath.Join(s.dataDir, filename), []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	sid := "missingspool01"
	startDownload(t, s, sid, filename)
	s.mu.Lock()
	state := s.downloads[sid]
	entry := s.downloadCache[state.cacheKey]
	s.mu.Unlock()
	if err := os.Remove(entry.spoolPath); err != nil {
		t.Fatal(err)
	}
	if got := s.handleTXT(signedName("d", []string{sid, "0"}), "127.0.0.1"); got[0] != "Download cache unavailable." {
		t.Fatalf("missing chunk spool response=%v", got)
	}
	if got := s.handleTXT(signedName("db", []string{sid, "0", "1"}), "127.0.0.1"); got[0] != "Download cache unavailable." {
		t.Fatalf("missing batch spool response=%v", got)
	}
}

func TestCatalogReadDirectoryError(t *testing.T) {
	s := newTestServer(t)
	if err := os.RemoveAll(s.dataDir); err != nil {
		t.Fatal(err)
	}
	if got := s.handleTXT(signedName("c", nil), "127.0.0.1"); got[0] != "Directory listing error." {
		t.Fatalf("catalog missing dir response=%v", got)
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
	chunks := s.clientArtifacts["win"].chunkCount
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

func TestClientArtifactProgressUsesBitmapAndExpires(t *testing.T) {
	s, total := newClientArtifactServer(t)
	client := "192.0.2.10"
	if got := s.clientChunk("win", []string{"0"}, client); len(got) != 1 {
		t.Fatalf("client chunk response=%v", got)
	}
	key := client + "|win"
	s.mu.Lock()
	progress, ok := s.clientTransfers[key]
	if !ok {
		s.mu.Unlock()
		t.Fatal("client transfer progress was not recorded")
	}
	if len(progress.seen) != (total+7)/8 || progress.seenCount != 1 {
		s.mu.Unlock()
		t.Fatalf("progress bitmap bytes=%d count=%d, want bytes=%d count=1", len(progress.seen), progress.seenCount, (total+7)/8)
	}
	progress.lastSeen = time.Now().Add(-clientTransferTTL - time.Second)
	s.clientTransfers[key] = progress
	s.cleanupExpiredLocked(time.Now())
	_, retained := s.clientTransfers[key]
	s.mu.Unlock()
	if retained {
		t.Fatal("expired client artifact progress was retained")
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

func TestHandleSOCKS5OperatorMalformedAndCapacityPaths(t *testing.T) {
	runPipe := func(t *testing.T, s *Server, client func(net.Conn)) {
		t.Helper()
		serverConn, clientConn := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.HandleSOCKS5OperatorForTest(serverConn)
		}()
		client(clientConn)
		_ = clientConn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("SOCKS handler did not terminate")
		}
	}

	t.Run("bad no-auth greeting", func(t *testing.T) {
		s := newTestServer(t, func(cfg *Config) {
			cfg.AllowProxy = true
			cfg.SocksNoAuth = true
		})
		runPipe(t, s, func(conn net.Conn) { _, _ = conn.Write([]byte{0x04, 0x01, 0x00}) })
	})

	t.Run("invalid connect command", func(t *testing.T) {
		s := newTestServer(t, func(cfg *Config) {
			cfg.AllowProxy = true
			cfg.SocksNoAuth = true
		})
		runPipe(t, s, func(conn net.Conn) {
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
			method := make([]byte, 2)
			_, _ = io.ReadFull(conn, method)
			go func() { _, _ = conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80}) }()
			reply := make([]byte, 10)
			_, _ = io.ReadFull(conn, reply)
			if reply[1] != 0x01 {
				t.Fatalf("invalid CONNECT reply=%v", reply)
			}
		})
	})

	t.Run("reverse capacity", func(t *testing.T) {
		s := newTestServer(t, func(cfg *Config) {
			cfg.AllowProxy = true
			cfg.SocksNoAuth = true
			cfg.ProxyMaxConn = 1
		})
		held, peer := net.Pipe()
		defer held.Close()
		defer peer.Close()
		if _, _, err := s.reverseEnqueueOpen("127.0.0.1:80", held); err != nil {
			t.Fatal(err)
		}
		runPipe(t, s, func(conn net.Conn) {
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
			method := make([]byte, 2)
			_, _ = io.ReadFull(conn, method)
			go func() { _, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80}) }()
			reply := make([]byte, 10)
			_, _ = io.ReadFull(conn, reply)
			if reply[1] != 0x05 {
				t.Fatalf("capacity reply=%v", reply)
			}
		})
	})
}

func TestCollectRetainedAxchgReadBranches(t *testing.T) {
	s := proxyTestServer(t)
	rc := &reverseConn{outbound: map[uint64]outboundProxyResponse{
		2: {segments: []string{"DATA", "two"}},
		1: {segments: []string{"DATA", "one"}},
	}}
	now := time.Now()
	if got := s.collectRetainedAxchgRead(rc, now); strings.Join(got, "|") != "DATA|one" {
		t.Fatalf("oldest retained response=%v", got)
	}
	rc.outbound = nil
	if got := s.collectRetainedAxchgRead(rc, now); strings.Join(got, "|") != "EMPTY" {
		t.Fatalf("empty retained response=%v", got)
	}
	rc.opClosed = true
	if got := s.collectRetainedAxchgRead(rc, now); strings.Join(got, "|") != "CLOSED" {
		t.Fatalf("closed retained response=%v", got)
	}
}

func TestProxyAgentEndpointValidationMatrix(t *testing.T) {
	s := proxyTestServer(t)
	now := time.Now().UTC()
	authArgs := func(command string, payload ...string) []string {
		ts := protocol.CurrentTimestamp(now)
		token := protocol.AuthToken(testSecret, testDomain, command, ts, payload)
		return append(append([]string{}, payload...), ts, token)
	}
	assertResponse := func(name string, got []string, want string) {
		t.Helper()
		if len(got) != 1 || got[0] != want {
			t.Fatalf("%s response=%v, want %q", name, got, want)
		}
	}

	assertResponse("poll auth", s.proxyAgentPoll(nil, now, "127.0.0.1"), proxyAuthFailResponse)
	assertResponse("poll payload", s.proxyAgentPoll(authArgs("apoll", "a", "b", "c"), now, "127.0.0.1"), "ERR malformed")
	assertResponse("poll id", s.proxyAgentPoll(authArgs("apoll", "not-a-poll-id"), now, "127.0.0.1"), "ERR bad poll")
	assertResponse("poll version", s.proxyAgentPoll(authArgs("apoll", "0123456789abcdef", "v3"), now, "127.0.0.1"), "ERR malformed")
	if validPollID("0123456789abcdeg") || validPollID("short") {
		t.Fatal("invalid poll ID accepted")
	}

	assertResponse("open auth", s.proxyAgentOpen(nil, now), proxyAuthFailResponse)
	assertResponse("open arity", s.proxyAgentOpen(authArgs("aopen", "only"), now), "ERR malformed")
	assertResponse("open identifiers", s.proxyAgentOpen(authArgs("aopen", "bad", "0123456789abcdef", "ok"), now), "ERR malformed")
	assertResponse("open status", s.proxyAgentOpen(authArgs("aopen", "0123456789abcdef", "fedcba9876543210", "mystery"), now), "ERR malformed")
	assertResponse("open unknown", s.proxyAgentOpen(authArgs("aopen", "0123456789abcdef", "fedcba9876543210", "ok"), now), "OK")

	assertResponse("status auth", s.proxyAgentStatus(nil, now), proxyAuthFailResponse)
	assertResponse("status identifiers", s.proxyAgentStatus(authArgs("astatus", "bad", "bad"), now), "CLOSED")
	assertResponse("status unknown", s.proxyAgentStatus(authArgs("astatus", "0123456789abcdef", "fedcba9876543210"), now), "CLOSED")

	op, peer := net.Pipe()
	defer op.Close()
	defer peer.Close()
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	key := rc.sessionKey
	assertResponse("open wrong lease", s.proxyAgentOpen(authArgs("aopen", cid, "fedcba9876543210", "ok"), now), "ERR lease")

	assertResponse("read arity", s.proxyAgentRead(nil, now), "ERR malformed")
	assertResponse("read cid", s.proxyAgentRead([]string{"bad", "1", "x"}, now), "ERR bad cid")
	assertResponse("read nonce", s.proxyAgentRead([]string{cid, "xyz", "x"}, now), "ERR bad nonce")
	assertResponse("read marker", s.proxyAgentRead([]string{cid, "1", "bad-marker", "x"}, now), "ERR malformed")
	assertResponse("read unknown", s.proxyAgentRead([]string{"0123456789abcdef", "1", "x"}, now), "CLOSED")
	assertResponse("read mac", s.proxyAgentRead([]string{cid, "1", "wrong"}, now), proxyAuthFailResponse)

	assertResponse("write arity", s.proxyAgentWrite(nil, now), "ERR malformed")
	assertResponse("write cid", s.proxyAgentWrite([]string{"bad", "1", "x", "x"}, now), "ERR bad cid")
	assertResponse("write seq", s.proxyAgentWrite([]string{cid, "xyz", "x", "x"}, now), "ERR bad seq")
	assertResponse("write unknown", s.proxyAgentWrite([]string{"0123456789abcdef", "1", "x", "x"}, now), "ERR unknown cid")
	assertResponse("write mac", s.proxyAgentWrite([]string{cid, "1", "x", "wrong"}, now), proxyAuthFailResponse)
	rc.mu.Lock()
	rc.agentClosed = true
	rc.mu.Unlock()
	assertResponse("write closed", s.proxyAgentWrite([]string{cid, "1", "x", protocol.SessionMAC(key, "awrite", 1)}, now), "ERR closed")
	rc.mu.Lock()
	rc.agentClosed = false
	rc.mu.Unlock()
	assertResponse("write encoding", s.proxyAgentWrite([]string{cid, "1", "!", protocol.SessionMAC(key, "awrite", 1)}, now), "ERR illegal base32 data at input byte 0")
	assertResponse("write ciphertext", s.proxyAgentWrite([]string{cid, "1", "aa", protocol.SessionMAC(key, "awrite", 1)}, now), "ERR open")

	assertResponse("close arity", s.proxyAgentClose(nil, now), "ERR malformed")
	assertResponse("close cid", s.proxyAgentClose([]string{"bad", "1", "x"}, now), "ERR bad cid")
	assertResponse("close nonce", s.proxyAgentClose([]string{cid, "xyz", "x"}, now), "ERR bad nonce")
	assertResponse("close unknown", s.proxyAgentClose([]string{"0123456789abcdef", "1", "x"}, now), "OK")
	assertResponse("close mac", s.proxyAgentClose([]string{cid, "1", "wrong"}, now), proxyAuthFailResponse)

	assertResponse("exchange arity", s.proxyAgentExchange(nil, now), "ERR malformed")
	assertResponse("exchange cid", s.proxyAgentExchange([]string{"bad", "0", "1", "x"}, now), "ERR bad cid")
	assertResponse("exchange seq", s.proxyAgentExchange([]string{cid, "xyz", "1", "x"}, now), "ERR bad seq")
	assertResponse("exchange nonce", s.proxyAgentExchange([]string{cid, "0", "xyz", "x"}, now), "ERR bad nonce")
	assertResponse("exchange ack", s.proxyAgentExchange([]string{cid, "0", "a-xyz", "1", "x"}, now), "ERR bad ack")
	assertResponse("exchange unknown", s.proxyAgentExchange([]string{"0123456789abcdef", "0", "1", "x"}, now), "CLOSED")
	assertResponse("exchange mac", s.proxyAgentExchange([]string{cid, "0", "2", "wrong"}, now), proxyAuthFailResponse)
	assertResponse("exchange missing write", s.proxyAgentExchange([]string{cid, "1", "3", protocol.SessionMAC(key, "axchg", 3)}, now), "ERR malformed")
	assertResponse("exchange encoding", s.proxyAgentExchange([]string{cid, "1", "!", "4", protocol.SessionMAC(key, "axchg", 4)}, now), "ERR illegal base32 data at input byte 0")
}

func TestProxyAgentEndpointsReportDisabled(t *testing.T) {
	s := newTestServer(t)
	now := time.Now().UTC()
	for name, response := range map[string][]string{
		"apoll":   s.proxyAgentPoll(nil, now, "127.0.0.1"),
		"aopen":   s.proxyAgentOpen(nil, now),
		"astatus": s.proxyAgentStatus(nil, now),
		"aread":   s.proxyAgentRead(nil, now),
		"awrite":  s.proxyAgentWrite(nil, now),
		"aclose":  s.proxyAgentClose(nil, now),
		"axchg":   s.proxyAgentExchange(nil, now),
	} {
		if len(response) != 1 || response[0] != proxyDisabledResponse {
			t.Fatalf("%s disabled response=%v", name, response)
		}
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

// TestSignalReadersForBufferWakesEnoughForBurst is the regression
// guard for the Medium finding "signalOneReaderLocked wakes only one
// waiter — burst larger than one worker's clamp stalls until parked
// workers self-poll (~150 ms latency spike)". The fix wakes ceil(len /
// maxRead) workers per pump write, capped by parked count.
//
// The test parks N waiters, fills opToAgent past several worker
// clamps, and asserts multiple wakes fire (not just one). A single-
// wake regression would leave data stranded until the parked workers'
// own longPollWindow expired.
func TestSignalReadersForBufferWakesEnoughForBurst(t *testing.T) {
	rc := &reverseConn{}
	rc.opCond = sync.NewCond(&rc.mu)

	// Park N waiters to have several candidates to wake.
	const N = 8
	woke := make(chan int, N)
	var wg sync.WaitGroup
	for i := range N {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if rc.awaitReadData(3 * time.Second) {
				woke <- id
			}
		}(i)
	}
	// Give the goroutines time to park.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		rc.mu.Lock()
		parked := len(rc.readWaiters)
		rc.mu.Unlock()
		if parked == N {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	rc.mu.Lock()
	if got := len(rc.readWaiters); got != N {
		rc.mu.Unlock()
		t.Fatalf("expected %d parked waiters, got %d", N, got)
	}

	// Fill opToAgent well past a single UDP worker's clamp
	// (gproxy.MaxReadBytes). Enough for at least 3 workers.
	burst := 3*gproxy.MaxReadBytes + 100
	rc.opToAgent.Write(bytes.Repeat([]byte("x"), burst))
	rc.signalReadersForBufferLocked()
	rc.mu.Unlock()

	// Collect wakes within a tight window.
	timeout := time.After(300 * time.Millisecond)
	wakes := 0
	minExpectedWakes := 3 // ceil(3*maxRead+100 / maxRead) == 4; require at least 3 as a safety margin
gather:
	for {
		select {
		case <-woke:
			wakes++
		case <-timeout:
			break gather
		}
	}
	if wakes < minExpectedWakes {
		t.Fatalf("burst wake fired only %d workers (want ≥ %d) — single-wake regression?", wakes, minExpectedWakes)
	}
	if wakes > N {
		t.Fatalf("wakes=%d exceeds parked count N=%d", wakes, N)
	}

	// Cleanup: close remaining waiters via closeAllReadersLocked.
	rc.mu.Lock()
	rc.closeAllReadersLocked()
	rc.mu.Unlock()
	wg.Wait()
}

func TestReverseModernPollLeaseAndOpenAcknowledgement(t *testing.T) {
	s := proxyTestServer(t)
	op, peer := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = peer.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	pollID := "0123456789abcdef"
	first := s.handleTXT(signedName("apoll", []string{pollID}), "127.0.0.1")
	if len(first) != 1 || !strings.HasPrefix(first[0], "OPEN "+cid+" ") {
		t.Fatalf("first modern poll = %v", first)
	}
	second := s.handleTXT(signedName("apoll", []string{pollID}), "127.0.0.1")
	if len(second) != 1 || second[0] != first[0] {
		t.Fatalf("duplicate poll must retain the same lease: first=%v second=%v", first, second)
	}
	other := s.handleTXT(signedName("apoll", []string{"fedcba9876543210"}), "127.0.0.1")
	if len(other) != 1 || other[0] != "EMPTY" {
		t.Fatalf("a different poll must not steal an active lease: %v", other)
	}

	// Expiry requeues the cid for another agent instead of stranding the
	// operator's pending SOCKS request.
	rc.mu.Lock()
	rc.leaseExpires = time.Now().Add(-time.Second)
	rc.mu.Unlock()
	s.proxyCleanupExpiredLocked(time.Now())
	other = s.handleTXT(signedName("apoll", []string{"fedcba9876543210"}), "127.0.0.1")
	if len(other) != 1 || !strings.HasPrefix(other[0], "OPEN "+cid+" ") {
		t.Fatalf("expired lease was not requeued: %v", other)
	}

	ack := s.handleTXT(signedName("aopen", []string{cid, "fedcba9876543210", "ok"}), "127.0.0.1")
	if len(ack) != 1 || ack[0] != "OK" {
		t.Fatalf("aopen response=%v", ack)
	}
	select {
	case <-rc.openReady:
		if rc.openStatus != 0x00 {
			t.Fatalf("open status=%#x", rc.openStatus)
		}
	case <-time.After(time.Second):
		t.Fatal("aopen did not release the SOCKS wait")
	}
	duplicate := s.handleTXT(signedName("aopen", []string{cid, "fedcba9876543210", "ok"}), "127.0.0.1")
	if len(duplicate) != 1 || duplicate[0] != "OK" {
		t.Fatalf("duplicate aopen must be idempotent, got %v", duplicate)
	}
}

func TestReverseV2StatusTransitions(t *testing.T) {
	s := proxyTestServer(t)
	op, peer := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = peer.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	pollID := "0123456789abcdef"
	poll := s.handleTXT(signedName("apoll", []string{pollID, "v2"}), "127.0.0.1")
	if len(poll) != 1 || !strings.HasPrefix(poll[0], "OPEN "+cid+" ") {
		t.Fatalf("v2 apoll=%v", poll)
	}
	if got := s.handleTXT(signedName("astatus", []string{cid, pollID}), "127.0.0.1"); len(got) != 1 || got[0] != "PENDING" {
		t.Fatalf("pending astatus=%v", got)
	}
	if got := s.handleTXT(signedName("aopen", []string{cid, pollID, "ok"}), "127.0.0.1"); len(got) != 1 || got[0] != "OK" {
		t.Fatalf("aopen=%v", got)
	}
	if got := s.handleTXT(signedName("astatus", []string{cid, pollID}), "127.0.0.1"); len(got) != 1 || got[0] != "OPEN" {
		t.Fatalf("open astatus=%v", got)
	}
	s.reverseCloseConn(cid, rc, "test")
	if got := s.handleTXT(signedName("astatus", []string{cid, pollID}), "127.0.0.1"); len(got) != 1 || got[0] != "CLOSED" {
		t.Fatalf("closed astatus=%v", got)
	}
}

func TestProxyAgentExchangeCachesLostResponseUntilReadACK(t *testing.T) {
	s := proxyTestServer(t)
	op, peer := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = peer.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	s.reverse.mu.Lock()
	s.reverse.pending = nil
	delete(s.reverse.pendCids, rc)
	s.reverse.mu.Unlock()
	rc.mu.Lock()
	_, _ = rc.opToAgent.Write([]byte("must not vanish when the DNS reply is lost"))
	rc.mu.Unlock()

	nonce := uint64(1)
	args := []string{cid, "0", strconv.FormatUint(nonce, 16), protocol.SessionMAC(rc.sessionKey, "axchg", nonce)}
	first := s.proxyAgentExchange(args, time.Now())
	if len(first) < 2 || !strings.HasPrefix(first[1], "DATA ") {
		t.Fatalf("first axchg response=%v", first)
	}
	second := s.proxyAgentExchange(args, time.Now())
	if strings.Join(second, "|") != strings.Join(first, "|") {
		t.Fatalf("duplicate axchg did not return cached response: first=%v second=%v", first, second)
	}
	rc.mu.Lock()
	entry := rc.responseCache[nonce]
	if entry == nil || !entry.ready || entry.readSeq != 1 || entry.readHead != "" {
		rc.mu.Unlock()
		t.Fatalf("response cache retained unexpected payload state: %#v", entry)
	}
	if rc.seqOpToA != 1 || len(rc.outbound) != 1 {
		rc.mu.Unlock()
		t.Fatalf("duplicate axchg drained data again: seq=%d outbound=%d", rc.seqOpToA, len(rc.outbound))
	}
	// Simulate bounded response-cache eviction before a delayed TCP retry. The
	// nonce remains in the replay window, so the retry must recover from the
	// ACK-retained outbound data instead of becoming a false auth failure.
	delete(rc.responseCache, nonce)
	rc.mu.Unlock()
	third := s.proxyAgentExchange(args, time.Now())
	if strings.Join(third, "|") != strings.Join(first, "|") {
		t.Fatalf("evicted duplicate did not recover retained data: first=%v retry=%v", first, third)
	}
	rc.mu.Lock()
	if rc.seqOpToA != 1 || len(rc.outbound) != 1 {
		rc.mu.Unlock()
		t.Fatalf("evicted duplicate drained data again: seq=%d outbound=%d", rc.seqOpToA, len(rc.outbound))
	}
	rc.mu.Unlock()

	ackNonce := uint64(2)
	ackArgs := []string{cid, "0", "a-1", strconv.FormatUint(ackNonce, 16), protocol.SessionMAC(rc.sessionKey, "axchg", ackNonce)}
	_ = s.proxyAgentExchange(ackArgs, time.Now())
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if len(rc.outbound) != 0 || rc.readAck != 1 {
		t.Fatalf("read ACK did not release retained outbound data: ack=%d outbound=%d", rc.readAck, len(rc.outbound))
	}
}

func TestProxyResponseCacheInflightMaterializationAndEviction(t *testing.T) {
	rc := &reverseConn{
		responseCache: make(map[uint64]*cachedProxyResponse),
		outbound: map[uint64]outboundProxyResponse{
			7: {segments: []string{"DATA 7", "payload"}},
		},
	}
	now := time.Now().UTC()
	rc.mu.Lock()
	cached, wait, owner := rc.beginResponse(1, now)
	if cached != nil || wait != nil || !owner {
		rc.mu.Unlock()
		t.Fatalf("first reservation cached=%v wait=%v owner=%v", cached, wait, owner)
	}
	_, wait, owner = rc.beginResponse(1, now)
	rc.mu.Unlock()
	if wait == nil || owner {
		t.Fatalf("duplicate inflight wait=%v owner=%v", wait, owner)
	}
	rc.finishResponse(1, []string{"ACK 0", "DATA 7", "payload"}, now)
	<-wait
	rc.mu.Lock()
	cached, _, owner = rc.beginResponse(1, now)
	rc.mu.Unlock()
	if owner || strings.Join(cached, "|") != "ACK 0|DATA 7|payload" {
		t.Fatalf("materialized retained response=%v owner=%v", cached, owner)
	}

	rc.mu.Lock()
	delete(rc.outbound, 7)
	rc.readAck = 7
	cached = rc.materializeCachedResponseLocked(rc.responseCache[1])
	if strings.Join(cached, "|") != "ACK 0|EMPTY" {
		rc.mu.Unlock()
		t.Fatalf("acked materialization=%v", cached)
	}
	rc.readAck = 0
	if got := rc.materializeCachedResponseLocked(rc.responseCache[1]); got != nil {
		rc.mu.Unlock()
		t.Fatalf("missing unacked outbound materialized=%v", got)
	}
	if got := rc.materializeCachedResponseLocked(nil); got != nil {
		rc.mu.Unlock()
		t.Fatalf("nil cache entry materialized=%v", got)
	}
	rc.responseCache = make(map[uint64]*cachedProxyResponse)
	for i := uint64(0); i < maxProxyResponseCache; i++ {
		rc.responseCache[i] = &cachedProxyResponse{ready: true, expires: now.Add(-time.Second)}
	}
	_, _, owner = rc.beginResponse(maxProxyResponseCache+3, now)
	rc.mu.Unlock()
	if !owner || len(rc.responseCache) > maxProxyResponseCache {
		t.Fatalf("cache owner=%v size=%d", owner, len(rc.responseCache))
	}
}

// TestProxyResponseCacheExpiredNotReadyEntryIsReclaimed guards the High
// finding in the 2026-08-17 review: `proxyCleanupExpiredLocked` only
// removed `ready` expired entries, so a `!ready` entry whose owner
// disappeared (panic, forgotten error path, etc.) lived forever, its
// `done` channel was never closed, and any parked axchg waiter blocked
// indefinitely.  Under sustained accumulation the responseCache would
// hit maxProxyResponseCache and further axchg on the cid would fail
// authentication.
//
// The test reserves a nonce (becoming owner), abandons it without
// calling finishResponse, forces cleanup with the owner deadline in
// the past, and asserts:
//   - the entry is removed from responseCache;
//   - the entry's done channel is closed so any parked waiter wakes.
func TestProxyResponseCacheExpiredNotReadyEntryIsReclaimed(t *testing.T) {
	s := newTestServer(t, func(cfg *Config) { cfg.AllowProxy = true })
	op, peer := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = peer.Close() })
	_, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	// Signal open so the cid is a fully live tunnel from cleanup's POV.
	rc.signalOpen(0x00)

	// Reserve a nonce (become owner). Snapshot the done channel — the
	// bug used to leave this open forever.
	rc.mu.Lock()
	_, _, owner := rc.beginResponse(1, time.Now().UTC())
	entry := rc.responseCache[1]
	rc.mu.Unlock()
	if !owner || entry == nil || entry.done == nil {
		t.Fatalf("beginResponse: owner=%v entry=%v", owner, entry)
	}
	waiterDone := entry.done

	// Force the owner deadline into the past AND make the whole tunnel
	// look idle so proxyCleanupExpiredLocked processes it. reverseTTL
	// is 30 min; we go well past.
	rc.mu.Lock()
	entry.expires = time.Now().UTC().Add(-time.Hour)
	rc.mu.Unlock()

	// Cleanup only touches the responseCache; it does not require the
	// whole conn to be expired. Run it and assert the !ready entry is
	// gone and its channel closed.
	s.mu.Lock()
	s.proxyCleanupExpiredLocked(time.Now().UTC())
	s.mu.Unlock()

	rc.mu.Lock()
	_, stillThere := rc.responseCache[1]
	rc.mu.Unlock()
	if stillThere {
		t.Fatal("expired !ready responseCache entry was not reclaimed by cleanup")
	}
	select {
	case <-waiterDone:
		// good — parked waiters would wake up here.
	case <-time.After(time.Second):
		t.Fatal("cleanup did not close entry.done; waiters would block forever")
	}
}

// TestProxyResponseCacheEvictionUnderNotReadyPressure is the second
// safety net for the High finding: even if cleanup has not run yet,
// beginResponse must be able to evict past-deadline !ready entries so
// a burst of stranded owners cannot fill responseCache and starve
// further axchg on the cid.
func TestProxyResponseCacheEvictionUnderNotReadyPressure(t *testing.T) {
	rc := &reverseConn{}
	rc.opCond = sync.NewCond(&rc.mu)
	past := time.Now().UTC().Add(-time.Hour)

	rc.mu.Lock()
	// Pre-populate the cache with maxProxyResponseCache stale !ready
	// entries. Ready-only eviction paths cannot recover this state.
	rc.responseCache = make(map[uint64]*cachedProxyResponse, maxProxyResponseCache)
	for i := uint64(1); i <= uint64(maxProxyResponseCache); i++ {
		rc.responseCache[i] = &cachedProxyResponse{done: make(chan struct{}), expires: past}
	}
	// Fresh nonce arriving now: without the third-pass eviction we
	// would either grow the map past its cap or fail to reserve.
	cached, wait, owner := rc.beginResponse(uint64(maxProxyResponseCache+7), time.Now().UTC())
	sz := len(rc.responseCache)
	rc.mu.Unlock()

	if !owner || cached != nil || wait != nil {
		t.Fatalf("under !ready pressure beginResponse should own a fresh slot: owner=%v cached=%v wait=%v", owner, cached, wait)
	}
	if sz > maxProxyResponseCache {
		t.Fatalf("responseCache grew past cap: len=%d cap=%d", sz, maxProxyResponseCache)
	}
}

func TestConcurrentAxchgReadReservationsRespectBufferCap(t *testing.T) {
	const capBytes = 8192
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.ProxyMaxConn = 1
		cfg.ProxyBufBytes = capBytes
	})
	op, peer := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = peer.Close() })
	_, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	rc.mu.Lock()
	_, _ = rc.opToAgent.Write(bytes.Repeat([]byte("x"), capBytes))
	rc.mu.Unlock()

	const workers = 32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.collectAxchgRead(rc, 1024, time.Now().UTC(), false)
		}()
	}
	wg.Wait()
	rc.mu.Lock()
	retained := rc.outboundPlainBytes
	reserved := rc.outboundReservedBytes
	buffered := rc.opToAgent.Len()
	inFlight := rc.outboundInFlight
	entries := len(rc.outbound)
	rc.mu.Unlock()
	if retained+reserved+buffered > capBytes {
		t.Fatalf("buffer cap exceeded: retained=%d reserved=%d buffered=%d cap=%d", retained, reserved, buffered, capBytes)
	}
	if inFlight != 0 || entries > maxOutboundUnacked {
		t.Fatalf("unfinished/oversized outbound state: inFlight=%d entries=%d", inFlight, entries)
	}
}

func TestReversePumpHonorsSmallBufferCapacity(t *testing.T) {
	s := newTestServer(t, func(cfg *Config) {
		cfg.AllowProxy = true
		cfg.ProxyMaxConn = 1
		cfg.ProxyBufBytes = 1
	})
	op, peer := net.Pipe()
	t.Cleanup(func() { _ = op.Close(); _ = peer.Close() })
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	go s.reversePumpOperator(cid, rc)
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatalf("operator write with a one-byte buffer blocked: %v", err)
	}
	resp := s.proxyAgentRead(sessionAreadArgs(cid, rc.sessionKey, 1, false), time.Now())
	if len(resp) < 2 || !strings.HasPrefix(resp[0], "DATA ") {
		t.Fatalf("small-buffer read response=%v", resp)
	}
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

func TestProxyAgentExchangeValidationAndWriteErrorBranches(t *testing.T) {
	disabled := newTestServer(t)
	if got := disabled.proxyAgentExchange(nil, time.Now()); got[0] != proxyDisabledResponse {
		t.Fatalf("disabled axchg=%v", got)
	}
	s := proxyTestServer(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"x"}, "ERR malformed"},
		{[]string{"bad", "0", "1", "x"}, "ERR bad cid"},
		{[]string{"0123456789abcdef", "zz", "1", "x"}, "ERR bad seq"},
		{[]string{"0123456789abcdef", "0", "zz", "x"}, "ERR bad nonce"},
		{[]string{"0123456789abcdef", "0", "a-zz", "1", "x"}, "ERR bad ack"},
		{[]string{"0123456789abcdef", "0", "1", "x"}, "CLOSED"},
	} {
		if got := s.proxyAgentExchange(tc.args, time.Now()); len(got) != 1 || got[0] != tc.want {
			t.Fatalf("axchg(%v)=%v, want %q", tc.args, got, tc.want)
		}
	}
	op, peer := net.Pipe()
	cid, rc, err := s.reverseEnqueueOpen("127.0.0.1:80", op)
	if err != nil {
		t.Fatal(err)
	}
	defer op.Close()
	defer peer.Close()
	if got := s.proxyAgentExchange([]string{cid, "0", "1", "wrong"}, time.Now()); got[0] != proxyAuthFailResponse {
		t.Fatalf("bad MAC axchg=%v", got)
	}
	nonce := uint64(2)
	if got := s.proxyAgentExchange([]string{cid, "1", "2", protocol.SessionMAC(rc.sessionKey, "axchg", nonce)}, time.Now()); got[0] != "ERR malformed" {
		t.Fatalf("missing write payload axchg=%v", got)
	}

	rc.mu.Lock()
	rc.agentClosed = true
	rc.mu.Unlock()
	if got := s.applyAxchgWrite(rc, 1, []string{"a"}, time.Now()); got != "ERR closed" {
		t.Fatalf("closed write=%q", got)
	}
	rc.mu.Lock()
	rc.agentClosed = false
	rc.seqAgentIn = 5
	rc.mu.Unlock()
	if got := s.applyAxchgWrite(rc, 5, []string{"a"}, time.Now()); got != "ACK 5" {
		t.Fatalf("duplicate write=%q", got)
	}
	if got := s.applyAxchgWrite(rc, 5+awriteWindow+1, []string{"a"}, time.Now()); got != "ERR seq" {
		t.Fatalf("far-ahead write=%q", got)
	}
	rc.mu.Lock()
	rc.seqAgentIn = 0
	rc.mu.Unlock()
	if got := s.applyAxchgWrite(rc, 1, []string{"!"}, time.Now()); !strings.HasPrefix(got, "ERR ") {
		t.Fatalf("bad Base32 write=%q", got)
	}
	badOpen := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("not-an-aead-record"))
	if got := s.applyAxchgWrite(rc, 1, []string{badOpen}, time.Now()); got != "ERR open" {
		t.Fatalf("bad AEAD write=%q", got)
	}
	badCompressed := gproxy.SealChunk(rc.aead, gproxy.DirClientToServer, 1, []byte{0xff})
	badCompressedLabel := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(badCompressed)
	if got := s.applyAxchgWrite(rc, 1, []string{badCompressedLabel}, time.Now()); got != "ERR decompress" {
		t.Fatalf("bad compressed write=%q", got)
	}
	_ = peer.Close()
	valid := gproxy.SealChunk(rc.aead, gproxy.DirClientToServer, 1, rc.compressor.Encode([]byte("write fails")))
	validLabel := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(valid)
	if got := s.applyAxchgWrite(rc, 1, []string{validLabel}, time.Now()); got != "ERR write" {
		t.Fatalf("operator write failure=%q", got)
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
