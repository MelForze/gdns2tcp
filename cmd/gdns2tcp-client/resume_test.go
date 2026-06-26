package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gdns2tcp/internal/protocol"
)

const testSourceSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// --------------------------- unit tests ---------------------------

func TestResumeCacheRoundtrip(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	if err := c.saveMeta(100, 14, testSourceSHA256); err != nil {
		t.Fatal(err)
	}
	if err := c.saveBatch(3, "chunkA"); err != nil {
		t.Fatal(err)
	}
	if err := c.saveBatch(0, "chunkB"); err != nil {
		t.Fatal(err)
	}

	got, err := c.loadCompleted(100, 14, testSourceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "chunkB" || got[3] != "chunkA" {
		t.Fatalf("loadCompleted = %v, want {0:chunkB, 3:chunkA}", got)
	}
	if len(got) != 2 {
		t.Fatalf("loadCompleted returned %d entries, want 2", len(got))
	}
}

func TestResumeCacheChunkCountMismatch(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	_ = c.saveMeta(100, 14, testSourceSHA256)
	_ = c.saveBatch(0, "data")

	got, err := c.loadCompleted(200, 14, testSourceSHA256) // different chunkCount
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map on mismatch, got %v", got)
	}
	if _, err := os.Stat(c.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cache dir should be removed after chunkCount mismatch")
	}
}

func TestResumeCacheBatchSizeMismatch(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	_ = c.saveMeta(100, 14, testSourceSHA256)
	_ = c.saveBatch(0, "data")

	got, err := c.loadCompleted(100, 8, testSourceSHA256) // different batchSize
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map on mismatch, got %v", got)
	}
	if _, err := os.Stat(c.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cache dir should be removed after batchSize mismatch")
	}
}

func TestResumeCacheSourceDigestMismatch(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	_ = c.saveMeta(100, 14, testSourceSHA256)
	_ = c.saveBatch(0, "data")

	got, err := c.loadCompleted(100, 14, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map on source digest mismatch, got %v", got)
	}
	if _, err := os.Stat(c.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cache dir should be removed after source digest mismatch")
	}
}

func TestResumeCacheSourceDigestRequired(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	_ = c.saveMeta(100, 14, testSourceSHA256)
	_ = c.saveBatch(0, "data")

	got, err := c.loadCompleted(100, 14, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map without source digest, got %v", got)
	}
	if _, err := os.Stat(c.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cache dir should be removed when source digest is unavailable")
	}
}

func TestResumeCacheNoMetaIgnoresStrayBatches(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	// Write a batch file directly without meta.json (simulates a crash after
	// the very first saveBatch but before saveMeta — not the expected order
	// but cache must still recover safely).
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.dir, "batch-000000"), []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := c.loadCompleted(100, 14, testSourceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map without meta, got %v", got)
	}
}

func TestResumeCacheDisabled(t *testing.T) {
	c := newResumeCache(t.TempDir(), "example.com", "file.bin", false)
	if err := c.saveMeta(100, 14, testSourceSHA256); err != nil {
		t.Fatal(err)
	}
	if err := c.saveBatch(0, "data"); err != nil {
		t.Fatal(err)
	}
	got, err := c.loadCompleted(100, 14, testSourceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("disabled cache returned %d entries, want 0", len(got))
	}
	if err := c.clear(); err != nil {
		t.Fatalf("clear on disabled cache returned %v", err)
	}
}

func TestResumeCacheClear(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	_ = c.saveMeta(50, 7, testSourceSHA256)
	_ = c.saveBatch(0, "a")
	_ = c.saveBatch(1, "b")
	if _, err := os.Stat(c.dir); err != nil {
		t.Fatalf("cache dir should exist before clear: %v", err)
	}
	if err := c.clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cache dir should be removed after clear")
	}
}

func TestResumeCacheCorruptMetaIsTreatedAsStale(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	_ = os.MkdirAll(c.dir, 0o700)
	if err := os.WriteFile(filepath.Join(c.dir, "meta.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := c.loadCompleted(100, 14, testSourceSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map for corrupt meta, got %v", got)
	}
	if _, err := os.Stat(c.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cache dir should be removed when meta is corrupt")
	}
}

func TestResumeCacheKeysAreDomainAndFilenameSensitive(t *testing.T) {
	root := t.TempDir()
	a := newResumeCache(root, "example.com", "file.bin", true)
	b := newResumeCache(root, "example.com", "OTHER.bin", true)
	c := newResumeCache(root, "other.com", "file.bin", true)
	if a.dir == b.dir || a.dir == c.dir || b.dir == c.dir {
		t.Fatalf("cache keys collided: %s %s %s", a.dir, b.dir, c.dir)
	}
}

// --------------------------- integration tests ---------------------------

// TestDownloadFileResumeCleansUpAfterSuccess verifies that the resume cache
// directory does not exist after a successful end-to-end download.
func TestDownloadFileResumeCleansUpAfterSuccess(t *testing.T) {
	dataDir := t.TempDir()
	ip, port := startEmbeddedServer(t, newServerCfg(t, dataDir))
	resolver := &txtResolver{server: ip, port: port, retries: 3}

	payload := make([]byte, 4000)
	for i := range payload {
		payload[i] = byte(i * 37 % 251)
	}
	filename := "resume-cleanup.bin"
	if err := os.WriteFile(filepath.Join(dataDir, filename), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	cacheDir := t.TempDir()
	cfg := config{
		domain:           "files.test",
		pass:             "integration-test-secret",
		filename:         filename,
		outFile:          filepath.Join(t.TempDir(), filename),
		retries:          3,
		dnsServer:        ip,
		dnsPort:          port,
		maxDownloadBytes: defaultMaxDownloadBytes,
		cacheDir:         cacheDir,
	}
	if err := downloadFile(resolver, cfg); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}

	// The per-id directory should be gone; cacheDir itself may still exist
	// (and that's fine — it's the parent root).
	cacheParent := newResumeCache(cacheDir, cfg.domain, cfg.filename, true)
	if _, err := os.Stat(cacheParent.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache dir %s should be cleared after success", cacheParent.dir)
	}
}

// TestDownloadFileResumeDropsPoisonedCache proves stale or corrupt cached
// batches do not trap the client in a permanent decrypt failure. The first
// attempt reads the poisoned cache, detects the final payload failure, clears
// the cache, and retries the transfer without resume.
func TestDownloadFileResumeDropsPoisonedCache(t *testing.T) {
	dataDir := t.TempDir()
	ip, port := startEmbeddedServer(t, newServerCfg(t, dataDir))
	resolver := &txtResolver{server: ip, port: port, retries: 3}

	payload := make([]byte, 6000)
	for i := range payload {
		payload[i] = byte(i*53%251 ^ 0x5A)
	}
	filename := "resume-uses-cache.bin"
	if err := os.WriteFile(filepath.Join(dataDir, filename), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	// First call dinit ourselves to discover chunkCount.
	chunkCount := discoverChunkCount(t, resolver, "files.test", "integration-test-secret", filename)

	// Pre-seed the cache: meta matches what downloadFile will compute, batch 0
	// is intentional garbage that base64-decodes to bytes failing HMAC.
	cacheDir := t.TempDir()
	batchSize := defaultDownloadBatch
	cache := newResumeCache(cacheDir, "files.test", filename, true)
	if err := cache.saveMeta(chunkCount, batchSize, sha256Hex(payload)); err != nil {
		t.Fatal(err)
	}
	// Valid base64 alphabet but cryptographically wrong: decryption will
	// fail HMAC verification and return an error.
	if err := cache.saveBatch(0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		t.Fatal(err)
	}

	cfg := config{
		domain:           "files.test",
		pass:             "integration-test-secret",
		filename:         filename,
		outFile:          filepath.Join(t.TempDir(), filename),
		retries:          3,
		dnsServer:        ip,
		dnsPort:          port,
		maxDownloadBytes: defaultMaxDownloadBytes,
		cacheDir:         cacheDir,
	}
	if err := downloadFile(resolver, cfg); err != nil {
		t.Fatalf("downloadFile should recover from poisoned cache, got %v", err)
	}
	got, err := os.ReadFile(cfg.outFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("downloaded payload mismatch after poisoned-cache retry")
	}
	if _, err := os.Stat(cache.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache dir %s should be cleared after retry success", cache.dir)
	}
}

// TestDownloadFileResumeDisabled verifies that -no-resume bypasses the cache
// even if valid pre-seeded data exists, so the download succeeds against the
// real server regardless of cache content.
func TestDownloadFileResumeDisabled(t *testing.T) {
	dataDir := t.TempDir()
	ip, port := startEmbeddedServer(t, newServerCfg(t, dataDir))
	resolver := &txtResolver{server: ip, port: port, retries: 3}

	payload := make([]byte, 5000)
	for i := range payload {
		payload[i] = byte(i*19%251 ^ 0x33)
	}
	filename := "resume-disabled.bin"
	if err := os.WriteFile(filepath.Join(dataDir, filename), payload, 0o600); err != nil {
		t.Fatal(err)
	}

	chunkCount := discoverChunkCount(t, resolver, "files.test", "integration-test-secret", filename)

	// Pre-seed poisoned cache.
	cacheDir := t.TempDir()
	cache := newResumeCache(cacheDir, "files.test", filename, true)
	_ = cache.saveMeta(chunkCount, defaultDownloadBatch, sha256Hex(payload))
	_ = cache.saveBatch(0, "AAAAAAAAAAAAAAAAAAAA")

	cfg := config{
		domain:           "files.test",
		pass:             "integration-test-secret",
		filename:         filename,
		outFile:          filepath.Join(t.TempDir(), filename),
		retries:          3,
		dnsServer:        ip,
		dnsPort:          port,
		maxDownloadBytes: defaultMaxDownloadBytes,
		cacheDir:         cacheDir,
		noResume:         true,
	}
	if err := downloadFile(resolver, cfg); err != nil {
		t.Fatalf("downloadFile with -no-resume should succeed despite poisoned cache, got %v", err)
	}
}

// discoverChunkCount issues a dinit DNS query against the test server and
// parses the chunk-count response — used by resume tests that need to
// pre-seed a cache with the exact shape downloadFile will discover.
func discoverChunkCount(t *testing.T, resolver *txtResolver, domain, pass, filename string) int {
	t.Helper()
	sid, err := protocol.NewSID()
	if err != nil {
		t.Fatal(err)
	}
	labels, err := protocol.EncodeFilenameLabels(filename)
	if err != nil {
		t.Fatal(err)
	}
	initArgs := append([]string{sid}, labels...)
	name := authenticatedName(pass, domain, "dinit", initArgs)
	resp, err := resolver.query(name)
	if err != nil {
		t.Fatalf("dinit: %v", err)
	}
	var n int
	if _, err := fmt.Sscanf(resp, "%d", &n); err != nil || n <= 0 {
		t.Fatalf("dinit response not a chunk count: %q", resp)
	}
	return n
}

// TestFormatBPS pins the three branches of the human-readable rate
// formatter — B/s, KB/s, MB/s — so the progress-bar text stays stable.
func TestFormatBPS(t *testing.T) {
	cases := []struct {
		bps  float64
		want string
	}{
		{0, "0 B/s"},
		{500, "500 B/s"},
		{1024, "1.0 KB/s"},
		{1536, "1.5 KB/s"},
		{1024 * 1024, "1.0 MB/s"},
		{2.5 * 1024 * 1024, "2.5 MB/s"},
	}
	for _, c := range cases {
		if got := formatBPS(c.bps); got != c.want {
			t.Errorf("formatBPS(%v) = %q want %q", c.bps, got, c.want)
		}
	}
}

// TestFormatETA covers all three branches: hours, minutes, seconds.
func TestFormatETA(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{5 * time.Second, "5s"},
		{90 * time.Second, "1m30s"},
		{2*time.Hour + 5*time.Minute, "2h05m"},
	}
	for _, c := range cases {
		if got := formatETA(c.d); got != c.want {
			t.Errorf("formatETA(%v) = %q want %q", c.d, got, c.want)
		}
	}
}

// jsonRoundtrip is a sanity sentinel that catches drift between the on-disk
// meta.json schema and the resumeMeta struct. The shape is asserted directly
// instead of going through json.Marshal because the test runs frequently and
// schema changes should be intentional.
func TestResumeMetaSchema(t *testing.T) {
	raw, err := json.Marshal(resumeMeta{ChunkCount: 7, BatchSize: 2, SourceSHA256: testSourceSHA256})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != `{"chunk_count":7,"batch_size":2,"source_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}` {
		t.Fatalf("meta json shape changed: %s", got)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
