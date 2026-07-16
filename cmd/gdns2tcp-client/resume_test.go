package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const testSourceSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestResumeCacheSingleSpoolRoundTrip(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	const (
		chunks = 4
		batch  = 2
		size   = int64(chunks*codecTXTChunkSize - 17)
	)
	completed, err := c.open(chunks, batch, testSourceSHA256, size)
	if err != nil || len(completed) != 0 {
		t.Fatalf("open fresh = %v, %v", completed, err)
	}
	first := string(make([]byte, batch*codecTXTChunkSize))
	last := string(make([]byte, int(size)-batch*codecTXTChunkSize))
	if err := c.saveBatch(0, 0, batch, first); err != nil {
		t.Fatal(err)
	}
	if err := c.saveBatch(1, 2, batch, last); err != nil {
		t.Fatal(err)
	}
	if err := c.sync(); err != nil {
		t.Fatal(err)
	}
	if err := c.close(); err != nil {
		t.Fatal(err)
	}

	resumed := newResumeCache(root, "example.com", "file.bin", true)
	completed, err = resumed.open(chunks, batch, testSourceSHA256, size)
	if err != nil {
		t.Fatal(err)
	}
	if len(completed) != 2 {
		t.Fatalf("completed batches=%v, want 2", completed)
	}
	info, err := os.Stat(resumed.path())
	if err != nil || info.Size() != size {
		t.Fatalf("spool stat = %v, %v", info, err)
	}
	entries, err := os.ReadDir(resumed.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 { // payload.b64, bitmap, meta
		t.Fatalf("resume cache file count=%d, want 3", len(entries))
	}
}

func TestResumeCheckpointNeverPublishesBitmapBeforePayloadSync(t *testing.T) {
	c := newResumeCache(t.TempDir(), "example.com", "durable.bin", true)
	if _, err := c.open(2, 1, testSourceSHA256, 2*codecTXTChunkSize); err != nil {
		t.Fatal(err)
	}
	defer c.close()
	c.lastCheckpoint = time.Now().Add(-3 * time.Second)
	c.checkpointHook = func(stage string) error {
		if stage == "spool-sync" {
			return errors.New("simulated crash before payload sync")
		}
		return nil
	}
	if err := c.saveBatch(0, 0, 1, string(make([]byte, codecTXTChunkSize))); err == nil {
		t.Fatal("fault hook did not stop the checkpoint")
	}
	onDisk, err := os.ReadFile(c.bitmapPath)
	if err != nil {
		t.Fatal(err)
	}
	if onDisk[0]&1 != 0 {
		t.Fatal("durable bitmap advanced before payload sync")
	}

	var order []string
	c.checkpointHook = func(stage string) error {
		order = append(order, stage)
		return nil
	}
	if err := c.sync(); err != nil {
		t.Fatal(err)
	}
	want := []string{"spool-sync", "bitmap-write", "bitmap-sync"}
	if len(order) != len(want) {
		t.Fatalf("checkpoint order=%v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("checkpoint order=%v, want %v", order, want)
		}
	}
	onDisk, err = os.ReadFile(c.bitmapPath)
	if err != nil || onDisk[0]&1 == 0 {
		t.Fatalf("checkpoint bitmap=%08b, err=%v", onDisk[0], err)
	}
}

func TestResumeDisabledAndValidationBranches(t *testing.T) {
	disabled := newResumeCache("", "example.com", "x", false)
	if completed, err := disabled.open(1, 1, testSourceSHA256, 1); err != nil || len(completed) != 0 {
		t.Fatalf("disabled open=%v err=%v", completed, err)
	}
	if err := disabled.saveBatch(0, 0, 1, "x"); err != nil {
		t.Fatal(err)
	}
	if err := disabled.sync(); err != nil {
		t.Fatal(err)
	}
	if err := disabled.clear(); err != nil {
		t.Fatal(err)
	}
	if err := disabled.acquireLock(); err != nil {
		t.Fatal(err)
	}
	if err := disabled.acquireQuotaLock(); err != nil {
		t.Fatal(err)
	}
	if disabled.completedLocked(-1) || disabled.completedLocked(0) {
		t.Fatal("empty bitmap reported a completed batch")
	}

	c := newResumeCache(t.TempDir(), "example.com", "invalid.bin", true)
	for _, args := range []struct {
		chunks, batch int
		digest        string
		size          int64
	}{{0, 1, testSourceSHA256, 1}, {1, 0, testSourceSHA256, 1}, {1, 1, "", 1}, {1, 1, testSourceSHA256, 0}} {
		if _, err := c.open(args.chunks, args.batch, args.digest, args.size); err == nil {
			t.Fatalf("invalid metadata accepted: %+v", args)
		}
	}
	if err := c.saveBatch(0, 0, 1, "x"); err == nil {
		t.Fatal("save without open succeeded")
	}
}

func TestResumeCheckpointAndFileHelperErrorBranches(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "hooks.bin", true)
	if _, err := c.open(1, 1, testSourceSHA256, codecTXTChunkSize); err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if _, err := c.expectedBatchLength(-1, 0, 1); err == nil {
		t.Fatal("negative batch accepted")
	}
	if _, err := c.expectedBatchLength(0, 1, 1); err == nil {
		t.Fatal("out-of-range offset accepted")
	}
	if err := c.saveBatch(0, 0, 1, "short"); err == nil {
		t.Fatal("short batch accepted")
	}
	if err := c.saveBatch(0, 0, 1, string(make([]byte, codecTXTChunkSize))); err != nil {
		t.Fatal(err)
	}
	c.checkpointHook = func(stage string) error {
		if stage == "bitmap-write" {
			return errors.New("bitmap write fault")
		}
		return nil
	}
	if err := c.sync(); err == nil {
		t.Fatal("bitmap-write hook error ignored")
	}
	c.checkpointHook = func(stage string) error {
		if stage == "bitmap-sync" {
			return errors.New("bitmap sync fault")
		}
		return nil
	}
	if err := c.sync(); err == nil {
		t.Fatal("bitmap-sync hook error ignored")
	}
	c.checkpointHook = nil

	path := filepath.Join(root, "atomic")
	if err := writeFileAtomic(path, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(filepath.Join(root, "missing", "x"), []byte("x")); err == nil {
		t.Fatal("atomic write into missing directory succeeded")
	}
	if err := writeAtAllFile(path, []byte("Z"), 1); err != nil {
		t.Fatal(err)
	}
	if err := writeAtAllFile(filepath.Join(root, "absent"), []byte("x"), 0); err == nil {
		t.Fatal("writeAtAllFile missing path succeeded")
	}
}

func TestResumeCacheShapeMismatchStartsFresh(t *testing.T) {
	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	if _, err := c.open(4, 2, testSourceSHA256, 1000); err != nil {
		t.Fatal(err)
	}
	if err := c.saveBatch(0, 0, 2, string(make([]byte, 508))); err != nil {
		t.Fatal(err)
	}
	_ = c.close()

	fresh := newResumeCache(root, "example.com", "file.bin", true)
	completed, err := fresh.open(5, 2, testSourceSHA256, 1200)
	if err != nil {
		t.Fatal(err)
	}
	if len(completed) != 0 {
		t.Fatalf("mismatched cache reused batches: %v", completed)
	}
}

func TestResumeCacheDisabledAndClear(t *testing.T) {
	disabled := newResumeCache(t.TempDir(), "example.com", "file.bin", false)
	completed, err := disabled.open(1, 1, testSourceSHA256, 10)
	if err != nil || len(completed) != 0 {
		t.Fatalf("disabled open = %v, %v", completed, err)
	}
	if err := disabled.clear(); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	c := newResumeCache(root, "example.com", "file.bin", true)
	if _, err := c.open(1, 1, testSourceSHA256, 10); err != nil {
		t.Fatal(err)
	}
	if err := c.clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache dir remains after clear: %v", err)
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

func TestPruneResumeCacheExpiresAndEnforcesQuota(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, "old")
	freshDir := filepath.Join(root, "fresh")
	for _, dir := range []string{oldDir, freshDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(oldDir, "payload.b64"), make([]byte, 20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(freshDir, "payload.b64"), make([]byte, 20), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(filepath.Join(oldDir, "payload.b64"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(oldDir, old, old); err != nil {
		t.Fatal(err)
	}
	if err := pruneResumeCache(root, 30, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired cache dir retained: %v", err)
	}
	if _, err := os.Stat(freshDir); err != nil {
		t.Fatalf("fresh cache dir removed: %v", err)
	}

	// Add a second live entry.  The old live entry is evicted first to keep
	// the root within quota, leaving the most recently touched spool intact.
	newerDir := filepath.Join(root, "newer")
	if err := os.Mkdir(newerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newerDir, "payload.b64"), make([]byte, 20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(freshDir, "payload.b64"), time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(freshDir, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := pruneResumeCache(root, 25, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(freshDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oldest live cache dir retained: %v", err)
	}
	if _, err := os.Stat(newerDir); err != nil {
		t.Fatalf("newest cache dir removed: %v", err)
	}
}

func TestPruneResumeCacheReservesBeforeSpoolCreation(t *testing.T) {
	root := t.TempDir()
	oldDir := filepath.Join(root, "old")
	if err := os.Mkdir(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "payload.b64"), make([]byte, 40), 0o600); err != nil {
		t.Fatal(err)
	}
	preserve := filepath.Join(root, "not-created-yet")
	if err := pruneResumeCacheFor(root, 100, 24*time.Hour, 80, preserve); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old entry was not evicted for the incoming reservation: %v", err)
	}
	if _, err := os.Stat(preserve); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pruning unexpectedly created the reserved entry: %v", err)
	}
	if err := pruneResumeCacheFor(root, 100, 24*time.Hour, 101, preserve); err == nil {
		t.Fatal("reservation larger than quota unexpectedly succeeded")
	}
}

func TestResumeQuotaSubprocessChild(t *testing.T) {
	root := os.Getenv("GDNS_RESUME_QUOTA_CHILD_ROOT")
	if root == "" {
		t.Skip("subprocess helper")
	}
	id := os.Getenv("GDNS_RESUME_QUOTA_CHILD_ID")
	cache := newResumeCache(root, "example.com", id+".bin", true)
	if err := cache.acquireLock(); err != nil {
		os.Exit(43)
	}
	defer cache.close()
	if err := cache.acquireQuotaLock(); err != nil {
		os.Exit(43)
	}
	const encodedSize = int64(60 << 10)
	if err := pruneResumeCacheForLocked(root, 100<<10, time.Hour, encodedSize, cache.dir); err != nil {
		os.Exit(42)
	}
	chunks := int((encodedSize + codecTXTChunkSize - 1) / codecTXTChunkSize)
	if _, err := cache.open(chunks, 1, testSourceSHA256, encodedSize); err != nil {
		os.Exit(43)
	}
	if err := cache.releaseQuotaLock(); err != nil {
		os.Exit(43)
	}
	// Keep the per-transfer lock while the other process acquires the quota
	// lock and attempts its nonblocking foreign-transfer eviction.
	time.Sleep(750 * time.Millisecond)
}

func TestResumeQuotaSerializedAcrossProcesses(t *testing.T) {
	root := t.TempDir()
	commands := make([]*exec.Cmd, 2)
	for i := range commands {
		cmd := exec.Command(os.Args[0], "-test.run=^TestResumeQuotaSubprocessChild$")
		cmd.Env = append(os.Environ(),
			"GDNS_RESUME_QUOTA_CHILD_ROOT="+root,
			fmt.Sprintf("GDNS_RESUME_QUOTA_CHILD_ID=%d", i),
		)
		commands[i] = cmd
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	var successes, quotaErrors int
	for _, cmd := range commands {
		err := cmd.Wait()
		if err == nil {
			successes++
			continue
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 42 {
			quotaErrors++
			continue
		}
		t.Fatalf("quota child failed unexpectedly: %v", err)
	}
	if successes != 1 || quotaErrors != 1 {
		t.Fatalf("successes=%d quota errors=%d, want one each", successes, quotaErrors)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		bytes, _, err := resumeDirStats(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		total += bytes
	}
	if total > 100<<10 {
		t.Fatalf("logical resume size=%d exceeds quota", total)
	}
}

func TestResumeCacheLockPreventsConcurrentMutation(t *testing.T) {
	root := t.TempDir()
	first := newResumeCache(root, "example.com", "locked.bin", true)
	if err := first.acquireLock(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(first.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if removeResumeCacheDir(first.dir) {
		t.Fatal("pruner removed an actively locked resume directory")
	}

	second := newResumeCache(root, "example.com", "locked.bin", true)
	acquired := make(chan error, 1)
	go func() { acquired <- second.acquireLock() }()
	select {
	case err := <-acquired:
		t.Fatalf("second cache acquired an active lock early: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := first.releaseLock(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("second cache did not acquire released lock: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second cache remained blocked after lock release")
	}
	if err := second.releaseLock(); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadFileStreamingResumeCleanup(t *testing.T) {
	dataDir := t.TempDir()
	ip, port := startEmbeddedServer(t, newServerCfg(t, dataDir))
	resolver := &txtResolver{server: ip, port: port, retries: 3}
	payload := make([]byte, 9000)
	for i := range payload {
		payload[i] = byte(i * 37 % 251)
	}
	filename := "resume-streaming.bin"
	if err := os.WriteFile(filepath.Join(dataDir, filename), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDir := t.TempDir()
	cfg := config{
		domain: "files.test", pass: "integration-test-secret", filename: filename,
		outFile: filepath.Join(t.TempDir(), filename), retries: 3, dnsServer: ip, dnsPort: port,
		maxDownloadBytes: defaultMaxDownloadBytes, cacheDir: cacheDir,
	}
	if err := downloadFile(resolver, cfg); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	got, err := os.ReadFile(cfg.outFile)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("download output mismatch: %v", err)
	}
	cache := newResumeCache(cacheDir, cfg.domain, cfg.filename, true)
	if _, err := os.Stat(cache.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resume cache should be cleared after success: %v", err)
	}
}

func TestFormatBPS(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{{0, "0 B/s"}, {1536, "1.5 KB/s"}, {2.5 * 1024 * 1024, "2.5 MB/s"}} {
		if got := formatBPS(tc.in); got != tc.want {
			t.Fatalf("formatBPS(%v)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestFormatETA(t *testing.T) {
	if got := formatETA(2*time.Hour + 5*time.Minute); got != "2h05m" {
		t.Fatalf("formatETA=%q", got)
	}
	if got := formatETA(3*time.Minute + 4*time.Second); got != "3m04s" {
		t.Fatalf("minute formatETA=%q", got)
	}
	if got := formatETA(9 * time.Second); got != "9s" {
		t.Fatalf("second formatETA=%q", got)
	}
}

func TestResumeMetaSchema(t *testing.T) {
	raw, err := json.Marshal(resumeMeta{ChunkCount: 7, BatchSize: 2, BatchCount: 4, EncodedSize: 1234, SourceSHA256: testSourceSHA256})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"chunk_count":7,"batch_size":2,"batch_count":4,"encoded_size":1234,"source_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}` {
		t.Fatalf("meta json shape changed: %s", raw)
	}
}

func TestResumeDisabledAndResourceErrorBranches(t *testing.T) {
	disabled := newResumeCache(t.TempDir(), "files.test", "file.bin", false)
	completed, err := disabled.open(1, 1, "digest", 1)
	if err != nil || len(completed) != 0 {
		t.Fatalf("disabled open completed=%v err=%v", completed, err)
	}
	if err := disabled.acquireLock(); err != nil {
		t.Fatal(err)
	}
	if err := disabled.acquireQuotaLock(); err != nil {
		t.Fatal(err)
	}
	if err := disabled.clear(); err != nil {
		t.Fatal(err)
	}
	if err := disabled.releaseLock(); err != nil {
		t.Fatal(err)
	}
	if err := disabled.releaseQuotaLock(); err != nil {
		t.Fatal(err)
	}

	enabled := newResumeCache(t.TempDir(), "files.test", "file.bin", true)
	if _, err := enabled.open(0, 1, "digest", 1); err == nil {
		t.Fatal("invalid resume metadata accepted")
	}
	bitmapOnly, err := os.CreateTemp(t.TempDir(), "bitmap")
	if err != nil {
		t.Fatal(err)
	}
	enabled.bitmapFile = bitmapOnly
	if err := enabled.closeSpool(); err != nil || enabled.bitmapFile != nil {
		t.Fatalf("bitmap-only close err=%v file=%v", err, enabled.bitmapFile)
	}
	enabled.dir = ""
	if err := enabled.clearFiles(); err != nil {
		t.Fatal(err)
	}

	missingDir := filepath.Join(t.TempDir(), "missing", "child")
	if err := writeFileAtomic(filepath.Join(missingDir, "meta"), []byte("x")); err == nil {
		t.Fatal("atomic write into missing directory succeeded")
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	if err := writeAtAll(closed, []byte("x"), 0); err == nil {
		t.Fatal("writeAtAll on closed file succeeded")
	}
	if err := writeAtAllFile(filepath.Join(t.TempDir(), "missing"), []byte("x"), 0); err == nil {
		t.Fatal("writeAtAllFile on missing file succeeded")
	}
}
