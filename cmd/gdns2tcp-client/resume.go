package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// resumeCache keeps a single preallocated encoded spool plus a compact bitmap
// of completed DNS batches.  The old one-file-per-batch scheme created tens
// of thousands of files for a moderately sized download and also rebuilt the
// full payload in RAM before decrypting it.
type resumeCache struct {
	root      string
	dir       string
	enabled   bool
	lockPath  string
	lock      *resumeFileLock
	quotaLock *resumeFileLock

	mu             sync.Mutex
	spool          *os.File
	bitmapFile     *os.File
	spoolPath      string
	bitmapPath     string
	bitmap         []byte
	meta           resumeMeta
	dirtyBatches   int
	lastCheckpoint time.Time
	checkpointHook func(string) error
}

type resumeCacheDir struct {
	path     string
	bytes    int64
	modified time.Time
}

type resumeMeta struct {
	ChunkCount   int    `json:"chunk_count"`
	BatchSize    int    `json:"batch_size"`
	BatchCount   int    `json:"batch_count"`
	EncodedSize  int64  `json:"encoded_size"`
	SourceSHA256 string `json:"source_sha256"`
}

func newResumeCache(root, domain, filename string, enabled bool) *resumeCache {
	if !enabled || root == "" {
		return &resumeCache{enabled: false}
	}
	sum := sha256.Sum256([]byte(domain + "|" + filename))
	id := hex.EncodeToString(sum[:])[:16]
	dir := filepath.Join(root, id)
	return &resumeCache{root: root, dir: dir, lockPath: dir + ".lock", enabled: true}
}

func defaultResumeRoot() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, "gdns2tcp")
}

// pruneResumeCache keeps abandoned resumable transfers from slowly filling a
// user's cache.  Only direct children of root are considered, so a malformed
// or unrelated path can never make this routine walk outside gdns2tcp's own
// cache namespace.  Active transfers touch their directory on open and are
// therefore retained unless the quota cannot be met otherwise.
func pruneResumeCache(root string, maxBytes int64, ttl time.Duration) error {
	return pruneResumeCacheFor(root, maxBytes, ttl, 0, "")
}

func pruneResumeCacheFor(root string, maxBytes int64, ttl time.Duration, reserveBytes int64, preserve string) error {
	if root == "" {
		return nil
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	lock, err := acquireResumeFileLock(filepath.Join(root, ".quota.lock"), false)
	if err != nil {
		return fmt.Errorf("lock resume quota: %w", err)
	}
	defer lock.release()
	return pruneResumeCacheForLocked(root, maxBytes, ttl, reserveBytes, preserve)
}

func pruneResumeCacheForLocked(root string, maxBytes int64, ttl time.Duration, reserveBytes int64, preserve string) error {
	if root == "" || maxBytes <= 0 || ttl <= 0 {
		return nil
	}
	if reserveBytes > maxBytes {
		return fmt.Errorf("resume entry needs %d bytes, cache quota is %d", reserveBytes, maxBytes)
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	now := time.Now()
	var total int64
	var preserveBytes int64
	dirs := make([]resumeCacheDir, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name())
		bytes, modified, sizeErr := resumeDirStats(path)
		if sizeErr != nil {
			continue
		}
		if path != preserve && now.Sub(modified) > ttl {
			if removeResumeCacheDir(path) {
				continue
			}
		}
		if path == preserve {
			preserveBytes = bytes
		}
		total += bytes
		dirs = append(dirs, resumeCacheDir{path: path, bytes: bytes, modified: modified})
	}
	if reserveBytes > preserveBytes {
		total += reserveBytes - preserveBytes
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].modified.Before(dirs[j].modified) })
	for _, entry := range dirs {
		if total <= maxBytes {
			break
		}
		if entry.path == preserve {
			continue
		}
		if removeResumeCacheDir(entry.path) {
			total -= entry.bytes
		}
	}
	if total > maxBytes {
		return fmt.Errorf("resume cache quota unavailable: need %d bytes, limit %d", total, maxBytes)
	}
	return nil
}

func removeResumeCacheDir(path string) bool {
	lock, err := acquireResumeFileLock(path+".lock", true)
	if err != nil {
		return false
	}
	defer lock.release()
	return os.RemoveAll(path) == nil
}

func resumeDirStats(root string) (int64, time.Time, error) {
	info, err := os.Stat(root)
	if err != nil {
		return 0, time.Time{}, err
	}
	bytes := int64(0)
	modified := info.ModTime()
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		bytes += fileInfo.Size()
		if fileInfo.ModTime().After(modified) {
			modified = fileInfo.ModTime()
		}
		return nil
	})
	return bytes, modified, err
}

// open validates/reuses a previous spool or atomically creates a fresh one.
// It returns the completed batch indexes represented in the bitmap.
func (c *resumeCache) open(chunkCount, batchSize int, sourceSHA256 string, encodedSize int64) (map[int]struct{}, error) {
	completed := make(map[int]struct{})
	if !c.enabled {
		return completed, nil
	}
	if chunkCount <= 0 || batchSize <= 0 || sourceSHA256 == "" || encodedSize <= 0 {
		return nil, errors.New("invalid resume metadata")
	}
	if err := c.acquireLock(); err != nil {
		return nil, err
	}
	ownedQuota := c.quotaLock == nil
	if err := c.acquireQuotaLock(); err != nil {
		return nil, err
	}
	if ownedQuota {
		defer c.releaseQuotaLock()
	}
	batchCount := (chunkCount + batchSize - 1) / batchSize
	want := resumeMeta{ChunkCount: chunkCount, BatchSize: batchSize, BatchCount: batchCount, EncodedSize: encodedSize, SourceSHA256: sourceSHA256}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, err
	}
	c.spoolPath = filepath.Join(c.dir, "payload.b64")
	c.bitmapPath = filepath.Join(c.dir, "batches.bitmap")
	metaPath := filepath.Join(c.dir, "meta.json")

	valid := false
	if raw, err := os.ReadFile(metaPath); err == nil {
		var current resumeMeta
		if json.Unmarshal(raw, &current) == nil && current == want {
			if info, statErr := os.Stat(c.spoolPath); statErr == nil && info.Size() == encodedSize {
				if bitmap, readErr := os.ReadFile(c.bitmapPath); readErr == nil && len(bitmap) == bitmapBytes(batchCount) {
					c.bitmap = bitmap
					valid = true
				}
			}
		}
	}
	if !valid {
		if err := c.clearFiles(); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(c.dir, 0o700); err != nil {
			return nil, err
		}
		c.bitmap = make([]byte, bitmapBytes(batchCount))
		if err := writeFileAtomic(metaPath, mustJSON(want)); err != nil {
			return nil, err
		}
		if err := os.WriteFile(c.bitmapPath, c.bitmap, 0o600); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(c.spoolPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if !valid {
		if err := f.Truncate(encodedSize); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	c.spool = f
	bitmapFile, err := os.OpenFile(c.bitmapPath, os.O_RDWR, 0o600)
	if err != nil {
		_ = f.Close()
		c.spool = nil
		return nil, err
	}
	c.bitmapFile = bitmapFile
	c.meta = want
	c.dirtyBatches = 0
	c.lastCheckpoint = time.Now()
	_ = os.Chtimes(c.dir, time.Now(), time.Now())
	for batch := 0; batch < batchCount; batch++ {
		if c.completedLocked(batch) {
			completed[batch] = struct{}{}
		}
	}
	return completed, nil
}

func mustJSON(meta resumeMeta) []byte {
	raw, err := json.Marshal(meta)
	if err != nil {
		panic(err)
	}
	return raw
}

func bitmapBytes(batchCount int) int { return (batchCount + 7) / 8 }

func (c *resumeCache) completedLocked(batch int) bool {
	return batch >= 0 && batch/8 < len(c.bitmap) && c.bitmap[batch/8]&(1<<uint(batch%8)) != 0
}

func (c *resumeCache) expectedBatchLength(batch, from, count int) (int, error) {
	if batch < 0 || batch >= c.meta.BatchCount || from < 0 || count <= 0 {
		return 0, errors.New("invalid batch")
	}
	offset := int64(from) * int64(codecTXTChunkSize)
	if offset < 0 || offset >= c.meta.EncodedSize {
		return 0, errors.New("batch offset out of range")
	}
	length := int64(count) * int64(codecTXTChunkSize)
	if remaining := c.meta.EncodedSize - offset; remaining < length {
		length = remaining
	}
	if length <= 0 || length > int64(^uint(0)>>1) {
		return 0, errors.New("batch length out of range")
	}
	return int(length), nil
}

// codecTXTChunkSize avoids importing internal/codec in this persistence-only
// file just to use a protocol constant.  It is kept equal to codec.TXTChunkSize.
const codecTXTChunkSize = 254

func (c *resumeCache) saveBatch(batch, from, count int, data string) error {
	if !c.enabled {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.spool == nil {
		return errors.New("resume spool is not open")
	}
	want, err := c.expectedBatchLength(batch, from, count)
	if err != nil {
		return err
	}
	if len(data) != want {
		return fmt.Errorf("batch %d length %d, want %d", batch, len(data), want)
	}
	offset := int64(from) * int64(codecTXTChunkSize)
	if err := writeAtAll(c.spool, []byte(data), offset); err != nil {
		return err
	}
	c.bitmap[batch/8] |= 1 << uint(batch%8)
	c.dirtyBatches++
	if c.dirtyBatches >= 256 || time.Since(c.lastCheckpoint) >= 2*time.Second {
		return c.checkpointLocked()
	}
	return nil
}

func (c *resumeCache) sync() error {
	if !c.enabled {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkpointLocked()
}

func (c *resumeCache) checkpointLocked() error {
	if c.spool == nil {
		return nil
	}
	if c.checkpointHook != nil {
		if err := c.checkpointHook("spool-sync"); err != nil {
			return err
		}
	}
	if err := c.spool.Sync(); err != nil {
		return err
	}
	if c.bitmapFile == nil {
		return errors.New("resume bitmap is not open")
	}
	if c.dirtyBatches > 0 {
		if c.checkpointHook != nil {
			if err := c.checkpointHook("bitmap-write"); err != nil {
				return err
			}
		}
		if err := writeAtAll(c.bitmapFile, c.bitmap, 0); err != nil {
			return err
		}
	}
	if c.checkpointHook != nil {
		if err := c.checkpointHook("bitmap-sync"); err != nil {
			return err
		}
	}
	if err := c.bitmapFile.Sync(); err != nil {
		return err
	}
	c.dirtyBatches = 0
	c.lastCheckpoint = time.Now()
	return nil
}

func (c *resumeCache) path() string { return c.spoolPath }

func (c *resumeCache) close() error {
	err := c.closeSpool()
	quotaErr := c.releaseQuotaLock()
	lockErr := c.releaseLock()
	if err != nil {
		return err
	}
	if quotaErr != nil {
		return quotaErr
	}
	return lockErr
}

func (c *resumeCache) closeSpool() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.spool == nil {
		if c.bitmapFile != nil {
			err := c.bitmapFile.Close()
			c.bitmapFile = nil
			return err
		}
		return nil
	}
	syncErr := c.checkpointLocked()
	err := c.spool.Close()
	c.spool = nil
	bitmapErr := error(nil)
	if c.bitmapFile != nil {
		bitmapErr = c.bitmapFile.Close()
		c.bitmapFile = nil
	}
	if syncErr != nil {
		return syncErr
	}
	if err == nil {
		err = bitmapErr
	}
	return err
}

func (c *resumeCache) acquireLock() error {
	if !c.enabled || c.lock != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.dir), 0o700); err != nil {
		return err
	}
	lock, err := acquireResumeFileLock(c.lockPath, false)
	if err != nil {
		return fmt.Errorf("lock resume cache: %w", err)
	}
	c.lock = lock
	return nil
}

func (c *resumeCache) releaseLock() error {
	if c.lock == nil {
		return nil
	}
	err := c.lock.release()
	c.lock = nil
	return err
}

func (c *resumeCache) acquireQuotaLock() error {
	if !c.enabled || c.quotaLock != nil {
		return nil
	}
	if err := os.MkdirAll(c.root, 0o700); err != nil {
		return err
	}
	lock, err := acquireResumeFileLock(filepath.Join(c.root, ".quota.lock"), false)
	if err != nil {
		return fmt.Errorf("lock resume quota: %w", err)
	}
	c.quotaLock = lock
	return nil
}

func (c *resumeCache) releaseQuotaLock() error {
	if c.quotaLock == nil {
		return nil
	}
	err := c.quotaLock.release()
	c.quotaLock = nil
	return err
}

func (c *resumeCache) clear() error {
	_ = c.closeSpool()
	if !c.enabled {
		return nil
	}
	return c.clearFiles()
}

func (c *resumeCache) clearFiles() error {
	if c.dir == "" {
		return nil
	}
	return os.RemoveAll(c.dir)
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func writeAtAll(f *os.File, data []byte, offset int64) error {
	for len(data) > 0 {
		n, err := f.WriteAt(data, offset)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
		offset += int64(n)
	}
	return nil
}

func writeAtAllFile(path string, data []byte, offset int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	err = writeAtAll(f, data, offset)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
