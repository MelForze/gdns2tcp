package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// resumeCache persists already-fetched download batches on disk so an
// interrupted download can pick up where it left off. It is layered above the
// existing chunk protocol: the server is told to re-prepare the file via
// `dinit` on every run; the cache only short-circuits the per-batch DNS
// queries for batches whose base64 payload is already on disk.
type resumeCache struct {
	dir     string
	enabled bool
}

type resumeMeta struct {
	ChunkCount   int    `json:"chunk_count"`
	BatchSize    int    `json:"batch_size"`
	SourceSHA256 string `json:"source_sha256"`
}

// newResumeCache returns a cache scoped to the (domain, filename) pair. When
// enabled is false (or no cache root is available), the returned cache
// silently no-ops: callers do not need to special-case the disabled path.
func newResumeCache(root, domain, filename string, enabled bool) *resumeCache {
	if !enabled || root == "" {
		return &resumeCache{enabled: false}
	}
	sum := sha256.Sum256([]byte(domain + "|" + filename))
	id := hex.EncodeToString(sum[:])[:16]
	return &resumeCache{
		dir:     filepath.Join(root, id),
		enabled: true,
	}
}

// defaultResumeRoot returns <UserCacheDir>/gdns2tcp or "" if the OS does not
// expose a per-user cache directory (rare; e.g. unset $HOME inside a
// container). An empty return value disables the cache cleanly.
func defaultResumeRoot() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, "gdns2tcp")
}

// loadCompleted returns the map of batchIdx → base64 payload for batches
// already present on disk. If meta.json's recorded shape or source digest does
// not match the current dinit/dmeta, the entire cache directory is wiped and an
// empty map is returned so the download proceeds from scratch.
func (c *resumeCache) loadCompleted(chunkCount, batchSize int, sourceSHA256 string) (map[int]string, error) {
	if !c.enabled {
		return map[int]string{}, nil
	}
	if sourceSHA256 == "" {
		_ = os.RemoveAll(c.dir)
		return map[int]string{}, nil
	}
	metaPath := filepath.Join(c.dir, "meta.json")
	raw, err := os.ReadFile(metaPath)
	if errors.Is(err, os.ErrNotExist) {
		// No meta yet — either fresh start or interrupted before meta wrote.
		// Either way, ignore any stray batch-* files for safety.
		_ = os.RemoveAll(c.dir)
		return map[int]string{}, nil
	}
	if err != nil {
		return map[int]string{}, nil
	}
	var meta resumeMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		_ = os.RemoveAll(c.dir)
		return map[int]string{}, nil
	}
	if meta.ChunkCount != chunkCount || meta.BatchSize != batchSize || meta.SourceSHA256 != sourceSHA256 {
		_ = os.RemoveAll(c.dir)
		return map[int]string{}, nil
	}

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return map[int]string{}, nil
	}
	batchRE := regexp.MustCompile(`^batch-(\d+)$`)
	completed := make(map[int]string, len(entries))
	for _, e := range entries {
		m := batchRE.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		idx, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.dir, e.Name()))
		if err != nil {
			continue
		}
		completed[idx] = string(data)
	}
	return completed, nil
}

// saveMeta writes the meta.json file describing the current download's shape.
// Called once at the start of a run after chunkCount, batchSize, and source
// digest are known.
func (c *resumeCache) saveMeta(chunkCount, batchSize int, sourceSHA256 string) error {
	if !c.enabled {
		return nil
	}
	if sourceSHA256 == "" {
		return nil
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("create resume cache: %w", err)
	}
	raw, err := json.Marshal(resumeMeta{ChunkCount: chunkCount, BatchSize: batchSize, SourceSHA256: sourceSHA256})
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(c.dir, "meta.json"), raw)
}

// saveBatch atomically persists the base64 payload for one completed batch.
// Safe to call concurrently from multiple goroutines for different k values.
func (c *resumeCache) saveBatch(k int, data string) error {
	if !c.enabled {
		return nil
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("batch-%06d", k)
	return writeFileAtomic(filepath.Join(c.dir, name), []byte(data))
}

// clear removes the cache directory entirely. Called after a successful
// end-to-end download so completed transfers leave no residue.
func (c *resumeCache) clear() error {
	if !c.enabled {
		return nil
	}
	return os.RemoveAll(c.dir)
}

// writeFileAtomic writes data via a temp file in the same directory and then
// renames it into place. Eliminates the half-written-file class of bugs if the
// process is killed mid-write.
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
