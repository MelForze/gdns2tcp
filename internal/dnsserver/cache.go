package dnsserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gdns2tcp/internal/codec"
	secure "gdns2tcp/internal/crypto"
)

type diskCacheMeta struct {
	Key         string `json:"key"`
	Spool       string `json:"spool"`
	MTimeUnixNs int64  `json:"mtime_unix_ns"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	EncodedSize int64  `json:"encoded_size"`
	ChunkCount  int    `json:"chunk_count"`
	LastAccess  int64  `json:"last_access_unix_ns"`
	Expires     int64  `json:"expires_unix_ns"`
}

const cacheMetaTouchInterval = time.Minute

// cleanupOrphanCacheFiles reconciles files that cannot be reached from cache
// metadata. These are left only by an interrupted build/publish sequence.
func (s *Server) cleanupOrphanCacheFiles() error {
	entries, err := os.ReadDir(s.cacheDir)
	if err != nil {
		return fmt.Errorf("read cache dir for reconciliation: %w", err)
	}
	for _, item := range entries {
		if item.IsDir() {
			continue
		}
		name := item.Name()
		if strings.HasPrefix(name, ".gdns2tcp-") {
			_ = os.Remove(filepath.Join(s.cacheDir, name))
			continue
		}
		if strings.HasSuffix(name, ".b64") {
			meta := strings.TrimSuffix(name, ".b64") + ".json"
			if _, err := os.Stat(filepath.Join(s.cacheDir, meta)); os.IsNotExist(err) {
				_ = os.Remove(filepath.Join(s.cacheDir, name))
			}
		}
	}
	return nil
}

func (s *Server) cleanupOrphanUploadFiles(_ time.Time) {
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return
	}
	for _, item := range entries {
		if item.IsDir() || !strings.HasPrefix(item.Name(), ".gdns2tcp-upload-") {
			continue
		}
		_ = os.Remove(filepath.Join(s.dataDir, item.Name()))
	}
}

func (s *Server) loadDownloadCache() error {
	entries, err := os.ReadDir(s.cacheDir)
	if err != nil {
		return fmt.Errorf("read cache dir: %w", err)
	}
	now := time.Now().UTC()
	for _, item := range entries {
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".json") {
			continue
		}
		metaPath := filepath.Join(s.cacheDir, item.Name())
		raw, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta diskCacheMeta
		if json.Unmarshal(raw, &meta) != nil || meta.Key == "" || meta.Spool == "" || meta.EncodedSize <= 0 || meta.ChunkCount <= 0 {
			_ = os.Remove(metaPath)
			continue
		}
		spoolPath := filepath.Join(s.cacheDir, filepath.Base(meta.Spool))
		info, err := os.Stat(spoolPath)
		if err != nil || info.Size() != meta.EncodedSize || !now.Before(time.Unix(0, meta.Expires)) {
			_ = os.Remove(metaPath)
			_ = os.Remove(spoolPath)
			continue
		}
		entry := downloadCacheEntry{
			spoolPath: spoolPath, metaPath: metaPath,
			mtime: time.Unix(0, meta.MTimeUnixNs), size: meta.Size, sha256: meta.SHA256,
			encodedSize: meta.EncodedSize, chunkCount: meta.ChunkCount,
			lastAccess: time.Unix(0, meta.LastAccess), expires: time.Unix(0, meta.Expires), lastMetaSave: now,
		}
		s.downloadCache[meta.Key] = entry
		s.downloadCacheBytes += entry.encodedSize
	}
	s.rebuildCacheOrderLocked()
	s.evictDownloadCacheLocked(now)
	return nil
}

func hashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.CopyBuffer(h, f, make([]byte, 64*1024))
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func downloadCacheKey(path, sourceSHA string) string {
	sum := sha256.Sum256([]byte(path + "|" + sourceSHA))
	return hex.EncodeToString(sum[:])
}

func cacheBuildReservation(sourceSize int64) int64 {
	const overhead = int64(1 << 20)
	if sourceSize <= 0 || sourceSize > (int64(^uint64(0)>>1)-overhead)/3 {
		return int64(^uint64(0) >> 1)
	}
	// At phase boundaries buildDownloadCache removes the previous temporary
	// file. Three source-sized files plus overhead is therefore a conservative
	// peak for snapshot/gzip/cipher/protected/base64 construction.
	return sourceSize*3 + overhead
}

func (s *Server) reserveCacheBuildLocked(bytes int64, now time.Time) bool {
	if bytes <= 0 || bytes > s.cacheMaxBytes {
		return false
	}
	s.evictDownloadCacheLocked(now)
	for s.downloadCacheBytes+s.downloadCacheReserved+bytes > s.cacheMaxBytes {
		removed := false
		for _, key := range append([]string(nil), s.downloadCacheOrder...) {
			entry, ok := s.downloadCache[key]
			if !ok || entry.active > 0 {
				continue
			}
			s.removeCacheLocked(key, entry)
			removed = true
			break
		}
		if !removed {
			return false
		}
	}
	s.downloadCacheReserved += bytes
	return true
}

func (s *Server) releaseCacheBuildLocked(bytes int64) {
	s.downloadCacheReserved -= bytes
	if s.downloadCacheReserved < 0 {
		s.downloadCacheReserved = 0
	}
}

func (s *Server) snapshotDownloadSource(path string, maxBytes int64) (snapshot string, size int64, digest string, err error) {
	in, err := os.Open(path)
	if err != nil {
		return "", 0, "", err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(s.cacheDir, ".gdns2tcp-source-*")
	if err != nil {
		return "", 0, "", err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	h := sha256.New()
	limited := &io.LimitedReader{R: in, N: maxBytes + 1}
	n, copyErr := io.CopyBuffer(io.MultiWriter(tmp, h), limited, make([]byte, 64*1024))
	if copyErr != nil {
		return "", 0, "", copyErr
	}
	if n > maxBytes {
		return "", 0, "", fmt.Errorf("source exceeds configured download limit")
	}
	if err := tmp.Close(); err != nil {
		return "", 0, "", err
	}
	ok = true
	return tmpName, n, hex.EncodeToString(h.Sum(nil)), nil
}

// prepareDownloadCache returns a cache entry and increments its active count.
// Callers must decrement it if they decide not to create a download state.
func (s *Server) prepareDownloadCache(path string, info os.FileInfo, now time.Time) (resultKey string, resultEntry downloadCacheEntry, resultErr error) {
	// Serialize the complete snapshot/hash/build operation per source path.
	// Waiting until after hashing would still let concurrent first requests
	// consume disk quota with duplicate snapshots of the same file.
	s.mu.Lock()
	if inFlight, ok := s.downloadCacheBuilds[path]; ok {
		done := inFlight.done
		s.mu.Unlock()
		<-done
		if inFlight.err != nil {
			return "", downloadCacheEntry{}, inFlight.err
		}
		return s.acquireExistingCache(inFlight.key, now)
	}
	build := &downloadCacheBuild{done: make(chan struct{})}
	s.downloadCacheBuilds[path] = build
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		build.key = resultKey
		build.err = resultErr
		delete(s.downloadCacheBuilds, path)
		close(build.done)
		s.mu.Unlock()
	}()

	reservation := cacheBuildReservation(info.Size())
	s.mu.Lock()
	if !s.reserveCacheBuildLocked(reservation, now) {
		s.mu.Unlock()
		return "", downloadCacheEntry{}, fmt.Errorf("download cache quota unavailable")
	}
	s.mu.Unlock()
	releaseReservation := true
	defer func() {
		if releaseReservation {
			s.mu.Lock()
			s.releaseCacheBuildLocked(reservation)
			s.mu.Unlock()
		}
	}()

	snapshot, size, sourceSHA, err := s.snapshotDownloadSource(path, s.maxDownloadBytes)
	if err != nil {
		return "", downloadCacheEntry{}, err
	}
	defer os.Remove(snapshot)
	actualReservation := cacheBuildReservation(size)
	if actualReservation != reservation {
		s.mu.Lock()
		s.releaseCacheBuildLocked(reservation)
		if !s.reserveCacheBuildLocked(actualReservation, now) {
			s.mu.Unlock()
			reservation = 0
			return "", downloadCacheEntry{}, fmt.Errorf("download cache quota unavailable")
		}
		reservation = actualReservation
		s.mu.Unlock()
	}
	key := downloadCacheKey(path, sourceSHA)
	s.mu.Lock()
	if entry, ok := s.downloadCache[key]; ok && now.Before(entry.expires) {
		entry.active++
		entry.lastAccess = now
		entry.expires = now.Add(s.cacheTTL)
		entry.lastMetaSave = now
		s.downloadCache[key] = entry
		s.touchCacheLocked(key)
		s.releaseCacheBuildLocked(reservation)
		releaseReservation = false
		s.mu.Unlock()
		_ = s.saveCacheMeta(entry, key)
		return key, entry, nil
	}
	s.mu.Unlock()

	built, buildErr := s.buildDownloadCache(snapshot, info, size, sourceSHA, key, now)
	finalSpool := filepath.Join(s.cacheDir, key+".b64")
	if buildErr == nil {
		buildErr = os.Rename(built.spoolPath, finalSpool)
	}
	if buildErr == nil {
		built.spoolPath = finalSpool
		built.metaPath = filepath.Join(s.cacheDir, key+".json")
		built.active = 1
		built.lastMetaSave = now
		buildErr = s.saveCacheMeta(built, key)
	}

	s.mu.Lock()
	s.releaseCacheBuildLocked(reservation)
	releaseReservation = false
	if buildErr == nil {
		s.downloadCache[key] = built
		s.downloadCacheBytes += built.encodedSize
		s.touchCacheLocked(key)
		s.evictDownloadCacheLocked(now)
	}
	s.mu.Unlock()
	if buildErr != nil {
		_ = os.Remove(built.spoolPath)
		_ = os.Remove(finalSpool)
		_ = os.Remove(filepath.Join(s.cacheDir, key+".json"))
		return "", downloadCacheEntry{}, buildErr
	}
	return key, built, nil
}

func (s *Server) acquireExistingCache(key string, now time.Time) (string, downloadCacheEntry, error) {
	s.mu.Lock()
	entry, ok := s.downloadCache[key]
	if !ok {
		s.mu.Unlock()
		return "", downloadCacheEntry{}, fmt.Errorf("cache entry disappeared")
	}
	entry.active++
	entry.lastAccess = now
	entry.expires = now.Add(s.cacheTTL)
	entry.lastMetaSave = now
	s.downloadCache[key] = entry
	s.touchCacheLocked(key)
	s.mu.Unlock()
	_ = s.saveCacheMeta(entry, key)
	return key, entry, nil
}

func (s *Server) buildDownloadCache(path string, info os.FileInfo, sourceSize int64, sourceSHA, key string, now time.Time) (downloadCacheEntry, error) {
	gzipTmp, err := os.CreateTemp(s.cacheDir, ".gdns2tcp-gzip-*")
	if err != nil {
		return downloadCacheEntry{}, err
	}
	gzipPath := gzipTmp.Name()
	if err := gzipTmp.Close(); err != nil {
		_ = os.Remove(gzipPath)
		return downloadCacheEntry{}, err
	}
	defer os.Remove(gzipPath)
	if err := codec.CompressFile(path, gzipPath); err != nil {
		return downloadCacheEntry{}, err
	}
	// path is a private snapshot created for this build; gzip now contains the
	// exact bytes whose digest is published, so release snapshot disk space.
	_ = os.Remove(path)
	protectedTmp, err := os.CreateTemp(s.cacheDir, ".gdns2tcp-protected-*")
	if err != nil {
		return downloadCacheEntry{}, err
	}
	protectedPath := protectedTmp.Name()
	if err := protectedTmp.Close(); err != nil {
		_ = os.Remove(protectedPath)
		return downloadCacheEntry{}, err
	}
	defer os.Remove(protectedPath)
	if err := secure.ProtectFile(s.secret, gzipPath, protectedPath); err != nil {
		return downloadCacheEntry{}, err
	}
	_ = os.Remove(gzipPath)
	spoolTmp, err := os.CreateTemp(s.cacheDir, ".gdns2tcp-download-*")
	if err != nil {
		return downloadCacheEntry{}, err
	}
	spoolPath := spoolTmp.Name()
	if err := spoolTmp.Close(); err != nil {
		_ = os.Remove(spoolPath)
		return downloadCacheEntry{}, err
	}
	encodedSize, err := codec.EncodeDNSFile(protectedPath, spoolPath, "base64")
	if err != nil {
		_ = os.Remove(spoolPath)
		return downloadCacheEntry{}, err
	}
	_ = os.Remove(protectedPath)
	chunkCount := int((encodedSize + codec.TXTChunkSize - 1) / codec.TXTChunkSize)
	if chunkCount <= 0 || chunkCount > maxTransferChunks {
		_ = os.Remove(spoolPath)
		return downloadCacheEntry{}, fmt.Errorf("encoded download chunk count is out of range")
	}
	return downloadCacheEntry{
		spoolPath: spoolPath, mtime: info.ModTime(), size: sourceSize, sha256: sourceSHA,
		encodedSize: encodedSize, chunkCount: chunkCount, lastAccess: now, expires: now.Add(s.cacheTTL),
	}, nil
}

func (s *Server) saveCacheMeta(entry downloadCacheEntry, key string) error {
	meta := diskCacheMeta{
		Key: key, Spool: filepath.Base(entry.spoolPath), MTimeUnixNs: entry.mtime.UnixNano(),
		Size: entry.size, SHA256: entry.sha256, EncodedSize: entry.encodedSize,
		ChunkCount: entry.chunkCount, LastAccess: entry.lastAccess.UnixNano(), Expires: entry.expires.UnixNano(),
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.cacheDir, ".gdns2tcp-meta-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(s.cacheDir, key+".json")); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func (s *Server) readCacheChunk(key string, index int, now time.Time) (string, error) {
	chunks, err := s.readCacheChunks(key, index, index+1, now)
	if err != nil {
		return "", err
	}
	if len(chunks) != 1 {
		return "", io.ErrUnexpectedEOF
	}
	return chunks[0], nil
}

func (s *Server) readCacheChunks(key string, from, end int, now time.Time) ([]string, error) {
	s.mu.Lock()
	entry, ok := s.downloadCache[key]
	if !ok || from < 0 || end <= from || end > entry.chunkCount {
		s.mu.Unlock()
		return nil, fmt.Errorf("cache chunk unavailable")
	}
	entry.lastAccess = now
	entry.expires = now.Add(s.cacheTTL)
	persistMeta := entry.lastMetaSave.IsZero() || now.Sub(entry.lastMetaSave) >= cacheMetaTouchInterval
	if persistMeta {
		entry.lastMetaSave = now
	}
	s.downloadCache[key] = entry
	s.touchCacheLocked(key)
	s.mu.Unlock()
	if persistMeta {
		_ = s.saveCacheMeta(entry, key)
	}

	f, err := os.Open(entry.spoolPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make([]string, 0, end-from)
	for index := from; index < end; index++ {
		offset := int64(index * codec.TXTChunkSize)
		length := int64(codec.TXTChunkSize)
		if remaining := entry.encodedSize - offset; remaining < length {
			length = remaining
		}
		buf := make([]byte, length)
		n, readErr := f.ReadAt(buf, offset)
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		if n != len(buf) {
			return nil, io.ErrUnexpectedEOF
		}
		out = append(out, string(buf))
	}
	return out, nil
}

func (s *Server) releaseCacheLocked(key string) {
	entry, ok := s.downloadCache[key]
	if !ok {
		return
	}
	if entry.active > 0 {
		entry.active--
	}
	s.downloadCache[key] = entry
}

func (s *Server) touchCacheLocked(key string) {
	for i, existing := range s.downloadCacheOrder {
		if existing == key {
			s.downloadCacheOrder = append(s.downloadCacheOrder[:i], s.downloadCacheOrder[i+1:]...)
			break
		}
	}
	s.downloadCacheOrder = append(s.downloadCacheOrder, key)
}

func (s *Server) rebuildCacheOrderLocked() {
	s.downloadCacheOrder = s.downloadCacheOrder[:0]
	keys := make([]string, 0, len(s.downloadCache))
	for key := range s.downloadCache {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return s.downloadCache[keys[i]].lastAccess.Before(s.downloadCache[keys[j]].lastAccess)
	})
	s.downloadCacheOrder = append(s.downloadCacheOrder, keys...)
}

func (s *Server) evictDownloadCacheLocked(now time.Time) {
	for key, entry := range s.downloadCache {
		if entry.active == 0 && !now.Before(entry.expires) {
			s.removeCacheLocked(key, entry)
		}
	}
	for s.downloadCacheBytes > s.cacheMaxBytes && len(s.downloadCacheOrder) > 0 {
		key := s.downloadCacheOrder[0]
		entry, ok := s.downloadCache[key]
		if !ok {
			s.downloadCacheOrder = s.downloadCacheOrder[1:]
			continue
		}
		if entry.active > 0 {
			// All older entries may be active. Move this one to the end and
			// continue looking for an evictable LRU entry.
			s.downloadCacheOrder = append(s.downloadCacheOrder[1:], key)
			allActive := true
			for _, candidate := range s.downloadCache {
				if candidate.active == 0 {
					allActive = false
					break
				}
			}
			if allActive {
				break
			}
			continue
		}
		s.removeCacheLocked(key, entry)
	}
}

func (s *Server) removeCacheLocked(key string, entry downloadCacheEntry) {
	delete(s.downloadCache, key)
	s.downloadCacheBytes -= entry.encodedSize
	for i, candidate := range s.downloadCacheOrder {
		if candidate == key {
			s.downloadCacheOrder = append(s.downloadCacheOrder[:i], s.downloadCacheOrder[i+1:]...)
			break
		}
	}
	_ = os.Remove(entry.spoolPath)
	_ = os.Remove(entry.metaPath)
}
