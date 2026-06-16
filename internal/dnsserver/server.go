package dnsserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gdns2tcp/internal/codec"
	secure "gdns2tcp/internal/crypto"
	"gdns2tcp/internal/protocol"

	"github.com/miekg/dns"
)

const (
	DefaultMaxUploadBytes   = 32 << 20
	DefaultMaxDownloadBytes = 32 << 20
	// clientChunkSize is the base64 chunk length used when serving downloadable
	// client artifacts over DNS. 254 fills a single DNS TXT character-string
	// (max 255 bytes) with one byte of safety margin. Independent from the
	// client's upload chunking.
	clientChunkSize        = 254
	maxClientTransferState  = 1024
	maxTransferChunks       = 1_000_000
	maxDownloadCacheEntries = 16
	maxDownloadBatch        = 32
	transferTTL             = 10 * time.Minute
	authFailedResponse     = "Authentication failed."
)

var dnsToBase64 = strings.NewReplacer("_", "+", "-", "/")

type Config struct {
	Domain           string
	Secret           string
	DataDir          string
	ClientArtifacts  []ClientArtifactConfig
	AllowList        bool
	MaxUploadBytes   int64
	MaxDownloadBytes int64
	Logger           *log.Logger
}

type ClientArtifactConfig struct {
	Alias    string
	Path     string
	Required bool
}

type Server struct {
	domain           string
	authDomain       string
	secret           string
	dataDir          string
	allowList        bool
	maxUploadBytes   int64
	maxDownloadBytes int64
	logger           *log.Logger

	mu        sync.Mutex
	downloads map[string]downloadState
	uploads   map[string]uploadState

	downloadCache      map[string]downloadCacheEntry
	downloadCacheOrder []string // FIFO insertion order for bounded eviction
	clientArtifacts    map[string]clientArtifact
	clientTransfers map[string]clientTransfer
}

type clientArtifact struct {
	name   string
	sha256 string
	chunks []string
}

type clientTransfer struct {
	seen       map[int]struct{}
	lastBucket int
}

type downloadState struct {
	filename string
	chunks   []string
	expires  time.Time
}

type downloadCacheEntry struct {
	chunks []string
	mtime  time.Time
}

type uploadState struct {
	file       *os.File
	filename   string
	path       string
	chunks     map[int]string
	total      int
	chunkSize  int
	encoding   string
	nextIndex int
	expires   time.Time
}

func New(cfg Config) (*Server, error) {
	domain, err := normalizeDomain(cfg.Domain)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Secret) == "" {
		return nil, errors.New("secret is required")
	}
	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "."
	}
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve data dir: %w", err)
	}
	info, err := os.Stat(absDataDir)
	if err != nil {
		return nil, fmt.Errorf("stat data dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("data dir %q is not a directory", absDataDir)
	}
	if cfg.MaxUploadBytes <= 0 {
		cfg.MaxUploadBytes = DefaultMaxUploadBytes
	}
	if cfg.MaxDownloadBytes <= 0 {
		cfg.MaxDownloadBytes = DefaultMaxDownloadBytes
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	server := &Server{
		domain:           domain,
		authDomain:       protocol.AuthDomain(domain),
		secret:           cfg.Secret,
		dataDir:          absDataDir,
		allowList:        cfg.AllowList,
		maxUploadBytes:   cfg.MaxUploadBytes,
		maxDownloadBytes: cfg.MaxDownloadBytes,
		logger:           logger,
		downloads:        make(map[string]downloadState),
		uploads:          make(map[string]uploadState),
		downloadCache:    make(map[string]downloadCacheEntry),
		clientArtifacts:  make(map[string]clientArtifact),
		clientTransfers:  make(map[string]clientTransfer),
	}
	for _, artifact := range cfg.ClientArtifacts {
		if err := server.prepareClientArtifact(artifact); err != nil {
			return nil, err
		}
	}
	return server, nil
}

func (s *Server) Domain() string {
	return s.domain
}

func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(r)

	if len(r.Question) == 0 {
		resp.Rcode = dns.RcodeFormatError
		if err := w.WriteMsg(resp); err != nil {
			s.logger.Printf("write DNS response: %v", err)
		}
		return
	}

	q := r.Question[0]
	if q.Qtype != dns.TypeTXT {
		resp.Rcode = dns.RcodeNameError
		if err := w.WriteMsg(resp); err != nil {
			s.logger.Printf("write DNS response: %v", err)
		}
		return
	}
	if !hasDomainSuffix(q.Name, s.domain) {
		resp.Rcode = dns.RcodeNameError
		if err := w.WriteMsg(resp); err != nil {
			s.logger.Printf("write DNS response: %v", err)
		}
		return
	}

	answer := s.handleTXT(q.Name, clientID(w.RemoteAddr()))
	resp.Answer = append(resp.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: answer,
	})
	if err := w.WriteMsg(resp); err != nil {
		s.logger.Printf("write DNS response: %v", err)
	}
}

func (s *Server) handleTXT(name, client string) []string {
	args, command, ok := parseCommand(name, s.domain)
	if !ok {
		return []string{"Invalid gdns2tcp request."}
	}
	now := time.Now().UTC()

	switch command {
	case "test":
		return s.testConnection(args)
	case "c":
		return s.catalog(args, now)
	case "dinit":
		return s.downloadInit(args, now)
	case "d":
		return s.downloadChunk(args, now)
	case "db":
		return s.downloadBatch(args, now)
	case "uinit":
		return s.uploadInit(args, now)
	case "u":
		return s.uploadChunk(args, now)
	case "client":
		return s.clientManifest("win", client)
	case "cl":
		return s.clientChunk("win", args, client)
	case "lazy", "base64":
		return []string{"Automatic remote PowerShell execution is disabled. Download clients manually through client-win/client-linux-amd64/client-linux-arm64/client-darwin-amd64/client-darwin-arm64 endpoints."}
	default:
		if strings.HasPrefix(command, "client-") {
			return s.clientManifest(strings.TrimPrefix(command, "client-"), client)
		}
		if strings.HasPrefix(command, "cl-") {
			return s.clientChunk(strings.TrimPrefix(command, "cl-"), args, client)
		}
		if strings.HasPrefix(command, "clb-") {
			return s.clientBatch(strings.TrimPrefix(command, "clb-"), args, client)
		}
		return []string{"Unknown gdns2tcp command."}
	}
}

func (s *Server) testConnection(args []string) []string {
	if len(args) != 1 || args[0] == "" {
		return []string{"Empty request. Please repeat."}
	}
	if args[0] == "EnCoDiNg" {
		s.logger.Printf("client supports mixed-case DNS labels; using base64 upload encoding")
		return []string{"base64"}
	}
	s.logger.Printf("DNS path lowercases labels; using base32 upload encoding")
	return []string{"base32"}
}

func (s *Server) catalog(args []string, now time.Time) []string {
	payload, ts, mac, ok := splitAuthenticatedArgs(args)
	if !ok || !protocol.VerifyAuth(s.secret, s.authDomain, "c", payload, ts, mac, now) {
		return []string{authFailedResponse}
	}
	if len(payload) > 1 {
		return []string{"Incorrect page number."}
	}
	if !s.allowList {
		return []string{"Listing disabled."}
	}
	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		s.logger.Printf("read data dir: %v", err)
		return []string{"Directory listing error."}
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	pages := codec.ChunkString(strings.Join(names, ","), codec.TXTChunkSize)
	if len(pages) == 0 {
		return []string{""}
	}
	if len(payload) == 0 {
		if len(pages) > 1 {
			return []string{fmt.Sprintf("Catalog contains %d pages.", len(pages))}
		}
		return []string{pages[0]}
	}
	page, err := strconv.Atoi(payload[0])
	if err != nil || page < 0 || page >= len(pages) {
		return []string{"Incorrect page number."}
	}
	return []string{pages[page]}
}

func (s *Server) downloadInit(args []string, now time.Time) []string {
	payload, ts, mac, ok := splitAuthenticatedArgs(args)
	if !ok || !protocol.VerifyAuth(s.secret, s.authDomain, "dinit", payload, ts, mac, now) {
		return []string{authFailedResponse}
	}
	if len(payload) < 3 {
		return []string{authFailedResponse}
	}
	sid := strings.ToLower(payload[0])
	if !protocol.ValidSID(sid) {
		return []string{"Invalid transfer id."}
	}
	filename, path, err := s.safePathFromFilenameLabels(payload[1:])
	if err != nil {
		return []string{"Invalid filename."}
	}
	path, err = s.resolveExistingPathWithinDataDir(path)
	if err != nil {
		s.logger.Printf("reject download path %q: %v", filename, err)
		return []string{"Invalid filename."}
	}

	s.mu.Lock()
	s.cleanupExpiredLocked(now)
	if _, exists := s.downloads[sid]; exists {
		s.mu.Unlock()
		return []string{"Transfer already exists."}
	}
	s.mu.Unlock()

	info, err := os.Stat(path)
	if err != nil {
		s.logger.Printf("stat download file %q: %v", filename, err)
		return []string{"Error open file."}
	}
	if !info.Mode().IsRegular() {
		return []string{"Error open file."}
	}
	if info.Size() > s.maxDownloadBytes {
		s.logger.Printf("download %q exceeded max size", filename)
		return []string{"Download is too large for this server policy."}
	}
	s.mu.Lock()
	if entry, ok := s.downloadCache[path]; ok && entry.mtime.Equal(info.ModTime()) {
		if _, exists := s.downloads[sid]; exists {
			s.mu.Unlock()
			return []string{"Transfer already exists."}
		}
		state := downloadState{
			filename: filename,
			chunks:   entry.chunks,
			expires:  now.Add(transferTTL),
		}
		s.downloads[sid] = state
		s.mu.Unlock()
		s.logger.Printf("served cached download %q as %s in %d chunks", filename, sid, len(state.chunks))
		return []string{strconv.Itoa(len(state.chunks))}
	}
	s.mu.Unlock()

	raw, err := os.ReadFile(path)
	if err != nil {
		s.logger.Printf("read download file %q: %v", filename, err)
		return []string{"Error open file."}
	}
	compressed, err := codec.Compress(raw)
	if err != nil {
		s.logger.Printf("compress download file %q: %v", filename, err)
		return []string{"Server compression error."}
	}
	protected, err := secure.ProtectToBase64(s.secret, compressed)
	if err != nil {
		s.logger.Printf("encrypt download file %q: %v", filename, err)
		return []string{"Server encryption error."}
	}

	chunks := codec.ChunkString(protected, codec.TXTChunkSize)
	state := downloadState{
		filename: filename,
		chunks:   chunks,
		expires:  now.Add(transferTTL),
	}
	s.mu.Lock()
	if _, alreadyCached := s.downloadCache[path]; !alreadyCached {
		if len(s.downloadCacheOrder) >= maxDownloadCacheEntries {
			evict := s.downloadCacheOrder[0]
			s.downloadCacheOrder = s.downloadCacheOrder[1:]
			delete(s.downloadCache, evict)
		}
		s.downloadCacheOrder = append(s.downloadCacheOrder, path)
	}
	s.downloadCache[path] = downloadCacheEntry{chunks: chunks, mtime: info.ModTime()}
	s.cleanupExpiredLocked(now)
	if _, exists := s.downloads[sid]; exists {
		s.mu.Unlock()
		return []string{"Transfer already exists."}
	}
	s.downloads[sid] = state
	s.mu.Unlock()

	s.logger.Printf("prepared download %q as %s in %d chunks", filename, sid, len(state.chunks))
	return []string{strconv.Itoa(len(state.chunks))}
}

func (s *Server) downloadChunk(args []string, now time.Time) []string {
	payload, ts, mac, ok := splitAuthenticatedArgs(args)
	if !ok || !protocol.VerifyAuth(s.secret, s.authDomain, "d", payload, ts, mac, now) {
		return []string{authFailedResponse}
	}
	if len(payload) != 2 {
		return []string{authFailedResponse}
	}
	sid := strings.ToLower(payload[0])
	index, err := strconv.Atoi(payload[1])
	if !protocol.ValidSID(sid) || err != nil {
		return []string{"Wrong chunk number."}
	}

	s.mu.Lock()
	s.cleanupExpiredLocked(now)
	state, exists := s.downloads[sid]
	if !exists {
		s.mu.Unlock()
		return []string{"Transfer not found."}
	}
	if index < 0 || index >= len(state.chunks) {
		s.mu.Unlock()
		return []string{"Wrong chunk number."}
	}
	chunk := state.chunks[index]
	state.expires = now.Add(transferTTL)
	s.downloads[sid] = state
	s.mu.Unlock()
	return []string{chunk}
}

// downloadBatch returns up to `count` consecutive chunks starting at `from`,
// each as a separate TXT character-string within a single TXT RR. Combined
// with EDNS0 on the client (advertising a larger UDP buffer), this reduces
// the per-chunk DNS query overhead by a factor of ~batchSize.
func (s *Server) downloadBatch(args []string, now time.Time) []string {
	payload, ts, mac, ok := splitAuthenticatedArgs(args)
	if !ok || !protocol.VerifyAuth(s.secret, s.authDomain, "db", payload, ts, mac, now) {
		return []string{authFailedResponse}
	}
	if len(payload) != 3 {
		return []string{authFailedResponse}
	}
	sid := strings.ToLower(payload[0])
	from, errFrom := strconv.Atoi(payload[1])
	count, errCount := strconv.Atoi(payload[2])
	if !protocol.ValidSID(sid) || errFrom != nil || errCount != nil || from < 0 || count <= 0 {
		return []string{"Wrong chunk number."}
	}
	if count > maxDownloadBatch {
		count = maxDownloadBatch
	}

	s.mu.Lock()
	s.cleanupExpiredLocked(now)
	state, exists := s.downloads[sid]
	if !exists {
		s.mu.Unlock()
		return []string{"Transfer not found."}
	}
	if from >= len(state.chunks) {
		s.mu.Unlock()
		return []string{"Wrong chunk number."}
	}
	end := from + count
	if end > len(state.chunks) {
		end = len(state.chunks)
	}
	batch := append([]string(nil), state.chunks[from:end]...)
	state.expires = now.Add(transferTTL)
	s.downloads[sid] = state
	s.mu.Unlock()
	return batch
}

func (s *Server) uploadInit(args []string, now time.Time) []string {
	payload, ts, mac, ok := splitAuthenticatedArgs(args)
	if !ok || !protocol.VerifyAuth(s.secret, s.authDomain, "uinit", payload, ts, mac, now) {
		return []string{authFailedResponse}
	}
	if len(payload) < 6 {
		return []string{authFailedResponse}
	}
	sid := strings.ToLower(payload[0])
	if !protocol.ValidSID(sid) {
		return []string{"Invalid transfer id."}
	}
	total, err := strconv.Atoi(payload[1])
	if err != nil || total <= 0 || total > maxTransferChunks {
		return []string{"Incorrect file length format."}
	}
	chunkSize, err := strconv.Atoi(payload[2])
	if err != nil || chunkSize <= 0 || chunkSize > codec.TXTChunkSize {
		return []string{"Incorrect chunk length format."}
	}
	encoding := strings.ToLower(payload[3])
	if encoding != "base32" && encoding != "base64" {
		return []string{"Incorrect upload encoding."}
	}
	maxWireLength := safeDouble(s.maxUploadBytes)
	if int64(total) > (maxWireLength+int64(chunkSize)-1)/int64(chunkSize) {
		return []string{"Upload is too large for this server policy."}
	}
	filename, path, err := s.safePathFromFilenameLabels(payload[4:])
	if err != nil {
		return []string{"Invalid filename."}
	}

	s.mu.Lock()
	s.cleanupExpiredLocked(now)
	if _, exists := s.uploads[sid]; exists {
		s.mu.Unlock()
		return []string{"Transfer already exists."}
	}
	s.mu.Unlock()

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return []string{"Error. File already exist."}
	}
	if err != nil {
		s.logger.Printf("create upload file %q: %v", filename, err)
		return []string{"Cannot create file."}
	}

	state := uploadState{
		file:       file,
		filename:   filename,
		path:       path,
		chunks:     make(map[int]string),
		total:      total,
		chunkSize: chunkSize,
		encoding:  encoding,
		nextIndex: 0,
		expires:   now.Add(transferTTL),
	}
	s.mu.Lock()
	s.cleanupExpiredLocked(now)
	if _, exists := s.uploads[sid]; exists {
		s.mu.Unlock()
		_ = file.Close()
		_ = os.Remove(path)
		return []string{"Transfer already exists."}
	}
	s.uploads[sid] = state
	s.mu.Unlock()

	s.logger.Printf("receiving upload %q as %s in %d chunks", filename, sid, total)
	return []string{"Ready to file uploading"}
}

func (s *Server) uploadChunk(args []string, now time.Time) []string {
	payload, ts, mac, ok := splitAuthenticatedArgs(args)
	if !ok || !protocol.VerifyAuth(s.secret, s.authDomain, "u", payload, ts, mac, now) {
		return []string{authFailedResponse}
	}
	if len(payload) < 3 {
		return []string{authFailedResponse}
	}
	sid := strings.ToLower(payload[0])
	index, err := strconv.Atoi(payload[1])
	if !protocol.ValidSID(sid) || err != nil {
		return []string{"Wrong chunk number."}
	}
	var builder strings.Builder
	for _, part := range payload[2:] {
		builder.WriteString(dnsToBase64.Replace(part))
	}
	wireChunk := builder.String()

	s.mu.Lock()
	s.cleanupExpiredLocked(now)
	state, exists := s.uploads[sid]
	if !exists {
		s.mu.Unlock()
		return []string{"Upload is not initialized."}
	}
	if index != state.nextIndex {
		next := state.nextIndex
		s.mu.Unlock()
		return []string{strconv.Itoa(next)}
	}
	if len(wireChunk) > state.chunkSize {
		s.mu.Unlock()
		return []string{"Incorrect chunk length format."}
	}
	state.chunks[index] = wireChunk
	if index == state.total-1 {
		delete(s.uploads, sid)
		s.mu.Unlock()
		return []string{s.finishUpload(sid, state)}
	}
	state.nextIndex++
	state.expires = now.Add(transferTTL)
	s.uploads[sid] = state
	next := state.nextIndex
	s.mu.Unlock()
	return []string{strconv.Itoa(next)}
}

func (s *Server) finishUpload(sid string, state uploadState) string {
	failed := false
	defer func() {
		if state.file != nil {
			_ = state.file.Close()
		}
		if failed {
			if err := os.Remove(state.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.logger.Printf("remove failed upload file %q: %v", state.filename, err)
			}
		}
	}()

	var encoded strings.Builder
	for i := 0; i < state.total; i++ {
		chunk, ok := state.chunks[i]
		if !ok {
			s.logger.Printf("upload %q missing chunk %d", state.filename, i)
			failed = true
			return strconv.Itoa(i)
		}
		encoded.WriteString(chunk)
	}
	protected, err := codec.DecodeDNSPayload(encoded.String(), state.encoding)
	if err != nil {
		s.logger.Printf("decode upload %q: %v", state.filename, err)
		failed = true
		return "Upload decode error."
	}
	compressed, err := secure.Open(s.secret, protected)
	if err != nil {
		s.logger.Printf("decrypt upload %q: %v", state.filename, err)
		failed = true
		return "Upload decryption error."
	}
	raw, err := codec.DecompressLimit(compressed, s.maxUploadBytes)
	if err != nil {
		s.logger.Printf("decompress upload %q: %v", state.filename, err)
		failed = true
		return "Upload decompression error."
	}
	if int64(len(raw)) > s.maxUploadBytes {
		s.logger.Printf("upload %q exceeded max uncompressed size", state.filename)
		failed = true
		return "Upload is too large for this server policy."
	}
	if _, err := state.file.Write(raw); err != nil {
		s.logger.Printf("write upload %q: %v", state.filename, err)
		failed = true
		return "Cannot write file."
	}
	s.logger.Printf("stored upload %q from %s (%d bytes)", state.filename, sid, len(raw))
	return "-1"
}

func (s *Server) prepareClientArtifact(cfg ClientArtifactConfig) error {
	alias := strings.ToLower(strings.TrimSpace(cfg.Alias))
	if alias == "" {
		return errors.New("client artifact alias is required")
	}
	if strings.Contains(alias, ".") {
		return fmt.Errorf("invalid client artifact alias %q", alias)
	}
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		return nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if cfg.Required {
			return fmt.Errorf("read client artifact %q: %w", path, err)
		}
		s.logger.Printf("client artifact %s is not configured: %v", alias, err)
		return nil
	}
	sum := sha256.Sum256(raw)
	s.clientArtifacts[alias] = clientArtifact{
		name:   filepath.Base(path),
		sha256: hex.EncodeToString(sum[:]),
		chunks: codec.ChunkString(base64.StdEncoding.EncodeToString(raw), clientChunkSize),
	}
	s.logger.Printf("client artifact %s configured from %s", alias, path)
	return nil
}

func (s *Server) clientManifest(alias, client string) []string {
	artifact, ok := s.clientArtifacts[alias]
	if !ok || len(artifact.chunks) == 0 {
		s.logger.Printf("client %s requested unavailable artifact %s", client, alias)
		return []string{"Client artifact is not configured."}
	}
	s.logger.Printf("client %s requested artifact %s (%s, %d chunks, sha256 %s)", client, alias, artifact.name, len(artifact.chunks), artifact.sha256)
	return []string{fmt.Sprintf("%s|%d|%s", artifact.name, len(artifact.chunks), artifact.sha256)}
}

func (s *Server) clientChunk(alias string, args []string, client string) []string {
	artifact, ok := s.clientArtifacts[alias]
	if !ok || len(artifact.chunks) == 0 {
		s.logger.Printf("client %s requested unavailable artifact chunk %s", client, alias)
		return []string{"Client artifact is not configured."}
	}
	if len(args) != 1 || args[0] == "" {
		return []string{"Missing chunk number."}
	}
	index, err := strconv.Atoi(args[0])
	if err != nil || index < 0 || index >= len(artifact.chunks) {
		return []string{"Incorrect chunk number."}
	}
	s.mu.Lock()
	s.logClientArtifactProgress(client, alias, artifact, index)
	s.mu.Unlock()
	return []string{artifact.chunks[index]}
}

// clientBatch is the batched counterpart of clientChunk: a single TXT response
// returns up to `count` consecutive client artifact chunks as separate
// character-strings, which the bootstrap script concatenates as-is. Like
// clientChunk it is unauthenticated by design (the artifact endpoints are how
// a fresh host obtains a client before it has the shared secret).
func (s *Server) clientBatch(alias string, args []string, client string) []string {
	artifact, ok := s.clientArtifacts[alias]
	if !ok || len(artifact.chunks) == 0 {
		s.logger.Printf("client %s requested unavailable artifact batch %s", client, alias)
		return []string{"Client artifact is not configured."}
	}
	if len(args) != 2 {
		return []string{"Missing chunk number."}
	}
	from, errFrom := strconv.Atoi(args[0])
	count, errCount := strconv.Atoi(args[1])
	if errFrom != nil || errCount != nil || from < 0 || count <= 0 {
		return []string{"Incorrect chunk number."}
	}
	if count > maxDownloadBatch {
		count = maxDownloadBatch
	}
	if from >= len(artifact.chunks) {
		return []string{"Incorrect chunk number."}
	}
	end := from + count
	if end > len(artifact.chunks) {
		end = len(artifact.chunks)
	}
	s.mu.Lock()
	for i := from; i < end; i++ {
		s.logClientArtifactProgress(client, alias, artifact, i)
	}
	s.mu.Unlock()
	return append([]string(nil), artifact.chunks[from:end]...)
}

func (s *Server) logClientArtifactProgress(client, alias string, artifact clientArtifact, index int) {
	key := client + "|" + alias
	progress, ok := s.clientTransfers[key]
	if !ok {
		if len(s.clientTransfers) >= maxClientTransferState {
			s.logger.Printf("client %s artifact %s: transfer state table full, skipping progress tracking", client, alias)
			return
		}
		progress = clientTransfer{
			seen:       make(map[int]struct{}),
			lastBucket: -1,
		}
	}
	if _, exists := progress.seen[index]; exists {
		s.clientTransfers[key] = progress
		return
	}
	progress.seen[index] = struct{}{}
	total := len(artifact.chunks)
	seen := len(progress.seen)
	percent := seen * 100 / total
	bucket := percent / 10 * 10
	if seen == 1 || bucket > progress.lastBucket || seen == total {
		s.logger.Printf("client %s artifact %s transfer progress: %d/%d chunks (%d%%)", client, alias, seen, total, percent)
		progress.lastBucket = bucket
	}
	if seen == total {
		s.logger.Printf("client %s artifact %s transfer completed: %s", client, alias, artifact.name)
		delete(s.clientTransfers, key)
		return
	}
	s.clientTransfers[key] = progress
}

func (s *Server) cleanupExpiredLocked(now time.Time) {
	for sid, state := range s.uploads {
		if now.Before(state.expires) {
			continue
		}
		if state.file != nil {
			_ = state.file.Close()
		}
		if err := os.Remove(state.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.logger.Printf("remove expired upload file %q: %v", state.filename, err)
		}
		delete(s.uploads, sid)
		s.logger.Printf("expired upload %q (%s)", state.filename, sid)
	}
	for sid, state := range s.downloads {
		if now.Before(state.expires) {
			continue
		}
		delete(s.downloads, sid)
		s.logger.Printf("expired download %q (%s)", state.filename, sid)
	}
}

func (s *Server) safePathFromFilenameLabels(labels []string) (string, string, error) {
	filename, err := protocol.DecodeFilenameLabels(labels)
	if err != nil {
		return "", "", err
	}
	return s.safePathFromFilename(filename)
}

func (s *Server) safePathFromFilename(filename string) (string, string, error) {
	if err := protocol.ValidateFilename(filename); err != nil {
		return "", "", err
	}
	path := filepath.Join(s.dataDir, filename)
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(s.dataDir, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", "", fmt.Errorf("path escapes data dir")
	}
	return filename, clean, nil
}

func (s *Server) resolveExistingPathWithinDataDir(path string) (string, error) {
	realDataDir, err := filepath.EvalSymlinks(s.dataDir)
	if err != nil {
		return "", fmt.Errorf("resolve data dir symlinks: %w", err)
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return path, nil
		}
		return "", fmt.Errorf("resolve path symlinks: %w", err)
	}
	rel, err := filepath.Rel(realDataDir, realPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes data dir")
	}
	return realPath, nil
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return "", errors.New("domain is required")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid domain label %q", label)
		}
	}
	return domain + ".", nil
}

func hasDomainSuffix(name, domain string) bool {
	fqdn := strings.ToLower(dns.Fqdn(name))
	return fqdn == domain || strings.HasSuffix(fqdn, "."+domain)
}

func clientID(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil || host == "" {
		return addr.String()
	}
	return host
}

func parseCommand(name, domain string) ([]string, string, bool) {
	fqdn := dns.Fqdn(name)
	if !hasDomainSuffix(fqdn, domain) {
		return nil, "", false
	}
	prefix := strings.TrimSuffix(fqdn, domain)
	prefix = strings.TrimSuffix(prefix, ".")
	if prefix == "" {
		return []string{""}, "", true
	}
	labels := strings.Split(prefix, ".")
	if len(labels) == 1 {
		return []string{""}, strings.ToLower(labels[0]), true
	}
	return labels[:len(labels)-1], strings.ToLower(labels[len(labels)-1]), true
}

func splitAuthenticatedArgs(args []string) ([]string, string, string, bool) {
	if len(args) < 2 {
		return nil, "", "", false
	}
	timestamp := args[len(args)-2]
	token := args[len(args)-1]
	if timestamp == "" || token == "" {
		return nil, "", "", false
	}
	payload := args[:len(args)-2]
	if len(payload) == 1 && payload[0] == "" {
		payload = nil
	}
	return payload, timestamp, token, true
}

func safeDouble(value int64) int64 {
	if value > math.MaxInt64/2 {
		return math.MaxInt64
	}
	return value * 2
}
