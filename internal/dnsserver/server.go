package dnsserver

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	DefaultMaxDownloadBytes = 256 << 20
	DefaultCacheMaxBytes    = 1 << 30
	DefaultCacheTTL         = 24 * time.Hour
	// clientChunkSize is the base64 chunk length used when serving downloadable
	// client artifacts over DNS. 254 fills a single DNS TXT character-string
	// (max 255 bytes) with one byte of safety margin. Independent from the
	// client's upload chunking.
	clientChunkSize        = 254
	maxClientTransferState = 1024
	// A 256 MiB incompressible download expands to roughly 358 MiB after
	// gzip/GDT2/base64, or about 1.41 million 254-byte TXT chunks.  Keep the
	// guard above that real worst case; transfer state is now disk-backed, so
	// this no longer implies a multi-million-element in-memory payload.
	maxTransferChunks  = 2_000_000
	maxDownloadBatch   = 32
	transferTTL        = 10 * time.Minute
	clientTransferTTL  = 10 * time.Minute
	authFailedResponse = "Authentication failed."
)

var dnsToBase64 = strings.NewReplacer("_", "+", "-", "/")

type Config struct {
	Domain              string
	Secret              string
	DataDir             string
	ClientArtifacts     []ClientArtifactConfig
	AllowList           bool
	MaxUploadBytes      int64
	MaxDownloadBytes    int64
	AllowProxy          bool
	SocksNoAuth         bool
	ProxyMaxConn        int
	ProxyBufBytes       int
	ProxyWatchdogWindow time.Duration
	CacheDir            string
	CacheMaxBytes       int64
	CacheTTL            time.Duration
	Logger              *log.Logger
}

type ClientArtifactConfig struct {
	Alias    string
	Path     string
	Required bool
}

type Server struct {
	// domain is the canonical domain: the one used to derive authDomain
	// (which is baked into the HMAC of every authenticated request).
	// Callers always sign under this name regardless of which shard
	// domain they route the query through.
	domain string
	// domains is the full accepted set (canonical first, then shards).
	// hasDomainSuffix / parseCommand walk this list to decide whether
	// an inbound QNAME belongs to us. For single-domain configs it has
	// exactly one entry equal to domain.
	domains          []string
	authDomain       string
	secret           string
	dataDir          string
	allowList        bool
	maxUploadBytes   int64
	maxDownloadBytes int64
	cacheDir         string
	cacheMaxBytes    int64
	cacheTTL         time.Duration
	allowProxy       bool
	socksNoAuth      bool
	logger           *log.Logger

	mu               sync.Mutex
	downloads        map[string]downloadState
	uploads          map[string]uploadState
	uploadTombstones map[string]uploadTombstone

	downloadCache         map[string]downloadCacheEntry
	downloadCacheOrder    []string // LRU, oldest first
	downloadCacheBytes    int64
	downloadCacheReserved int64
	downloadCacheBuilds   map[string]*downloadCacheBuild
	clientArtifacts       map[string]clientArtifact
	clientTransfers       map[string]clientTransfer
	reverse               *reverseState

	janitorStop  chan struct{}
	janitorDone  chan struct{}
	shutdownOnce sync.Once
}

type clientArtifact struct {
	name   string
	sha256 string
	chunks []string
}

type clientTransfer struct {
	seen       []byte
	seenCount  int
	lastBucket int
	lastSeen   time.Time
}

type downloadState struct {
	filename     string
	cacheKey     string
	chunkCount   int
	encodedSize  int64
	sourceSHA256 string
	expires      time.Time
}

type downloadCacheEntry struct {
	spoolPath    string
	metaPath     string
	mtime        time.Time
	size         int64
	sha256       string
	encodedSize  int64
	chunkCount   int
	lastAccess   time.Time
	expires      time.Time
	lastMetaSave time.Time
	active       int
}

type downloadCacheBuild struct {
	done chan struct{}
	key  string
	err  error
}

type uploadState struct {
	spool       *os.File
	filename    string
	path        string
	spoolPath   string
	fingerprint string
	total       int
	chunkSize   int
	encoding    string
	nextIndex   int
	expires     time.Time
}

type uploadTombstone struct {
	fingerprint string
	finalIndex  int
	result      string
	expires     time.Time
}

func New(cfg Config) (*Server, error) {
	domain, domains, err := normalizeDomains(cfg.Domain)
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
	cacheDir := strings.TrimSpace(cfg.CacheDir)
	if cacheDir == "" {
		cacheDir = filepath.Join(absDataDir, ".gdns2tcp-cache")
	}
	cacheDir, err = filepath.Abs(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("resolve cache dir: %w", err)
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	if cfg.CacheMaxBytes <= 0 {
		cfg.CacheMaxBytes = DefaultCacheMaxBytes
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	server := &Server{
		domain:              domain,
		domains:             domains,
		authDomain:          protocol.AuthDomain(domain),
		secret:              cfg.Secret,
		dataDir:             absDataDir,
		allowList:           cfg.AllowList,
		maxUploadBytes:      cfg.MaxUploadBytes,
		maxDownloadBytes:    cfg.MaxDownloadBytes,
		cacheDir:            cacheDir,
		cacheMaxBytes:       cfg.CacheMaxBytes,
		cacheTTL:            cfg.CacheTTL,
		allowProxy:          cfg.AllowProxy,
		socksNoAuth:         cfg.SocksNoAuth,
		logger:              logger,
		downloads:           make(map[string]downloadState),
		uploads:             make(map[string]uploadState),
		uploadTombstones:    make(map[string]uploadTombstone),
		downloadCache:       make(map[string]downloadCacheEntry),
		downloadCacheBuilds: make(map[string]*downloadCacheBuild),
		clientArtifacts:     make(map[string]clientArtifact),
		clientTransfers:     make(map[string]clientTransfer),
		janitorStop:         make(chan struct{}),
		janitorDone:         make(chan struct{}),
	}
	if err := server.cleanupOrphanCacheFiles(); err != nil {
		return nil, err
	}
	server.cleanupOrphanUploadFiles(time.Now().UTC())
	if err := server.loadDownloadCache(); err != nil {
		return nil, err
	}
	if cfg.AllowProxy {
		server.reverse = newReverseState(cfg.ProxyBufBytes, cfg.ProxyMaxConn, cfg.ProxyWatchdogWindow, logger)
	}
	for _, artifact := range cfg.ClientArtifacts {
		if err := server.prepareClientArtifact(artifact); err != nil {
			return nil, err
		}
	}
	server.startJanitor()
	return server, nil
}

// Shutdown closes the SOCKS5 listener (if any) and tears down every live
// proxy tunnel. Idempotent. Returns immediately if proxy is disabled.
func (s *Server) Shutdown() {
	s.shutdownOnce.Do(func() {
		close(s.janitorStop)
		<-s.janitorDone
		s.proxyShutdown()
	})
}

func (s *Server) startJanitor() {
	go func() {
		defer close(s.janitorDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.mu.Lock()
				s.cleanupExpiredLocked(time.Now().UTC())
				s.mu.Unlock()
			case <-s.janitorStop:
				return
			}
		}
	}()
}

func (s *Server) Domain() string {
	return s.domain
}

// Domains returns every accepted shard suffix, canonical first. For
// single-domain configs the slice has exactly one entry equal to
// Domain(). Callers must not mutate the returned slice.
func (s *Server) Domains() []string {
	return s.domains
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
	matchedDomain, ok := hasAnyDomainSuffix(q.Name, s.domains)
	if !ok {
		resp.Rcode = dns.RcodeNameError
		if err := w.WriteMsg(resp); err != nil {
			s.logger.Printf("write DNS response: %v", err)
		}
		return
	}

	// This process is the authoritative endpoint for every configured shard.
	// Recursive resolvers use AA to distinguish a real delegated answer from
	// a lame/non-authoritative response. Omitting it made high-volume proxy
	// traffic work reliably only when clients bypassed recursion with -ds.
	resp.Authoritative = true

	if q.Qtype != dns.TypeTXT {
		// Names below the dynamic tunnel zone exist for TXT. A query for a
		// different type is therefore NODATA (NOERROR with an empty answer),
		// not NXDOMAIN. Returning NXDOMAIN here lets recursive resolvers
		// negatively cache the name and suppress later TXT traffic.
		resp.Rcode = dns.RcodeSuccess
		if err := w.WriteMsg(resp); err != nil {
			s.logger.Printf("write DNS response: %v", err)
		}
		return
	}

	answer := s.handleTXTOnDomain(q.Name, matchedDomain, clientID(w.RemoteAddr()))
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

// handleTXT is the entry point used by direct-invocation tests. It
// rediscovers the shard suffix itself, then delegates to
// handleTXTOnDomain. Production traffic reaches handleTXTOnDomain
// directly from ServeDNS, which has already computed matchedDomain.
func (s *Server) handleTXT(name, client string) []string {
	matchedDomain, ok := hasAnyDomainSuffix(name, s.domains)
	if !ok {
		return []string{"Invalid gdns2tcp request."}
	}
	return s.handleTXTOnDomain(name, matchedDomain, client)
}

// handleTXTOnDomain dispatches a validated inbound query. matchedDomain
// must be the shard suffix hasAnyDomainSuffix picked — parseCommand
// uses it to trim the right suffix off the query name. HMAC checks
// downstream always run against s.authDomain (canonical), so the shard
// the client happened to route through has no effect on auth.
func (s *Server) handleTXTOnDomain(name, matchedDomain, client string) []string {
	args, command, ok := parseCommand(name, matchedDomain)
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
	case "dmeta":
		return s.downloadMeta(args, now)
	case "d":
		return s.downloadChunk(args, now)
	case "db":
		return s.downloadBatch(args, now)
	case "apoll":
		return s.proxyAgentPoll(args, now, client)
	case "aopen":
		return s.proxyAgentOpen(args, now)
	case "aread":
		return s.proxyAgentRead(args, now)
	case "awrite":
		return s.proxyAgentWrite(args, now)
	case "aclose":
		return s.proxyAgentClose(args, now)
	case "axchg":
		return s.proxyAgentExchange(args, now)
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
		// Internal cache/spool files are implementation details, never
		// downloadable artifacts.  Restrict the catalog to regular visible
		// files so an in-progress upload cannot appear as a valid download.
		if strings.HasPrefix(entry.Name(), ".") || !entry.Type().IsRegular() {
			continue
		}
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
	if existing, exists := s.downloads[sid]; exists {
		if existing.filename == filename {
			existing.expires = now.Add(transferTTL)
			s.downloads[sid] = existing
			s.mu.Unlock()
			return []string{strconv.Itoa(existing.chunkCount)}
		}
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
	key, entry, err := s.prepareDownloadCache(path, info, now)
	if err != nil {
		s.logger.Printf("prepare download %q: %v", filename, err)
		if strings.Contains(err.Error(), "limit") {
			return []string{"Download is too large for this server policy."}
		}
		return []string{"Server download preparation error."}
	}

	s.mu.Lock()
	s.cleanupExpiredLocked(now)
	if existing, exists := s.downloads[sid]; exists {
		s.releaseCacheLocked(key)
		if existing.filename == filename {
			existing.expires = now.Add(transferTTL)
			s.downloads[sid] = existing
			s.mu.Unlock()
			return []string{strconv.Itoa(existing.chunkCount)}
		}
		s.mu.Unlock()
		return []string{"Transfer already exists."}
	}
	state := downloadState{
		filename: filename, cacheKey: key, chunkCount: entry.chunkCount,
		encodedSize: entry.encodedSize, sourceSHA256: entry.sha256,
		expires: now.Add(transferTTL),
	}
	s.downloads[sid] = state
	s.mu.Unlock()

	s.logger.Printf("prepared streamed download %q as %s in %d chunks", filename, sid, state.chunkCount)
	return []string{strconv.Itoa(state.chunkCount)}
}

func (s *Server) downloadMeta(args []string, now time.Time) []string {
	payload, ts, mac, ok := splitAuthenticatedArgs(args)
	if !ok || !protocol.VerifyAuth(s.secret, s.authDomain, "dmeta", payload, ts, mac, now) {
		return []string{authFailedResponse}
	}
	if len(payload) != 1 {
		return []string{authFailedResponse}
	}
	sid := strings.ToLower(payload[0])
	if !protocol.ValidSID(sid) {
		return []string{"Invalid transfer id."}
	}

	s.mu.Lock()
	s.cleanupExpiredLocked(now)
	state, exists := s.downloads[sid]
	if !exists {
		s.mu.Unlock()
		return []string{"Transfer not found."}
	}
	state.expires = now.Add(transferTTL)
	s.downloads[sid] = state
	s.mu.Unlock()

	return []string{fmt.Sprintf("%d|%s|%d", state.chunkCount, state.sourceSHA256, state.encodedSize)}
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
	if index < 0 || index >= state.chunkCount {
		s.mu.Unlock()
		return []string{"Wrong chunk number."}
	}
	state.expires = now.Add(transferTTL)
	s.downloads[sid] = state
	s.mu.Unlock()
	chunk, err := s.readCacheChunk(state.cacheKey, index, now)
	if err != nil {
		s.logger.Printf("read download chunk %s/%d: %v", sid, index, err)
		return []string{"Download cache unavailable."}
	}
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
	if from >= state.chunkCount {
		s.mu.Unlock()
		return []string{"Wrong chunk number."}
	}
	end := from + count
	if end > state.chunkCount {
		end = state.chunkCount
	}
	state.expires = now.Add(transferTTL)
	s.downloads[sid] = state
	s.mu.Unlock()
	batch, err := s.readCacheChunks(state.cacheKey, from, end, now)
	if err != nil {
		s.logger.Printf("read download batch %s/%d: %v", sid, from, err)
		return []string{"Download cache unavailable."}
	}
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
	fingerprint := fmt.Sprintf("%s|%d|%d|%s", filename, total, chunkSize, encoding)

	s.mu.Lock()
	s.cleanupExpiredLocked(now)
	if existing, exists := s.uploads[sid]; exists {
		if existing.fingerprint == fingerprint {
			existing.expires = now.Add(transferTTL)
			s.uploads[sid] = existing
			s.mu.Unlock()
			return []string{"Ready to file uploading"}
		}
		s.mu.Unlock()
		return []string{"Transfer already exists."}
	}
	s.mu.Unlock()
	if _, err := os.Lstat(path); err == nil {
		return []string{"Error. File already exist."}
	} else if !errors.Is(err, os.ErrNotExist) {
		s.logger.Printf("stat upload file %q: %v", filename, err)
		return []string{"Cannot create file."}
	}
	spool, err := os.CreateTemp(s.dataDir, ".gdns2tcp-upload-*.wire")
	if err != nil {
		s.logger.Printf("create upload spool %q: %v", filename, err)
		return []string{"Cannot create file."}
	}

	state := uploadState{
		spool: spool, filename: filename, path: path, spoolPath: spool.Name(),
		fingerprint: fingerprint, total: total, chunkSize: chunkSize, encoding: encoding,
		nextIndex: 0, expires: now.Add(transferTTL),
	}
	s.mu.Lock()
	s.cleanupExpiredLocked(now)
	if _, exists := s.uploads[sid]; exists {
		s.mu.Unlock()
		_ = spool.Close()
		_ = os.Remove(spool.Name())
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
		if tombstone, ok := s.uploadTombstones[sid]; ok && index == tombstone.finalIndex {
			result := tombstone.result
			s.mu.Unlock()
			return []string{result}
		}
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
	if err := writeAll(state.spool, []byte(wireChunk)); err != nil {
		delete(s.uploads, sid)
		s.mu.Unlock()
		_ = state.spool.Close()
		_ = os.Remove(state.spoolPath)
		return []string{"Cannot write file."}
	}
	if index == state.total-1 {
		delete(s.uploads, sid)
		s.mu.Unlock()
		result := s.finishUpload(sid, state)
		s.mu.Lock()
		s.uploadTombstones[sid] = uploadTombstone{fingerprint: state.fingerprint, finalIndex: index, result: result, expires: now.Add(transferTTL)}
		s.mu.Unlock()
		return []string{result}
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
		if state.spool != nil {
			_ = state.spool.Close()
		}
		_ = os.Remove(state.spoolPath)
	}()

	if state.spool == nil {
		return "Upload decode error."
	}
	if err := state.spool.Close(); err != nil {
		return "Cannot write file."
	}
	protected, err := os.CreateTemp(s.dataDir, ".gdns2tcp-upload-protected-*")
	if err != nil {
		return "Cannot create file."
	}
	protectedPath := protected.Name()
	_ = protected.Close()
	defer os.Remove(protectedPath)
	if _, err := codec.DecodeDNSFile(state.spoolPath, protectedPath, state.encoding); err != nil {
		s.logger.Printf("decode upload %q: %v", state.filename, err)
		return "Upload decode error."
	}
	compressed, err := os.CreateTemp(s.dataDir, ".gdns2tcp-upload-compressed-*")
	if err != nil {
		return "Cannot create file."
	}
	compressedPath := compressed.Name()
	_ = compressed.Close()
	defer os.Remove(compressedPath)
	if err := secure.OpenFile(s.secret, protectedPath, compressedPath); err != nil {
		s.logger.Printf("decrypt upload %q: %v", state.filename, err)
		return "Upload decryption error."
	}
	output, err := os.CreateTemp(s.dataDir, ".gdns2tcp-upload-output-*")
	if err != nil {
		return "Cannot create file."
	}
	outputPath := output.Name()
	_ = output.Close()
	defer func() {
		if failed {
			_ = os.Remove(outputPath)
		}
	}()
	written, err := codec.DecompressFileLimit(compressedPath, outputPath, s.maxUploadBytes)
	if err != nil {
		s.logger.Printf("decompress upload %q: %v", state.filename, err)
		failed = true
		return "Upload decompression error."
	}
	if err := publishNoOverwrite(outputPath, state.path); err != nil {
		s.logger.Printf("publish upload %q: %v", state.filename, err)
		failed = true
		return "Cannot write file."
	}
	failed = false
	s.logger.Printf("stored upload %q from %s (%d bytes)", state.filename, sid, written)
	return "-1"
}

func publishNoOverwrite(tmpPath, finalPath string) error {
	if err := os.Link(tmpPath, finalPath); err != nil {
		return err
	}
	return os.Remove(tmpPath)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
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
//
// The first character-string in the response is a per-batch SHA-256 digest
// of the concatenated base64 chunks, prefixed with `s:`. The bootstrap
// script verifies this digest before accepting the batch; that lets a
// single UDP-truncated or middlebox-mangled batch be detected and retried
// immediately, instead of surfacing as a final-file SHA mismatch only
// after thousands of batches have already been downloaded.
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
	chunks := artifact.chunks[from:end]
	sum := sha256.Sum256([]byte(strings.Join(chunks, "")))
	out := make([]string, 0, len(chunks)+1)
	out = append(out, "s:"+hex.EncodeToString(sum[:]))
	out = append(out, chunks...)
	return out
}

func (s *Server) logClientArtifactProgress(client, alias string, artifact clientArtifact, index int) {
	now := time.Now().UTC()
	key := client + "|" + alias
	progress, ok := s.clientTransfers[key]
	if !ok {
		if len(s.clientTransfers) >= maxClientTransferState {
			s.logger.Printf("client %s artifact %s: transfer state table full, skipping progress tracking", client, alias)
			return
		}
		progress = clientTransfer{
			seen:       make([]byte, (len(artifact.chunks)+7)/8),
			lastBucket: -1,
		}
	}
	progress.lastSeen = now
	byteIndex := index / 8
	if byteIndex < 0 || byteIndex >= len(progress.seen) {
		return
	}
	bit := byte(1 << uint(index%8))
	if progress.seen[byteIndex]&bit != 0 {
		s.clientTransfers[key] = progress
		return
	}
	progress.seen[byteIndex] |= bit
	progress.seenCount++
	total := len(artifact.chunks)
	seen := progress.seenCount
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
	for key, progress := range s.clientTransfers {
		if !progress.lastSeen.IsZero() && now.Sub(progress.lastSeen) > clientTransferTTL {
			delete(s.clientTransfers, key)
		}
	}
	for sid, state := range s.uploads {
		if now.Before(state.expires) {
			continue
		}
		if state.spool != nil {
			_ = state.spool.Close()
		}
		if err := os.Remove(state.spoolPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.logger.Printf("remove expired upload spool %q: %v", state.filename, err)
		}
		delete(s.uploads, sid)
		s.logger.Printf("expired upload %q (%s)", state.filename, sid)
	}
	for sid, state := range s.downloads {
		if now.Before(state.expires) {
			continue
		}
		s.releaseCacheLocked(state.cacheKey)
		delete(s.downloads, sid)
		s.logger.Printf("expired download %q (%s)", state.filename, sid)
	}
	for sid, tombstone := range s.uploadTombstones {
		if !now.Before(tombstone.expires) {
			delete(s.uploadTombstones, sid)
		}
	}
	s.evictDownloadCacheLocked(now)
	s.proxyCleanupExpiredLocked(now)
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

// normalizeDomains parses a CSV list of domains — the shape accepted by
// the -domain flag. The first entry is the *canonical* domain (the one
// baked into HMAC signatures via protocol.AuthDomain); every entry
// (including canonical) is added to the accepted-suffix list used by
// hasDomainSuffix / parseCommand to decide whether an inbound QNAME
// belongs to us.
//
// Returns (canonical, all, err). Duplicates are dropped after
// normalization. A single-domain input (no comma) is fully backward
// compatible: canonical == all[0] == normalizeDomain(input).
func normalizeDomains(csv string) (string, []string, error) {
	raw := strings.Split(csv, ",")
	all := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	var canonical string
	for _, r := range raw {
		if strings.TrimSpace(r) == "" {
			continue
		}
		d, err := normalizeDomain(r)
		if err != nil {
			return "", nil, err
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		all = append(all, d)
		if canonical == "" {
			canonical = d
		}
	}
	if canonical == "" {
		return "", nil, errors.New("domain is required")
	}
	return canonical, all, nil
}

// hasAnyDomainSuffix returns (matchedDomain, true) if the QNAME belongs
// to any of the configured accepted domains, or ("", false) otherwise.
// Callers pass the matched suffix on to parseCommand so args are split
// against the *actual* shard the query landed on.
func hasAnyDomainSuffix(name string, domains []string) (string, bool) {
	fqdn := strings.ToLower(dns.Fqdn(name))
	for _, d := range domains {
		if fqdn == d || strings.HasSuffix(fqdn, "."+d) {
			return d, true
		}
	}
	return "", false
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

// parseCommand splits a QNAME into (args, command, ok) against the
// matched domain suffix. Suffix matching and command extraction are
// case-insensitive (resolvers may randomize label case per RFC 5452
// 0x20 or upcase whole labels), but args are returned with their
// original wire case preserved — some args carry base64 payload where
// case is significant. HMAC/session-MAC on the server side lowercase
// args internally for verification.
func parseCommand(name, domain string) ([]string, string, bool) {
	fqdn := dns.Fqdn(name)
	fqdnLower := strings.ToLower(fqdn)
	if fqdnLower != domain && !strings.HasSuffix(fqdnLower, "."+domain) {
		return nil, "", false
	}
	// Compute the byte length of the suffix on the wire so we can strip
	// it from the original-case fqdn without accidentally chopping into
	// mixed-case content.
	suffixLen := len(domain)
	if fqdnLower != domain {
		suffixLen++ // account for the leading dot in ".domain"
	}
	prefix := fqdn[:len(fqdn)-suffixLen]
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
