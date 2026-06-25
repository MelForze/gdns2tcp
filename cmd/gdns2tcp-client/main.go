package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gdns2tcp/internal/codec"
	secure "gdns2tcp/internal/crypto"
	"gdns2tcp/internal/protocol"
)

const defaultDNSPort = "53"
const defaultMaxDownloadBytes int64 = 32 << 20

const (
	// defaultChunkSize is the default and maximum encoded upload chunk size
	// (in characters) the client will attempt before measuring against the
	// 253-char DNS name limit. Independent from the server's artifact chunking.
	defaultChunkSize           = 180
	minChunkSize               = 32
	retryBackoff               = 250 * time.Millisecond
	defaultDownloadParallelism = 32
	maxDownloadParallelism     = 64
	// defaultDownloadBatch is the number of chunks bundled into a single TXT
	// response when using the batched download endpoint. 14 keeps the entire
	// response (~3.5 KB plus headers) safely under the EDNS0 4096-byte UDP
	// buffer across the full range of supported domain lengths.
	defaultDownloadBatch = 14
	maxDownloadBatch     = 32
	progressBarWidth     = 25
)

type config struct {
	domain           string
	mode             string
	pass             string
	inFile           string
	outFile          string
	filename         string
	dnsServer        string
	dnsPort          string
	chunkSize        int
	retries          int
	maxDownloadBytes int64
	tcp              bool
	parallelism      int
	batch            int
	noResume         bool
	cacheDir         string // override for tests; production callers leave empty to use defaultResumeRoot()
}

type txtResolver struct {
	server  string
	port    string
	retries int
	useTCP  bool
	timeout time.Duration

	tcpPoolOnce sync.Once
	tcpPool     *tcpPool
}

type progressBar struct {
	label   string
	total   int
	perStep int
	start   time.Time
	mu      sync.Mutex
	last    int
}

func newProgressBar(label string, total, perStep int) *progressBar {
	return &progressBar{label: label, total: total, perStep: perStep, start: time.Now()}
}

func (pb *progressBar) render(done int) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if done < pb.last {
		return
	}
	pb.last = done
	pct := 0
	if pb.total > 0 {
		pct = done * 100 / pb.total
	}
	filled := progressBarWidth * pct / 100
	var bar string
	switch {
	case done >= pb.total:
		bar = strings.Repeat("=", progressBarWidth)
	case filled == 0:
		bar = ">" + strings.Repeat(" ", progressBarWidth-1)
	default:
		bar = strings.Repeat("=", filled) + ">" + strings.Repeat(" ", progressBarWidth-filled-1)
	}
	elapsed := time.Since(pb.start).Seconds()
	suffix := ""
	if elapsed > 0.5 && done > 0 {
		bps := float64(done) * float64(pb.perStep) / elapsed
		suffix = "  " + formatBPS(bps)
		if done < pb.total && bps > 0 {
			rem := float64(pb.total-done) * float64(pb.perStep) / bps
			suffix += "  ETA " + formatETA(time.Duration(rem*float64(time.Second)))
		}
	}
	fmt.Printf("\r%-12s [%s] %d/%d%s", pb.label, bar, done, pb.total, suffix)
}

func (pb *progressBar) finish(done int) {
	pb.render(done)
	fmt.Println()
}

func formatBPS(bps float64) string {
	const (
		kb = 1024
		mb = 1024 * kb
	)
	switch {
	case bps >= mb:
		return fmt.Sprintf("%.1f MB/s", bps/mb)
	case bps >= kb:
		return fmt.Sprintf("%.1f KB/s", bps/kb)
	default:
		return fmt.Sprintf("%.0f B/s", bps)
	}
}

func formatETA(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// validateConfig checks that the flags required for the requested mode are
// present. It is called once by run() before any network activity, so the
// user receives a clear error message without waiting for DNS.
func validateConfig(mode string, cfg config) error {
	if cfg.domain == "" {
		return errors.New("domain is required")
	}
	switch strings.ToLower(mode) {
	case "list", "upload", "download":
		if cfg.pass == "" {
			return errors.New("pass is required")
		}
	}
	switch strings.ToLower(mode) {
	case "upload":
		if strings.TrimSpace(cfg.inFile) == "" {
			return errors.New("input file is required")
		}
	case "download":
		if strings.TrimSpace(cfg.filename) == "" {
			return errors.New("filename is required for download")
		}
	}
	return nil
}

func run() error {
	cfg := parseFlags()
	if err := validateConfig(cfg.mode, cfg); err != nil {
		return err
	}
	if cfg.dnsServer == "" {
		server, err := resolveDomainServer(cfg.domain)
		if err != nil {
			return err
		}
		cfg.dnsServer = server
		fmt.Printf("using DNS server %s:%s resolved from %s\n", cfg.dnsServer, cfg.dnsPort, cfg.domain)
	}
	resolver := &txtResolver{
		server:  cfg.dnsServer,
		port:    cfg.dnsPort,
		retries: cfg.retries,
		useTCP:  cfg.tcp,
		timeout: 5 * time.Second,
	}

	switch strings.ToLower(cfg.mode) {
	case "test":
		encoding, err := testConnection(resolver, cfg.domain)
		if err != nil {
			return err
		}
		fmt.Printf("server selected %s upload encoding\n", encoding)
	case "list":
		return listFiles(resolver, cfg)
	case "upload":
		return uploadFile(resolver, cfg)
	case "download":
		return downloadFile(resolver, cfg)
	default:
		return fmt.Errorf("unsupported mode %q; use test, list, upload, or download", cfg.mode)
	}
	return nil
}

func parseFlags() config {
	cfg := config{}
	flag.StringVar(&cfg.domain, "domain", "", "authoritative gdns2tcp domain")
	flag.StringVar(&cfg.mode, "mode", "", "operation: test, list, upload, download")
	flag.StringVar(&cfg.pass, "pass", "", "shared encryption secret")
	flag.StringVar(&cfg.inFile, "in", "", "local file to upload")
	flag.StringVar(&cfg.outFile, "out", "", "local output file for downloads")
	flag.StringVar(&cfg.filename, "filename", "", "remote filename to download")
	flag.StringVar(&cfg.dnsServer, "dns-server", "", "DNS server address; empty resolves -domain and uses the first IP")
	flag.StringVar(&cfg.dnsPort, "dns-port", defaultDNSPort, "DNS server port; defaults to 53")
	flag.IntVar(&cfg.chunkSize, "chunk-size", defaultChunkSize, "maximum encoded upload chunk size")
	flag.IntVar(&cfg.retries, "retries", 3, "DNS query attempts before failing")
	flag.Int64Var(&cfg.maxDownloadBytes, "max-download-bytes", defaultMaxDownloadBytes, "maximum decompressed download size")
	flag.BoolVar(&cfg.tcp, "tcp", false, "use TCP instead of UDP for DNS queries")
	flag.IntVar(&cfg.parallelism, "parallelism", defaultDownloadParallelism, "concurrent DNS queries during download (1-64)")
	flag.IntVar(&cfg.batch, "batch", defaultDownloadBatch, "chunks per DNS response when downloading (1-32; 1 disables batching)")
	flag.BoolVar(&cfg.noResume, "no-resume", false, "disable resume from local cache and always fetch all chunks")
	flag.Parse()

	cfg.domain = strings.TrimSuffix(strings.TrimSpace(cfg.domain), ".")
	cfg.mode = strings.TrimSpace(cfg.mode)
	cfg.dnsPort = strings.TrimSpace(cfg.dnsPort)
	if cfg.dnsPort == "" {
		cfg.dnsPort = defaultDNSPort
	}
	if cfg.maxDownloadBytes <= 0 {
		cfg.maxDownloadBytes = defaultMaxDownloadBytes
	}
	if cfg.parallelism < 1 {
		cfg.parallelism = defaultDownloadParallelism
	}
	if cfg.parallelism > maxDownloadParallelism {
		cfg.parallelism = maxDownloadParallelism
	}
	if cfg.batch < 1 {
		cfg.batch = defaultDownloadBatch
	}
	if cfg.batch > maxDownloadBatch {
		cfg.batch = maxDownloadBatch
	}
	return cfg
}

func resolveDomainServer(domain string) (string, error) {
	if domain == "" {
		return "", errors.New("domain is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return "", fmt.Errorf("resolve DNS server from domain %s: %w", domain, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("domain %s did not resolve to an IP address", domain)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return ips[0].String(), nil
}

func (r *txtResolver) query(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", errors.New("empty DNS query name")
	}
	retries := r.retries
	if retries < 1 {
		retries = 1
	}

	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		value, err := r.queryOnce(name)
		if err == nil {
			return value, nil
		}
		lastErr = err
		if attempt < retries {
			time.Sleep(time.Duration(attempt) * retryBackoff)
		}
	}
	return "", lastErr
}

func (r *txtResolver) queryOnce(name string) (string, error) {
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if strings.TrimSpace(r.server) == "" {
		if r.port != "" && r.port != defaultDNSPort {
			return "", errors.New("dns-server is required when dns-port is not 53")
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		values, err := net.DefaultResolver.LookupTXT(ctx, fqdn(name))
		if err != nil {
			return "", err
		}
		if len(values) == 0 {
			return "", fmt.Errorf("no TXT response for %s", name)
		}
		return strings.Join(values, ""), nil
	}

	id := randomDNSID()
	q, err := buildTXTQuery(name, id)
	if err != nil {
		return "", err
	}
	addr := net.JoinHostPort(r.server, r.port)
	var resp []byte
	if r.useTCP {
		// Persistent pool avoids ephemeral-port exhaustion on
		// multi-thousand-query downloads (parallelism=32 + ~11K
		// chunks bursts out ~16K connections within seconds).
		r.tcpPoolOnce.Do(func() { r.tcpPool = newTCPPool(addr) })
		resp, err = r.tcpPool.exchange(q, timeout)
	} else {
		resp, err = exchangeUDP(addr, q, timeout)
	}
	if err != nil {
		return "", err
	}
	value, err := parseTXTResponse(resp, binary.BigEndian.Uint16(q[:2]))
	if err != nil {
		return "", fmt.Errorf("%w for %s", err, name)
	}
	return value, nil
}

func testConnection(resolver *txtResolver, domain string) (string, error) {
	if domain == "" {
		return "", errors.New("domain is required")
	}
	encoding, err := resolver.query("EnCoDiNg.test." + domain)
	if err != nil {
		return "", err
	}
	if encoding != "base64" && encoding != "base32" {
		return "", fmt.Errorf("server returned unsupported encoding %q", encoding)
	}
	return encoding, nil
}

func listFiles(resolver *txtResolver, cfg config) error {
	first, err := resolver.query(authenticatedName(cfg.pass, cfg.domain, "c", nil))
	if err != nil {
		return err
	}
	fmt.Println(first)

	matches := regexp.MustCompile(`Catalog contains (\d+) pages`).FindStringSubmatch(first)
	if len(matches) != 2 {
		return nil
	}
	pages, err := strconv.Atoi(matches[1])
	if err != nil {
		return err
	}
	for page := 0; page < pages; page++ {
		value, err := resolver.query(authenticatedName(cfg.pass, cfg.domain, "c", []string{strconv.Itoa(page)}))
		if err != nil {
			return err
		}
		fmt.Println(value)
	}
	return nil
}

func uploadFile(resolver *txtResolver, cfg config) error {
	inputPath, err := resolveInputPath(cfg.inFile)
	if err != nil {
		return err
	}
	encoding, err := testConnection(resolver, cfg.domain)
	if err != nil {
		return err
	}

	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}
	compressed, err := codec.Compress(raw)
	if err != nil {
		return err
	}
	protected, err := secure.Protect(cfg.pass, compressed)
	if err != nil {
		return err
	}
	encoded, err := codec.EncodeDNSPayload(protected, encoding)
	if err != nil {
		return err
	}
	if encoding == "base32" {
		encoded = strings.ToLower(encoded)
	}

	sid, err := protocol.NewSID()
	if err != nil {
		return err
	}
	filenameLabels, err := protocol.EncodeFilenameLabels(filepath.Base(inputPath))
	if err != nil {
		return err
	}
	effectiveChunkSize, err := effectiveUploadChunkSize(cfg.domain, sid, cfg.chunkSize)
	if err != nil {
		return err
	}
	chunks := codec.ChunkString(encoded, effectiveChunkSize)
	initArgs := append([]string{sid, strconv.Itoa(len(chunks)), strconv.Itoa(effectiveChunkSize), encoding}, filenameLabels...)
	initName := authenticatedName(cfg.pass, cfg.domain, "uinit", initArgs)
	if len(initName) > 253 {
		return fmt.Errorf("DNS upload init name is %d characters (limit 253); use a shorter filename or domain", len(initName))
	}
	status, err := resolver.query(initName)
	if err != nil {
		return err
	}
	if status != "Ready to file uploading" {
		return fmt.Errorf("upload initialization failed: %s", status)
	}

	pb := newProgressBar("uploading", len(chunks), effectiveChunkSize)
	index := 0
	for {
		if index >= len(chunks) {
			return fmt.Errorf("server requested chunk %d outside prepared range", index)
		}
		wireChunk := dnsSafeChunk(chunks[index], encoding)
		labels := codec.ChunkString(wireChunk, 63)
		requestArgs := append([]string{sid, strconv.Itoa(index)}, labels...)
		requestName := authenticatedName(cfg.pass, cfg.domain, "u", requestArgs)
		if len(requestName) > 253 {
			return fmt.Errorf("DNS query name for chunk %d is %d characters (limit 253); reduce -chunk-size or use a shorter domain", index, len(requestName))
		}
		response, err := resolver.query(requestName)
		if err != nil {
			return err
		}
		nextIndex, err := strconv.Atoi(response)
		if err != nil {
			return fmt.Errorf("server returned upload error: %s", response)
		}
		if nextIndex == -1 {
			break
		}
		if nextIndex < 0 {
			return fmt.Errorf("server signaled upload failure with code %d", nextIndex)
		}
		index = nextIndex
		pb.render(index)
	}
	pb.finish(len(chunks))
	return nil
}

func downloadFile(resolver *txtResolver, cfg config) error {
	if strings.TrimSpace(cfg.filename) == "" {
		return errors.New("filename is required for download")
	}
	outputPath := cfg.outFile
	if strings.TrimSpace(outputPath) == "" {
		outputPath = cfg.filename
	}
	outputPath, err := resolveOutputPath(outputPath)
	if err != nil {
		return err
	}

	sid, err := protocol.NewSID()
	if err != nil {
		return err
	}
	filenameLabels, err := protocol.EncodeFilenameLabels(filepath.Base(cfg.filename))
	if err != nil {
		return err
	}
	initArgs := append([]string{sid}, filenameLabels...)
	initName := authenticatedName(cfg.pass, cfg.domain, "dinit", initArgs)
	if len(initName) > 253 {
		return fmt.Errorf("DNS download init name is %d characters (limit 253); use a shorter filename or domain", len(initName))
	}
	chunkCountText, err := resolver.query(initName)
	if err != nil {
		return err
	}
	chunkCount, err := strconv.Atoi(chunkCountText)
	if err != nil || chunkCount <= 0 {
		return fmt.Errorf("download initialization failed: %s", chunkCountText)
	}

	batchSize := cfg.batch
	if batchSize < 1 {
		batchSize = defaultDownloadBatch
	}
	parallelism := cfg.parallelism
	if parallelism < 1 {
		parallelism = defaultDownloadParallelism
	}
	nBatches := (chunkCount + batchSize - 1) / batchSize
	batchResults := make([]string, nBatches)
	batchErrors := make([]error, nBatches)
	var completedChunks int64

	cacheRoot := cfg.cacheDir
	if cacheRoot == "" {
		cacheRoot = defaultResumeRoot()
	}
	cache := newResumeCache(cacheRoot, cfg.domain, cfg.filename, !cfg.noResume)
	completed, _ := cache.loadCompleted(chunkCount, batchSize)
	usedCachedBatches := len(completed) > 0
	if err := cache.saveMeta(chunkCount, batchSize); err != nil {
		return fmt.Errorf("write resume meta: %w", err)
	}
	for k, data := range completed {
		if k < 0 || k >= nBatches {
			continue
		}
		batchResults[k] = data
		from := k * batchSize
		count := batchSize
		if from+count > chunkCount {
			count = chunkCount - from
		}
		atomic.AddInt64(&completedChunks, int64(count))
	}

	sem := make(chan struct{}, parallelism)
	var wg sync.WaitGroup
	pb := newProgressBar("downloading", chunkCount, codec.TXTChunkSize)
	if initial := int(atomic.LoadInt64(&completedChunks)); initial > 0 {
		pb.render(initial)
	}
	for k := 0; k < nBatches; k++ {
		if _, done := completed[k]; done {
			continue
		}
		k := k
		from := k * batchSize
		count := batchSize
		if from+count > chunkCount {
			count = chunkCount - from
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-sem; wg.Done() }()
			var name string
			if batchSize == 1 {
				name = authenticatedName(cfg.pass, cfg.domain, "d", []string{sid, strconv.Itoa(from)})
			} else {
				name = authenticatedName(cfg.pass, cfg.domain, "db", []string{sid, strconv.Itoa(from), strconv.Itoa(count)})
			}
			batchResults[k], batchErrors[k] = resolver.query(name)
			if batchErrors[k] == nil {
				_ = cache.saveBatch(k, batchResults[k])
				n := atomic.AddInt64(&completedChunks, int64(count))
				pb.render(int(n))
			}
		}()
	}
	wg.Wait()
	pb.finish(int(atomic.LoadInt64(&completedChunks)))

	var encoded strings.Builder
	encoded.Grow(chunkCount * codec.TXTChunkSize)
	for k, err := range batchErrors {
		if err != nil {
			return fmt.Errorf("batch starting at chunk %d: %w", k*batchSize, err)
		}
		encoded.WriteString(batchResults[k])
	}

	raw, err := decodeDownloadedPayload(encoded.String(), cfg.pass, cfg.maxDownloadBytes)
	if err != nil {
		if usedCachedBatches && !cfg.noResume {
			_ = cache.clear()
			retryCfg := cfg
			retryCfg.noResume = true
			return downloadFile(resolver, retryCfg)
		}
		return err
	}
	if err := writeOutput(outputPath, raw); err != nil {
		return err
	}
	_ = cache.clear()
	fmt.Printf("saved %s\n", outputPath)
	return nil
}

func decodeDownloadedPayload(encoded, pass string, maxDownloadBytes int64) ([]byte, error) {
	protected, err := codec.DecodeDNSPayload(encoded, "base64")
	if err != nil {
		return nil, fmt.Errorf("decode download payload: %w", err)
	}
	compressed, err := secure.Open(pass, protected)
	if err != nil {
		return nil, err
	}
	raw, err := codec.DecompressLimit(compressed, maxDownloadBytes)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func resolveInputPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("input file is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("input path is a directory: %s", abs)
	}
	return abs, nil
}

func resolveOutputPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("output file is required")
	}
	return filepath.Abs(path)
}

func writeOutput(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("output file already exists: %s", path)
	}
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("write output file: %w", writeErr)
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close output file: %w", closeErr)
	}
	return nil
}

func effectiveUploadChunkSize(domain, sid string, requested int) (int, error) {
	if requested <= 0 {
		requested = defaultChunkSize
	}
	if requested > defaultChunkSize {
		requested = defaultChunkSize
	}
	for size := requested; size >= minChunkSize; size-- {
		dummy := strings.Repeat("a", size)
		args := append([]string{sid, "999999"}, codec.ChunkString(dummy, 63)...)
		name := authenticatedNameWithTimestamp("secret", domain, "u", args, protocol.CurrentTimestamp(time.Now()))
		if len(name) <= 253 {
			return size, nil
		}
	}
	return 0, errors.New("domain is too long for DNS upload chunks")
}

func dnsSafeChunk(chunk, encoding string) string {
	safe := strings.NewReplacer("+", "_", "/", "-", "=", "").Replace(chunk)
	if encoding == "base32" {
		return strings.ToLower(safe)
	}
	return safe
}

func authenticatedName(secret, domain, command string, args []string) string {
	return authenticatedNameWithTimestamp(secret, domain, command, args, protocol.CurrentTimestamp(time.Now()))
}

func authenticatedNameWithTimestamp(secret, domain, command string, args []string, timestamp string) string {
	token := protocol.AuthToken(secret, domain, command, timestamp, args)
	labels := make([]string, 0, len(args)+3)
	labels = append(labels, args...)
	labels = append(labels, timestamp, token)
	return protocol.JoinName(domain, command, labels)
}
