package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gdns2tcp/internal/clihelp"
	"gdns2tcp/internal/codec"
	secure "gdns2tcp/internal/crypto"
	"gdns2tcp/internal/protocol"
)

const defaultDNSPort = "53"
const defaultMaxDownloadBytes int64 = 256 << 20

const (
	defaultResumeCacheBytes = int64(1 << 30)
	defaultResumeCacheTTL   = 7 * 24 * time.Hour
)

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
	// domain is the canonical domain used for HMAC. For single-domain
	// configs it also equals the QNAME suffix. For CSV configs it is
	// the first entry.
	domain string
	// shardDomains / shardAuthDomains / shardLongest / shardRotor
	// mirror the agent's fanout state. QNAMEs rotate through the
	// shards round-robin per DNS query (parallel download workers
	// share the atomic counter).
	shardDomains     []string
	shardAuthDomains []string
	shardLongest     string
	shardRotor       *atomic.Uint64
	domainErr        error

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
	cacheDir         string
	modeCount        int

	listMode     bool
	uploadFile   string
	downloadFile string
	testMode     bool
}

type txtResolver struct {
	server  string
	port    string
	retries int
	useTCP  bool
	timeout time.Duration

	poolMu  sync.Mutex
	closed  bool
	tcpPool *tcpPool
}

var errResolverClosed = errors.New("DNS resolver closed")

func (r *txtResolver) close() {
	if r == nil {
		return
	}
	r.poolMu.Lock()
	if r.closed {
		r.poolMu.Unlock()
		return
	}
	r.closed = true
	pool := r.tcpPool
	r.tcpPool = nil
	r.poolMu.Unlock()
	if pool != nil {
		pool.close()
	}
}

func (r *txtResolver) isClosed() bool {
	r.poolMu.Lock()
	closed := r.closed
	r.poolMu.Unlock()
	return closed
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
func validateConfig(cfg config) error {
	if cfg.domainErr != nil {
		return cfg.domainErr
	}
	if cfg.domain == "" {
		return errors.New("domain is required")
	}
	if cfg.modeCount > 1 {
		return errors.New("choose exactly one mode: --list, --upload <file>, --download <file>, or --test")
	}
	if cfg.mode == "" {
		return errors.New("specify --list, --upload <file>, --download <file>, or --test")
	}
	switch cfg.mode {
	case "list", "upload", "download":
		if cfg.pass == "" {
			return errors.New("password is required")
		}
	}
	switch cfg.mode {
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
	return runClient(cfg)
}

func runClient(cfg config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	if cfg.tcp && cfg.dnsServer == "" {
		server, err := systemResolverAddress()
		if err != nil {
			return fmt.Errorf("-tcp needs a discoverable system DNS server; pass -dns-server explicitly: %w", err)
		}
		cfg.dnsServer = server
	}
	if cfg.dnsServer != "" {
		fmt.Printf("using DNS server %s:%s\n", cfg.dnsServer, cfg.dnsPort)
	}
	resolver := &txtResolver{
		server:  cfg.dnsServer,
		port:    cfg.dnsPort,
		retries: cfg.retries,
		useTCP:  cfg.tcp,
		timeout: 5 * time.Second,
	}
	defer func() { resolver.close() }()
	encoding, probeErr := testConnectionSharded(resolver, cfg)
	if !cfg.tcp && errors.Is(probeErr, errDNSResponseTruncated) {
		server := cfg.dnsServer
		if strings.TrimSpace(server) == "" {
			var err error
			server, err = systemResolverAddress()
			if err != nil {
				return fmt.Errorf("UDP DNS was truncated and TCP resolver discovery failed: %w", err)
			}
		}
		resolver.close()
		cfg.tcp = true
		cfg.dnsServer = server
		resolver = &txtResolver{server: server, port: cfg.dnsPort, retries: cfg.retries, useTCP: true, timeout: 5 * time.Second}
		encoding, probeErr = testConnectionSharded(resolver, cfg)
		if probeErr == nil {
			fmt.Printf("DNS probe was truncated over UDP; promoted transfer transport to TCP\n")
		}
	}
	if probeErr != nil {
		return probeErr
	}

	switch strings.ToLower(cfg.mode) {
	case "test":
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

// systemResolverAddress extracts the first configured recursive resolver so
// -tcp can actually use DNS-over-TCP rather than silently falling back to
// net.DefaultResolver's UDP path.  Platforms without resolv.conf receive a
// clear actionable error asking for -dns-server.
func systemResolverAddress() (string, error) {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" && net.ParseIP(fields[1]) != nil {
			return fields[1], nil
		}
	}
	return "", errors.New("no nameserver entry in /etc/resolv.conf")
}

func parseFlags() config {
	cfg := config{}
	installUsage()
	flag.StringVar(&cfg.domain, "domain", "", "authoritative gdns2tcp domain. Accepts a single name or CSV list (a.com,b.com,c.com) — the first is used as the canonical HMAC domain, all are rotated round-robin as QNAME suffixes to spread load across resolver per-zone rate-limits.")
	flag.StringVar(&cfg.domain, "d", "", "short alias for -domain")
	flag.StringVar(&cfg.pass, "password", "", "shared encryption secret")
	flag.StringVar(&cfg.pass, "p", "", "short alias for -password")
	flag.StringVar(&cfg.pass, "pass", "", "deprecated alias for -password")
	flag.BoolVar(&cfg.listMode, "list", false, "list files on the server")
	flag.StringVar(&cfg.uploadFile, "upload", "", "local file to upload")
	flag.StringVar(&cfg.uploadFile, "in", "", "deprecated alias for -upload")
	flag.StringVar(&cfg.downloadFile, "download", "", "remote filename to download")
	flag.StringVar(&cfg.downloadFile, "filename", "", "deprecated alias for -download")
	flag.BoolVar(&cfg.testMode, "test", false, "test connection to the server")
	flag.StringVar(&cfg.outFile, "out", "", "local output file for downloads")
	flag.StringVar(&cfg.dnsServer, "dns-server", "", "DNS server address; empty uses the system resolver")
	flag.StringVar(&cfg.dnsServer, "ds", "", "short alias for -dns-server")
	flag.StringVar(&cfg.dnsPort, "dns-port", defaultDNSPort, "DNS server port; defaults to 53")
	flag.StringVar(&cfg.dnsPort, "dp", defaultDNSPort, "short alias for -dns-port")
	flag.IntVar(&cfg.chunkSize, "chunk-size", defaultChunkSize, "maximum encoded upload chunk size")
	flag.IntVar(&cfg.retries, "retries", 3, "DNS query attempts before failing")
	flag.Int64Var(&cfg.maxDownloadBytes, "max-download-bytes", defaultMaxDownloadBytes, "maximum decompressed download size")
	flag.BoolVar(&cfg.tcp, "tcp", false, "use TCP instead of UDP for DNS queries")
	flag.IntVar(&cfg.parallelism, "parallelism", defaultDownloadParallelism, "concurrent DNS queries during download (1-64)")
	flag.IntVar(&cfg.batch, "batch", defaultDownloadBatch, "chunks per DNS response when downloading (1-32; 1 disables batching)")
	flag.BoolVar(&cfg.noResume, "no-resume", false, "disable resume from local cache and always fetch all chunks")
	flag.StringVar(&cfg.cacheDir, "cache-dir", "", "download resume cache directory (default: OS user cache)")
	flag.Parse()

	cfg.domain, cfg.shardDomains, cfg.shardAuthDomains, cfg.shardLongest, cfg.domainErr = protocol.ParseDomainCSV(cfg.domain)
	cfg.shardRotor = new(atomic.Uint64)

	if cfg.listMode {
		cfg.modeCount++
	}
	if cfg.uploadFile != "" {
		cfg.modeCount++
	}
	if cfg.downloadFile != "" {
		cfg.modeCount++
	}
	if cfg.testMode {
		cfg.modeCount++
	}

	switch {
	case cfg.listMode:
		cfg.mode = "list"
	case cfg.uploadFile != "":
		cfg.mode = "upload"
		cfg.inFile = cfg.uploadFile
	case cfg.downloadFile != "":
		cfg.mode = "download"
		cfg.filename = cfg.downloadFile
	case cfg.testMode:
		cfg.mode = "test"
	}

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
	if !cfg.noResume && cfg.cacheDir == "" {
		cfg.cacheDir = defaultResumeRoot()
	}
	return cfg
}

func installUsage() {
	program := filepath.Base(os.Args[0])
	flag.CommandLine.Usage = func() {
		clihelp.Print(flag.CommandLine.Output(), program,
			"-domain <zone> <mode> [options]",
			[]string{
				fmt.Sprintf("%s -domain files.example.com -test -dns-server 203.0.113.10", program),
				fmt.Sprintf("%s -domain files.example.com -password \"$GDNS_PASS\" -list", program),
				fmt.Sprintf("%s -domain files.example.com -password \"$GDNS_PASS\" -upload ./payload.bin", program),
				fmt.Sprintf("%s -domain files.example.com -password \"$GDNS_PASS\" -download payload.bin -out ./payload.bin", program),
			},
			[]clihelp.Group{
				{
					Title: "Connection and authentication",
					Flags: []clihelp.Flag{
						{Names: "-domain, -d <zone>", Description: "authoritative gdns2tcp zone; CSV enables shard fan-out, first zone is canonical"},
						{Names: "-password, -p <secret>", Description: "shared secret; required for list, upload and download"},
					},
				},
				{
					Title: "Mode: choose exactly one",
					Flags: []clihelp.Flag{
						{Names: "-test", Description: "probe server DNS protocol support; no file transfer"},
						{Names: "-list", Description: "list files available on the server"},
						{Names: "-upload <path>", Description: "upload a local file to the server"},
						{Names: "-download <name>", Description: "download a remote filename from the server"},
					},
				},
				{
					Title: "DNS transport",
					Flags: []clihelp.Flag{
						{Names: "-dns-server, -ds <ip>", Description: "DNS server address; empty uses the system resolver"},
						{Names: "-dns-port, -dp <port>", Description: "DNS server port (default " + defaultDNSPort + ")"},
						{Names: "-tcp", Description: "use TCP instead of UDP for DNS queries"},
						{Names: "-retries <n>", Description: "DNS query attempts before failing (default 3)"},
					},
				},
				{
					Title: "Upload options",
					Flags: []clihelp.Flag{
						{Names: "-chunk-size <n>", Description: fmt.Sprintf("maximum encoded upload chunk size (default %d)", defaultChunkSize)},
					},
				},
				{
					Title: "Download options",
					Flags: []clihelp.Flag{
						{Names: "-out <path>", Description: "local output path; default is the remote filename"},
						{Names: "-max-download-bytes <n>", Description: fmt.Sprintf("maximum decompressed download size (default %d)", defaultMaxDownloadBytes)},
						{Names: "-parallelism <n>", Description: fmt.Sprintf("concurrent download DNS queries, 1-%d (default %d)", maxDownloadParallelism, defaultDownloadParallelism)},
						{Names: "-batch <n>", Description: fmt.Sprintf("chunks per download DNS response, 1-%d; 1 disables batching (default %d)", maxDownloadBatch, defaultDownloadBatch)},
						{Names: "-no-resume", Description: "ignore local resume cache and fetch all chunks again"},
						{Names: "-cache-dir <dir>", Description: "resume spool cache; default is OS user cache (1 GiB / 7 days)"},
					},
				},
				{
					Title: "Deprecated aliases",
					Flags: []clihelp.Flag{
						{Names: "-pass <secret>", Description: "alias for -password"},
						{Names: "-in <path>", Description: "alias for -upload"},
						{Names: "-filename <name>", Description: "alias for -download"},
					},
				},
			},
			[]string{
				"Go's flag parser accepts both -flag and --flag forms.",
				"The client rejects conflicting modes instead of choosing one by precedence.",
				"Use -tcp when UDP truncation, loss, or resolver policy breaks large downloads.",
			},
		)
	}
}

func (r *txtResolver) query(name string) (string, error) {
	return r.queryNames([]string{name})
}

func (r *txtResolver) queryNames(names []string) (string, error) {
	if len(names) == 0 || strings.TrimSpace(names[0]) == "" {
		return "", errors.New("empty DNS query name")
	}
	retries := r.retries
	if retries < 1 {
		retries = 1
	}

	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		name := names[(attempt-1)%len(names)]
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
	if r.isClosed() {
		return "", errResolverClosed
	}
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
		r.poolMu.Lock()
		if r.closed {
			r.poolMu.Unlock()
			return "", errResolverClosed
		}
		if r.tcpPool == nil {
			r.tcpPool = newTCPPool(addr)
		}
		pool := r.tcpPool
		r.poolMu.Unlock()
		resp, err = pool.exchange(q, timeout)
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

func testConnectionSharded(resolver *txtResolver, cfg config) (string, error) {
	domains := cfg.retryShardDomains()
	names := make([]string, len(domains))
	for i, domain := range domains {
		names[i] = "EnCoDiNg.test." + domain
	}
	encoding, err := resolver.queryNames(names)
	if err != nil {
		return "", err
	}
	if encoding != "base64" && encoding != "base32" {
		return "", fmt.Errorf("server returned unsupported encoding %q", encoding)
	}
	return encoding, nil
}

func listFiles(resolver *txtResolver, cfg config) error {
	first, err := resolver.queryNames(authenticatedNames(cfg, "c", nil))
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
		value, err := resolver.queryNames(authenticatedNames(cfg, "c", []string{strconv.Itoa(page)}))
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
	encoding, err := testConnectionSharded(resolver, cfg)
	if err != nil {
		return err
	}

	sid, err := protocol.NewSID()
	if err != nil {
		return err
	}
	filenameLabels, err := protocol.EncodeFilenameLabels(filepath.Base(inputPath))
	if err != nil {
		return err
	}
	effectiveChunkSize, err := effectiveUploadChunkSize(cfg.longestBudgetDomain(), sid, cfg.chunkSize)
	if err != nil {
		return err
	}
	spoolDir, err := os.MkdirTemp("", "gdns2tcp-upload-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(spoolDir)
	gzipPath := filepath.Join(spoolDir, "payload.gz")
	protectedPath := filepath.Join(spoolDir, "payload.gdt")
	encodedPath := filepath.Join(spoolDir, "payload.txt")
	if err := codec.CompressFile(inputPath, gzipPath); err != nil {
		return fmt.Errorf("compress input file: %w", err)
	}
	if err := secure.ProtectFile(cfg.pass, gzipPath, protectedPath); err != nil {
		return err
	}
	encodedSize, err := codec.EncodeDNSFile(protectedPath, encodedPath, encoding)
	if err != nil {
		return err
	}
	if encodedSize <= 0 || encodedSize > int64(^uint(0)>>1) {
		return errors.New("encoded upload size is out of range")
	}
	chunkCount := int((encodedSize + int64(effectiveChunkSize) - 1) / int64(effectiveChunkSize))
	if chunkCount <= 0 {
		return errors.New("upload has no encoded chunks")
	}
	encodedFile, err := os.Open(encodedPath)
	if err != nil {
		return err
	}
	defer encodedFile.Close()
	initArgs := append([]string{sid, strconv.Itoa(chunkCount), strconv.Itoa(effectiveChunkSize), encoding}, filenameLabels...)
	initNames := authenticatedNames(cfg, "uinit", initArgs)
	if len(initNames[0]) > 253 {
		return fmt.Errorf("DNS upload init name is %d characters (limit 253); use a shorter filename or domain", len(initNames[0]))
	}
	status, err := resolver.queryNames(initNames)
	if err != nil {
		return err
	}
	if status != "Ready to file uploading" {
		return fmt.Errorf("upload initialization failed: %s", status)
	}

	pb := newProgressBar("uploading", chunkCount, effectiveChunkSize)
	index := 0
	for {
		if index >= chunkCount {
			return fmt.Errorf("server requested chunk %d outside prepared range", index)
		}
		chunk, err := readSpoolChunk(encodedFile, int64(index)*int64(effectiveChunkSize), effectiveChunkSize)
		if err != nil {
			return fmt.Errorf("read upload spool chunk %d: %w", index, err)
		}
		wireChunk := dnsSafeChunk(string(chunk), encoding)
		labels := codec.ChunkString(wireChunk, 63)
		requestArgs := append([]string{sid, strconv.Itoa(index)}, labels...)
		requestNames := authenticatedNames(cfg, "u", requestArgs)
		if len(requestNames[0]) > 253 {
			return fmt.Errorf("DNS query name for chunk %d is %d characters (limit 253); reduce -chunk-size or use a shorter domain", index, len(requestNames[0]))
		}
		response, err := resolver.queryNames(requestNames)
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
	pb.finish(chunkCount)
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
	initNames := authenticatedNames(cfg, "dinit", initArgs)
	if len(initNames[0]) > 253 {
		return fmt.Errorf("DNS download init name is %d characters (limit 253); use a shorter filename or domain", len(initNames[0]))
	}
	chunkCountText, err := resolver.queryNames(initNames)
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
	sourceSHA256, encodedSize, ok := fetchDownloadSourceSHA256(resolver, cfg, sid, chunkCount)
	if !ok {
		return errors.New("download metadata is unavailable or malformed")
	}
	if err := validateDownloadShape(chunkCount, batchSize, encodedSize, cfg.maxDownloadBytes); err != nil {
		return err
	}
	nBatches := (chunkCount + batchSize - 1) / batchSize

	cacheRoot := cfg.cacheDir
	temporaryCacheRoot := ""
	if cfg.noResume || cacheRoot == "" {
		var err error
		temporaryCacheRoot, err = os.MkdirTemp("", "gdns2tcp-download-*")
		if err != nil {
			return err
		}
		defer os.RemoveAll(temporaryCacheRoot)
		cacheRoot = temporaryCacheRoot
	}
	cache := newResumeCache(cacheRoot, cfg.domain, cfg.filename, true)
	if err := cache.acquireLock(); err != nil {
		return err
	}
	defer cache.close()
	if err := cache.acquireQuotaLock(); err != nil {
		return err
	}
	if temporaryCacheRoot == "" {
		reserveBytes := encodedSize + int64(bitmapBytes(nBatches)) + 4096
		if reserveBytes < encodedSize {
			return errors.New("resume cache reservation overflows int64")
		}
		if err := pruneResumeCacheForLocked(cacheRoot, defaultResumeCacheBytes, defaultResumeCacheTTL, reserveBytes, cache.dir); err != nil {
			return fmt.Errorf("prune download resume cache: %w", err)
		}
	}
	completed, err := cache.open(chunkCount, batchSize, sourceSHA256, encodedSize)
	quotaErr := cache.releaseQuotaLock()
	if err != nil {
		return fmt.Errorf("open download spool: %w", err)
	}
	if quotaErr != nil {
		return fmt.Errorf("release download resume quota lock: %w", quotaErr)
	}
	usedCachedBatches := len(completed) > 0 && temporaryCacheRoot == ""
	var completedChunks int64
	for k := range completed {
		from := k * batchSize
		count := batchSize
		if from+count > chunkCount {
			count = chunkCount - from
		}
		atomic.AddInt64(&completedChunks, int64(count))
	}

	sem := make(chan struct{}, parallelism)
	batchErrors := make([]error, nBatches)
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
			var names []string
			if batchSize == 1 {
				names = authenticatedNames(cfg, "d", []string{sid, strconv.Itoa(from)})
			} else {
				names = authenticatedNames(cfg, "db", []string{sid, strconv.Itoa(from), strconv.Itoa(count)})
			}
			data, queryErr := resolver.queryNames(names)
			if queryErr == nil {
				queryErr = cache.saveBatch(k, from, count, data)
			}
			batchErrors[k] = queryErr
			if queryErr == nil {
				n := atomic.AddInt64(&completedChunks, int64(count))
				pb.render(int(n))
			}
		}()
	}
	wg.Wait()
	pb.finish(int(atomic.LoadInt64(&completedChunks)))
	for k, batchErr := range batchErrors {
		if batchErr != nil {
			return fmt.Errorf("batch starting at chunk %d: %w", k*batchSize, batchErr)
		}
	}
	if err := cache.sync(); err != nil {
		return fmt.Errorf("sync download spool: %w", err)
	}
	spoolPath := cache.path()
	if err := cache.closeSpool(); err != nil {
		return err
	}
	if err := decodeDownloadedFile(spoolPath, cfg.pass, outputPath, cfg.maxDownloadBytes, sourceSHA256); err != nil {
		if usedCachedBatches {
			_ = cache.clear()
			_ = cache.releaseLock()
			retryCfg := cfg
			retryCfg.noResume = true
			return downloadFile(resolver, retryCfg)
		}
		return err
	}
	_ = cache.clear()
	fmt.Printf("saved %s\n", outputPath)
	return nil
}

func fetchDownloadSourceSHA256(resolver *txtResolver, cfg config, sid string, chunkCount int) (string, int64, bool) {
	resp, err := resolver.queryNames(authenticatedNames(cfg, "dmeta", []string{sid}))
	if err != nil {
		return "", 0, false
	}
	metaChunkCount, sourceSHA256, encodedSize, ok := parseDownloadMeta(resp)
	if !ok || metaChunkCount != chunkCount {
		return "", 0, false
	}
	return sourceSHA256, encodedSize, true
}

func parseDownloadMeta(value string) (chunkCount int, sourceSHA256 string, encodedSize int64, ok bool) {
	parts := strings.Split(value, "|")
	if len(parts) != 2 && len(parts) != 3 {
		return 0, "", 0, false
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n <= 0 {
		return 0, "", 0, false
	}
	digest := strings.ToLower(parts[1])
	if len(digest) != sha256HexLength {
		return 0, "", 0, false
	}
	for _, r := range digest {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return 0, "", 0, false
	}
	if len(parts) == 2 {
		return n, digest, 0, true
	}
	encodedSize, err = strconv.ParseInt(parts[2], 10, 64)
	if err != nil || encodedSize <= 0 || encodedSize > int64(n)*codec.TXTChunkSize || encodedSize <= int64(n-1)*codec.TXTChunkSize {
		return 0, "", 0, false
	}
	return n, digest, encodedSize, true
}

const sha256HexLength = 64

func validateDownloadShape(chunkCount, batchSize int, encodedSize, maxDownloadBytes int64) error {
	if chunkCount <= 0 || batchSize <= 0 || encodedSize <= 0 || maxDownloadBytes <= 0 {
		return errors.New("invalid authenticated download metadata")
	}
	maxEncoded := maxDownloadBytes
	if maxEncoded <= (int64(^uint64(0)>>1))/2 {
		maxEncoded *= 2
	} else {
		maxEncoded = int64(^uint64(0) >> 1)
	}
	if encodedSize > maxEncoded {
		return fmt.Errorf("encoded download exceeds configured byte limit")
	}
	maxChunks := (encodedSize + codec.TXTChunkSize - 1) / codec.TXTChunkSize
	if int64(chunkCount) != maxChunks {
		return errors.New("download metadata chunk count does not match encoded size")
	}
	if chunkCount > int(^uint(0)>>1)-batchSize+1 {
		return errors.New("download batch count overflows int")
	}
	return nil
}

// decodeDownloadedFile verifies and transforms the on-disk base64 spool into
// an output temp file, validates the source digest, then atomically publishes
// it without overwriting an existing destination.
func decodeDownloadedFile(spoolPath, pass, outputPath string, maxDownloadBytes int64, sourceSHA256 string) error {
	dir := filepath.Dir(outputPath)
	protected, err := os.CreateTemp(dir, ".gdns2tcp-protected-*")
	if err != nil {
		return err
	}
	protectedPath := protected.Name()
	if err := protected.Close(); err != nil {
		_ = os.Remove(protectedPath)
		return err
	}
	defer os.Remove(protectedPath)
	if _, err := codec.DecodeDNSFile(spoolPath, protectedPath, "base64"); err != nil {
		return fmt.Errorf("decode download payload: %w", err)
	}
	compressed, err := os.CreateTemp(dir, ".gdns2tcp-compressed-*")
	if err != nil {
		return err
	}
	compressedPath := compressed.Name()
	if err := compressed.Close(); err != nil {
		_ = os.Remove(compressedPath)
		return err
	}
	defer os.Remove(compressedPath)
	if err := secure.OpenFile(pass, protectedPath, compressedPath); err != nil {
		return err
	}
	tmpOutput, err := os.CreateTemp(dir, ".gdns2tcp-output-*")
	if err != nil {
		return err
	}
	tmpOutputPath := tmpOutput.Name()
	if err := tmpOutput.Close(); err != nil {
		_ = os.Remove(tmpOutputPath)
		return err
	}
	publish := false
	defer func() {
		if !publish {
			_ = os.Remove(tmpOutputPath)
		}
	}()
	if _, err := codec.DecompressFileLimit(compressedPath, tmpOutputPath, maxDownloadBytes); err != nil {
		return err
	}
	digest, err := fileSHA256(tmpOutputPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(digest, sourceSHA256) {
		return errors.New("download source digest mismatch")
	}
	if err := publishOutputNoOverwrite(tmpOutputPath, outputPath); err != nil {
		return err
	}
	publish = true
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 64*1024)); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func publishOutputNoOverwrite(tmpPath, outputPath string) error {
	if err := os.Link(tmpPath, outputPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output file already exists: %s", outputPath)
		}
		return err
	}
	return os.Remove(tmpPath)
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
		name := authenticatedNameWithTimestamp("secret", domain, protocol.AuthDomain(domain), "u", args, protocol.CurrentTimestamp(time.Now()))
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

func readSpoolChunk(f *os.File, offset int64, max int) ([]byte, error) {
	if max <= 0 || offset < 0 {
		return nil, errors.New("invalid spool read")
	}
	buf := make([]byte, max)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	return buf[:n], nil
}

// authenticatedName builds a signed QNAME. canonicalDomain drives the
// HMAC (server verifies against its own canonical -domain), while
// shardAuthDomain (AuthDomain-normalized) picks the suffix that ends
// the QNAME. For single-domain configs the two are equivalent.
func authenticatedName(secret, canonicalDomain, shardAuthDomain, command string, args []string) string {
	return authenticatedNameWithTimestamp(secret, canonicalDomain, shardAuthDomain, command, args, protocol.CurrentTimestamp(time.Now()))
}

func authenticatedNameWithTimestamp(secret, canonicalDomain, shardAuthDomain, command string, args []string, timestamp string) string {
	token := protocol.AuthToken(secret, canonicalDomain, command, timestamp, args)
	labels := make([]string, 0, len(args)+3)
	labels = append(labels, args...)
	labels = append(labels, timestamp, token)
	// command must already be lowercase — JoinNameFast's contract.
	return protocol.JoinNameFast(shardAuthDomain, command, labels)
}

func authenticatedNames(cfg config, command string, args []string) []string {
	timestamp := protocol.CurrentTimestamp(time.Now())
	token := protocol.AuthToken(cfg.pass, cfg.domain, command, timestamp, args)
	labels := make([]string, 0, len(args)+2)
	labels = append(labels, args...)
	labels = append(labels, timestamp, token)
	domains := cfg.retryShardAuthDomains()
	names := make([]string, len(domains))
	for i, domain := range domains {
		names[i] = protocol.JoinNameFast(domain, command, labels)
	}
	return names
}

// longestBudgetDomain returns the longest configured shard domain, or
// canonical as a fallback for configs constructed without parseFlags
// (test fixtures). Used by the QNAME-length budget calc so no shard
// can silently overflow the 253-char limit.
func (c config) longestBudgetDomain() string {
	if c.shardLongest != "" {
		return c.shardLongest
	}
	return c.domain
}

// pickShardAuthDomain returns the next shard AuthDomain suffix by
// round-robining shardRotor. Single-domain / fallback configs skip
// the atomic and return AuthDomain(cfg.domain).
func (c config) pickShardAuthDomain() string {
	if len(c.shardAuthDomains) == 0 {
		return protocol.AuthDomain(c.domain)
	}
	if len(c.shardAuthDomains) == 1 || c.shardRotor == nil {
		return c.shardAuthDomains[0]
	}
	idx := (c.shardRotor.Add(1) - 1) % uint64(len(c.shardAuthDomains))
	return c.shardAuthDomains[idx]
}

func (c config) retryShardAuthDomains() []string {
	domains := c.shardAuthDomains
	if len(domains) == 0 {
		return []string{protocol.AuthDomain(c.domain)}
	}
	if len(domains) == 1 || c.shardRotor == nil {
		return domains[:1]
	}
	start := int((c.shardRotor.Add(1) - 1) % uint64(len(domains)))
	ordered := make([]string, len(domains))
	for i := range ordered {
		ordered[i] = domains[(start+i)%len(domains)]
	}
	return ordered
}

func (c config) retryShardDomains() []string {
	domains := c.shardDomains
	if len(domains) == 0 {
		return []string{c.domain}
	}
	if len(domains) == 1 || c.shardRotor == nil {
		return domains[:1]
	}
	start := int((c.shardRotor.Add(1) - 1) % uint64(len(domains)))
	ordered := make([]string, len(domains))
	for i := range ordered {
		ordered[i] = domains[(start+i)%len(domains)]
	}
	return ordered
}
