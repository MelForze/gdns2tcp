package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof/* on http.DefaultServeMux
	"os"
	"path/filepath"
	"strings"
	"time"

	"gdns2tcp/internal/clihelp"
	"gdns2tcp/internal/dnsserver"

	"github.com/miekg/dns"
)

const defaultPort = "53"

func main() {
	if err := run(); err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		domain           string
		listenHost       string
		port             string
		secret           string
		dataDir          string
		clientsDir       string
		maxUploadBytes   int64
		maxDownloadBytes int64
		disableList      bool
		allowProxy       bool
		socksListen      string
		socksIface       string
		socksNoAuth      bool
		proxyMaxConn     int
		proxyBufBytes    int
		cacheDir         string
		cacheMaxBytes    int64
		cacheTTL         time.Duration
		pprofAddr        string
	)

	installUsage()
	flag.StringVar(&domain, "domain", "", "authoritative DNS domain. Accepts a single name (files.example.com) or a comma-separated list for shard-domain fan-out (files.example.com,files1.example.com,files2.example.com); the first entry is used as the canonical HMAC domain.")
	flag.StringVar(&domain, "d", "", "short alias for -domain")
	flag.StringVar(&listenHost, "listen", "0.0.0.0", "UDP listen address (defaults to all interfaces)")
	flag.StringVar(&listenHost, "l", "0.0.0.0", "short alias for -listen")
	flag.StringVar(&port, "port", defaultPort, "UDP listen port")
	flag.StringVar(&secret, "password", "", "shared encryption secret")
	flag.StringVar(&secret, "p", "", "short alias for -password")
	flag.StringVar(&secret, "pass", "", "deprecated alias for -password")
	flag.StringVar(&dataDir, "data-dir", ".", "directory used for uploaded and downloaded files")
	flag.StringVar(&clientsDir, "clients-dir", "clients", "directory containing client artifacts served through client-*/cl-* endpoints")
	flag.Int64Var(&maxUploadBytes, "max-upload-bytes", dnsserver.DefaultMaxUploadBytes, "maximum protected upload payload accepted by the server")
	flag.Int64Var(&maxDownloadBytes, "max-download-bytes", dnsserver.DefaultMaxDownloadBytes, "maximum source file size accepted for DNS downloads")
	flag.BoolVar(&disableList, "disable-list", false, "disable the DNS file listing command")
	flag.BoolVar(&allowProxy, "allow-proxy", false, "enable the reverse SOCKS5 listener and agent DNS endpoints (apoll/aread/awrite/aclose/axchg). Off by default; pass -allow-proxy to turn on.")
	flag.StringVar(&socksListen, "socks-listen", "127.0.0.1:9050", "TCP address for the operator-facing SOCKS5 listener")
	flag.StringVar(&socksIface, "socks-iface", "", "if set, look up this interface's IPv4 address and use it as the SOCKS5 listen host (overrides the host portion of -socks-listen)")
	flag.BoolVar(&socksNoAuth, "socks-no-auth", true, "skip SOCKS5 username/password auth. Default: on; pass -socks-no-auth=false to require user=gdns2tcp password=<-secret>.")
	flag.IntVar(&proxyMaxConn, "proxy-max-conn", 64, "maximum concurrent tunnel connections")
	flag.IntVar(&proxyBufBytes, "proxy-buf-bytes", 1<<20, "per-tunnel buffer cap (bytes) in each direction")
	flag.StringVar(&cacheDir, "cache-dir", "", "durable download spool cache directory (default <data-dir>/.gdns2tcp-cache)")
	flag.Int64Var(&cacheMaxBytes, "cache-max-bytes", dnsserver.DefaultCacheMaxBytes, "maximum durable download cache size in bytes")
	flag.DurationVar(&cacheTTL, "cache-ttl", dnsserver.DefaultCacheTTL, "download cache retention duration")
	flag.StringVar(&pprofAddr, "pprof-addr", "", "if set, expose net/http/pprof on this addr (e.g. 127.0.0.1:6060). Dev-only.")
	flag.Parse()

	if strings.TrimSpace(pprofAddr) != "" {
		go func() {
			log.Printf("pprof listening on http://%s/debug/pprof/", pprofAddr)
			if err := http.ListenAndServe(pprofAddr, nil); err != nil {
				log.Printf("pprof exited: %v", err)
			}
		}()
	}

	if strings.TrimSpace(domain) == "" {
		return errors.New("domain is required")
	}
	if strings.TrimSpace(secret) == "" {
		return errors.New("password is required")
	}
	if strings.TrimSpace(listenHost) == "" {
		listenHost = "0.0.0.0"
	}
	if maxUploadBytes <= 0 {
		return errors.New("max-upload-bytes must be positive")
	}
	if maxDownloadBytes <= 0 {
		return errors.New("max-download-bytes must be positive")
	}
	if cacheMaxBytes <= 0 {
		return errors.New("cache-max-bytes must be positive")
	}
	if cacheTTL <= 0 {
		return errors.New("cache-ttl must be positive")
	}

	server, err := dnsserver.New(dnsserver.Config{
		Domain:  domain,
		Secret:  secret,
		DataDir: dataDir,
		ClientArtifacts: []dnsserver.ClientArtifactConfig{
			{Alias: "win", Path: filepath.Join(clientsDir, "gdns2tcp-client.ps1"), Required: true},
			{Alias: "linux-amd64", Path: filepath.Join(clientsDir, "gdns2tcp-client-linux-amd64")},
			{Alias: "linux-arm64", Path: filepath.Join(clientsDir, "gdns2tcp-client-linux-arm64")},
			{Alias: "darwin-amd64", Path: filepath.Join(clientsDir, "gdns2tcp-client-darwin-amd64")},
			{Alias: "darwin-arm64", Path: filepath.Join(clientsDir, "gdns2tcp-client-darwin-arm64")},
			{Alias: "client-proxy-linux-amd64", Path: filepath.Join(clientsDir, "gdns2tcp-client-proxy-linux-amd64")},
			{Alias: "client-proxy-linux-arm64", Path: filepath.Join(clientsDir, "gdns2tcp-client-proxy-linux-arm64")},
			{Alias: "client-proxy-darwin-amd64", Path: filepath.Join(clientsDir, "gdns2tcp-client-proxy-darwin-amd64")},
			{Alias: "client-proxy-darwin-arm64", Path: filepath.Join(clientsDir, "gdns2tcp-client-proxy-darwin-arm64")},
			{Alias: "client-proxy-windows-amd64", Path: filepath.Join(clientsDir, "gdns2tcp-client-proxy-windows-amd64.exe")},
			{Alias: "client-proxy-windows-arm64", Path: filepath.Join(clientsDir, "gdns2tcp-client-proxy-windows-arm64.exe")},
		},
		AllowList:        !disableList,
		MaxUploadBytes:   maxUploadBytes,
		MaxDownloadBytes: maxDownloadBytes,
		AllowProxy:       allowProxy,
		SocksNoAuth:      socksNoAuth,
		ProxyMaxConn:     proxyMaxConn,
		ProxyBufBytes:    proxyBufBytes,
		CacheDir:         cacheDir,
		CacheMaxBytes:    cacheMaxBytes,
		CacheTTL:         cacheTTL,
		Logger:           log.Default(),
	})
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(listenHost, port)
	absDataDir := dataDir
	if abs, err := filepath.Abs(dataDir); err == nil {
		absDataDir = abs
	}
	absClientsDir := clientsDir
	if abs, err := filepath.Abs(clientsDir); err == nil {
		absClientsDir = abs
	}
	if all := server.Domains(); len(all) > 1 {
		log.Printf("gdns2tcp listening on udp+tcp://%s for %d shard domains (canonical %s): %s", addr, len(all), server.Domain(), strings.Join(all, ", "))
	} else {
		log.Printf("gdns2tcp listening on udp+tcp://%s for %s", addr, server.Domain())
	}
	log.Printf("data directory: %s", absDataDir)
	log.Printf("clients directory: %s", absClientsDir)
	udpSrv, tcpSrv := newDNSServers(addr, server)
	errCh := make(chan error, 3)
	go func() { errCh <- udpSrv.ListenAndServe() }()
	go func() { errCh <- tcpSrv.ListenAndServe() }()
	if allowProxy {
		if socksIface != "" {
			ip, err := resolveInterfaceIPv4(socksIface)
			if err != nil {
				return fmt.Errorf("resolve -socks-iface %s: %w", socksIface, err)
			}
			_, port, splitErr := net.SplitHostPort(socksListen)
			if splitErr != nil {
				return fmt.Errorf("parse -socks-listen %s: %w", socksListen, splitErr)
			}
			socksListen = net.JoinHostPort(ip, port)
			log.Printf("SOCKS5 bind selected via -socks-iface %s -> %s", socksIface, socksListen)
		}
		if socksNoAuth {
			host, _, _ := net.SplitHostPort(socksListen)
			if host != "127.0.0.1" && host != "::1" && host != "localhost" {
				log.Printf("WARNING: -socks-no-auth + -socks-listen=%s is an open relay reachable by anyone who can route to that address", socksListen)
			}
		}
		go func() { errCh <- server.ServeSOCKS5(socksListen) }()
	}
	firstErr := <-errCh
	server.Shutdown()
	_ = udpSrv.Shutdown()
	_ = tcpSrv.Shutdown()
	return fmt.Errorf("dns server stopped: %w", firstErr)
}

func newDNSServers(addr string, handler dns.Handler) (*dns.Server, *dns.Server) {
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	// gdns2tcp keeps several pipelined DNS requests in flight per connection.
	// miekg/dns otherwise closes a TCP connection after 128 queries, which can
	// discard a response for an already-applied axchg and force an ambiguous
	// nonce retry. Keep direct authoritative connections alive; socket failure
	// and idle timeouts are still handled by the library and the client pools.
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: handler, MaxTCPQueries: -1}
	return udp, tcp
}

func installUsage() {
	program := filepath.Base(os.Args[0])
	flag.CommandLine.Usage = func() {
		clihelp.Print(flag.CommandLine.Output(), program,
			"-domain <zone> -password <secret> [options]",
			[]string{
				fmt.Sprintf("%s -domain files.example.com -password \"$GDNS_PASS\" -clients-dir ./clients", program),
				fmt.Sprintf("%s -domain files.example.com -password \"$GDNS_PASS\" -listen 0.0.0.0 -port 53", program),
				fmt.Sprintf("%s -domain files.example.com -password \"$GDNS_PASS\" -allow-proxy -socks-listen 127.0.0.1:9050", program),
			},
			[]clihelp.Group{
				{
					Title: "Required",
					Flags: []clihelp.Flag{
						{Names: "-domain, -d <zone>", Description: "authoritative DNS zone; CSV enables shard fan-out, first zone is canonical"},
						{Names: "-password, -p <secret>", Description: "shared encryption/authentication secret"},
					},
				},
				{
					Title: "DNS listener",
					Flags: []clihelp.Flag{
						{Names: "-listen, -l <ip>", Description: "DNS listen host (default 0.0.0.0)"},
						{Names: "-port <port>", Description: "DNS UDP+TCP listen port (default " + defaultPort + ")"},
					},
				},
				{
					Title: "Files and transfer limits",
					Flags: []clihelp.Flag{
						{Names: "-data-dir <dir>", Description: "directory for operator files and uploads (default .)"},
						{Names: "-clients-dir <dir>", Description: "directory with downloadable client artifacts (default clients)"},
						{Names: "-disable-list", Description: "disable the DNS file listing command"},
						{Names: "-max-upload-bytes <n>", Description: fmt.Sprintf("maximum protected upload payload (default %d)", dnsserver.DefaultMaxUploadBytes)},
						{Names: "-max-download-bytes <n>", Description: fmt.Sprintf("maximum source file size served for downloads (default %d)", dnsserver.DefaultMaxDownloadBytes)},
					},
				},
				{
					Title: "Download disk cache",
					Flags: []clihelp.Flag{
						{Names: "-cache-dir <dir>", Description: "durable encoded spool cache (default <data-dir>/.gdns2tcp-cache)"},
						{Names: "-cache-max-bytes <n>", Description: fmt.Sprintf("hard cache/build byte quota (default %d)", dnsserver.DefaultCacheMaxBytes)},
						{Names: "-cache-ttl <duration>", Description: "inactive cache retention window (default 24h)"},
					},
				},
				{
					Title: "Reverse SOCKS proxy",
					Flags: []clihelp.Flag{
						{Names: "-allow-proxy", Description: "enable reverse SOCKS5 listener and agent DNS endpoints"},
						{Names: "-socks-listen <host:port>", Description: "operator-facing SOCKS5 listen address (default 127.0.0.1:9050)"},
						{Names: "-socks-iface <name>", Description: "bind SOCKS host to the first non-loopback IPv4 on this interface"},
						{Names: "-socks-no-auth=<bool>", Description: "skip SOCKS username/password auth (default true); set false for user=gdns2tcp and password=secret"},
						{Names: "-proxy-max-conn <n>", Description: "maximum concurrent tunnel connections (default 64)"},
						{Names: "-proxy-buf-bytes <n>", Description: "per-tunnel buffer cap per direction in bytes (default 1048576)"},
					},
				},
				{
					Title: "Diagnostics",
					Flags: []clihelp.Flag{
						{Names: "-pprof-addr <host:port>", Description: "enable net/http/pprof on this address; development only"},
					},
				},
				{
					Title: "Deprecated aliases",
					Flags: []clihelp.Flag{
						{Names: "-pass <secret>", Description: "alias for -password"},
					},
				},
			},
			[]string{
				"Go's flag parser accepts both -flag and --flag forms.",
				"Keep -socks-listen on 127.0.0.1 unless you intentionally expose the proxy.",
			},
		)
	}
}

// resolveInterfaceIPv4 returns the first usable IPv4 address bound to the
// named interface, skipping loopback. Used by the -socks-iface flag so the
// operator can say "bind to eth0" or "wlan0" without having to look up the
// address themselves.
func resolveInterfaceIPv4(name string) (string, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("interface %s has no non-loopback IPv4 address", name)
}
