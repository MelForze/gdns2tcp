package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

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
	)

	flag.StringVar(&domain, "domain", "", "authoritative DNS domain, for example files.example.com")
	flag.StringVar(&domain, "d", "", "short alias for -domain")
	flag.StringVar(&listenHost, "listen", "0.0.0.0", "UDP listen address (defaults to all interfaces)")
	flag.StringVar(&listenHost, "l", "0.0.0.0", "short alias for -listen")
	flag.StringVar(&port, "port", defaultPort, "UDP listen port")
	flag.StringVar(&port, "p", defaultPort, "short alias for -port")
	flag.StringVar(&secret, "secret", "", "shared encryption secret")
	flag.StringVar(&secret, "s", "", "short alias for -secret")
	flag.StringVar(&dataDir, "data-dir", ".", "directory used for uploaded and downloaded files")
	flag.StringVar(&clientsDir, "clients-dir", "clients", "directory containing client artifacts served through client-*/cl-* endpoints")
	flag.Int64Var(&maxUploadBytes, "max-upload-bytes", dnsserver.DefaultMaxUploadBytes, "maximum protected upload payload accepted by the server")
	flag.Int64Var(&maxDownloadBytes, "max-download-bytes", dnsserver.DefaultMaxDownloadBytes, "maximum source file size accepted for DNS downloads")
	flag.BoolVar(&disableList, "disable-list", false, "disable the DNS file listing command")
	flag.BoolVar(&allowProxy, "allow-proxy", false, "enable the reverse SOCKS5 listener and agent DNS endpoints (apoll/aread/awrite/aclose/axchg). Off by default; pass -allow-proxy to turn on.")
	flag.StringVar(&socksListen, "socks-listen", "0.0.0.0:9050", "TCP address for the operator-facing SOCKS5 listener")
	flag.StringVar(&socksIface, "socks-iface", "", "if set, look up this interface's IPv4 address and use it as the SOCKS5 listen host (overrides the host portion of -socks-listen)")
	flag.BoolVar(&socksNoAuth, "socks-no-auth", true, "skip SOCKS5 username/password auth. Default: on (so operators can connect with no credentials). Pass -socks-no-auth=false to require user=gdns2tcp password=<-secret>.")
	flag.IntVar(&proxyMaxConn, "proxy-max-conn", 64, "maximum concurrent tunnel connections")
	flag.IntVar(&proxyBufBytes, "proxy-buf-bytes", 1<<20, "per-tunnel buffer cap (bytes) in each direction")
	flag.Parse()

	if strings.TrimSpace(domain) == "" {
		return errors.New("domain is required")
	}
	if strings.TrimSpace(secret) == "" {
		return errors.New("secret is required")
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
	log.Printf("gdns2tcp listening on udp+tcp://%s for %s", addr, server.Domain())
	log.Printf("data directory: %s", absDataDir)
	log.Printf("clients directory: %s", absClientsDir)
	udpSrv := &dns.Server{Addr: addr, Net: "udp", Handler: server}
	tcpSrv := &dns.Server{Addr: addr, Net: "tcp", Handler: server}
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
