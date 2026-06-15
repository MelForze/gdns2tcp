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
	)

	flag.StringVar(&domain, "domain", "", "authoritative DNS domain, for example files.example.com")
	flag.StringVar(&domain, "d", "", "short alias for -domain")
	flag.StringVar(&listenHost, "listen", "", "UDP listen address")
	flag.StringVar(&listenHost, "l", "", "short alias for -listen")
	flag.StringVar(&port, "port", defaultPort, "UDP listen port")
	flag.StringVar(&port, "p", defaultPort, "short alias for -port")
	flag.StringVar(&secret, "secret", "", "shared encryption secret")
	flag.StringVar(&secret, "s", "", "short alias for -secret")
	flag.StringVar(&dataDir, "data-dir", ".", "directory used for uploaded and downloaded files")
	flag.StringVar(&clientsDir, "clients-dir", "clients", "directory containing client artifacts served through client-*/cl-* endpoints")
	flag.Int64Var(&maxUploadBytes, "max-upload-bytes", dnsserver.DefaultMaxUploadBytes, "maximum protected upload payload accepted by the server")
	flag.Int64Var(&maxDownloadBytes, "max-download-bytes", dnsserver.DefaultMaxDownloadBytes, "maximum source file size accepted for DNS downloads")
	flag.BoolVar(&disableList, "disable-list", false, "disable the DNS file listing command")
	flag.Parse()

	if strings.TrimSpace(domain) == "" {
		return errors.New("domain is required")
	}
	if strings.TrimSpace(listenHost) == "" {
		return errors.New("listen address is required")
	}
	if strings.TrimSpace(secret) == "" {
		return errors.New("secret is required")
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
		},
		AllowList:        !disableList,
		MaxUploadBytes:   maxUploadBytes,
		MaxDownloadBytes: maxDownloadBytes,
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
	errCh := make(chan error, 2)
	go func() { errCh <- udpSrv.ListenAndServe() }()
	go func() { errCh <- tcpSrv.ListenAndServe() }()
	firstErr := <-errCh
	_ = udpSrv.Shutdown()
	_ = tcpSrv.Shutdown()
	<-errCh
	return fmt.Errorf("dns server stopped: %w", firstErr)
}
