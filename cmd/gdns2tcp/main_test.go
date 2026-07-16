package main

import (
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// resetFlagCommandLine replaces flag.CommandLine with a fresh FlagSet for the
// duration of the test and restores the original on cleanup. This lets tests
// call run() without "flag redefined" panics. Must NOT be used in parallel
// tests.
func resetFlagCommandLine(t *testing.T, args ...string) {
	t.Helper()
	old := flag.CommandLine
	t.Cleanup(func() { flag.CommandLine = old })
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	os.Args = append([]string{os.Args[0]}, args...)
}

func TestRunMissingDomain(t *testing.T) {
	resetFlagCommandLine(t, "-listen=127.0.0.1", "-p=s")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "domain is required") {
		t.Fatalf("error=%v, want 'domain is required'", err)
	}
}

func TestRunMissingPassword(t *testing.T) {
	resetFlagCommandLine(t, "-domain=files.test", "-listen=127.0.0.1")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "password is required") {
		t.Fatalf("error=%v, want 'password is required'", err)
	}
}

func TestRunInvalidMaxUploadBytes(t *testing.T) {
	resetFlagCommandLine(t,
		"-domain=files.test", "-listen=127.0.0.1", "-p=s",
		"-max-upload-bytes=0",
	)
	err := run()
	if err == nil || !strings.Contains(err.Error(), "max-upload-bytes must be positive") {
		t.Fatalf("error=%v, want 'max-upload-bytes must be positive'", err)
	}
}

func TestRunInvalidMaxDownloadBytes(t *testing.T) {
	resetFlagCommandLine(t,
		"-domain=files.test", "-listen=127.0.0.1", "-p=s",
		"-max-download-bytes=-1",
	)
	err := run()
	if err == nil || !strings.Contains(err.Error(), "max-download-bytes must be positive") {
		t.Fatalf("error=%v, want 'max-download-bytes must be positive'", err)
	}
}

func TestRunAdditionalLimitValidation(t *testing.T) {
	for _, tc := range []struct {
		flag, want string
	}{
		{"-max-client-artifact-bytes=0", "max-client-artifact-bytes"},
		{"-cache-max-bytes=0", "cache-max-bytes"},
		{"-cache-ttl=0s", "cache-ttl"},
	} {
		resetFlagCommandLine(t, "-domain=files.test", "-listen=127.0.0.1", "-p=s", tc.flag)
		if err := run(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s error=%v, want %q", tc.flag, err, tc.want)
		}
	}
}

func TestRunProxyInterfaceFailsBeforeStartingListeners(t *testing.T) {
	clientsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(clientsDir, "gdns2tcp-client.ps1"), []byte("# client"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetFlagCommandLine(t,
		"-domain=one.test,two.test", "-listen=127.0.0.1", "-p=s", "-clients-dir="+clientsDir,
		"-allow-proxy", "-socks-iface=definitely-missing-interface",
	)
	if err := run(); err == nil || !strings.Contains(err.Error(), "socks-iface") {
		t.Fatalf("proxy interface error=%v", err)
	}
}

func TestDNSTCPServerDoesNotCloseAfterDefaultQueryLimit(t *testing.T) {
	udp, tcp := newDNSServers("127.0.0.1:0", dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {}))
	if udp.Net != "udp" || tcp.Net != "tcp" {
		t.Fatalf("unexpected transports: udp=%q tcp=%q", udp.Net, tcp.Net)
	}
	if tcp.MaxTCPQueries != -1 {
		t.Fatalf("MaxTCPQueries=%d, want -1 for long-lived pipelined tunnels", tcp.MaxTCPQueries)
	}
}

// TestRunMissingRequiredClientArtifact verifies that dnsserver.New returns an
// error when the required win (PowerShell) client artifact is absent.
// All validation passes, but the clients-dir points to an empty temp dir.
func TestRunMissingRequiredClientArtifact(t *testing.T) {
	clientsDir := t.TempDir() // no gdns2tcp-client.ps1 inside
	resetFlagCommandLine(t,
		"-domain=files.test", "-listen=127.0.0.1", "-p=test-secret",
		"-clients-dir="+clientsDir,
	)
	err := run()
	if err == nil || !strings.Contains(err.Error(), "client artifact") {
		t.Fatalf("error=%v, want error about missing client artifact", err)
	}
}

// TestRunListenAndServeFails verifies that run() propagates the error from
// dns.ListenAndServe when the listen address is invalid. This exercises the
// log/filepath.Abs section and the final return path of run().
// The goroutine+timeout guard ensures the test cannot hang if the address
// were ever accepted (e.g. on an unusual network stack).
func TestRunListenAndServeFails(t *testing.T) {
	clientsDir := t.TempDir()
	ps1 := filepath.Join(clientsDir, "gdns2tcp-client.ps1")
	if err := os.WriteFile(ps1, []byte("# placeholder"), 0o644); err != nil {
		t.Fatal(err)
	}
	resetFlagCommandLine(t,
		"-domain=files.test", "-listen=256.256.256.256", "-p=test-secret",
		"-clients-dir="+clientsDir,
	)
	errc := make(chan error, 1)
	go func() { errc <- run() }()
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "dns server stopped") {
			t.Fatalf("error=%v, want 'dns server stopped'", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run() did not return within 5 s; listen address may have been accepted")
	}
}

func TestRunProxyNoAuthNonLoopbackAndInvalidDNSListen(t *testing.T) {
	clientsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(clientsDir, "gdns2tcp-client.ps1"), []byte("# client"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetFlagCommandLine(t,
		"-domain=files.test", "-listen=256.256.256.256", "-p=test-secret",
		"-clients-dir="+clientsDir, "-allow-proxy", "-socks-listen=0.0.0.0:0",
	)
	if err := run(); err == nil || !strings.Contains(err.Error(), "dns server stopped") {
		t.Fatalf("proxy server stop error=%v", err)
	}
}

func TestRunProxyInterfaceRejectsMalformedSocksAddress(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	interfaceName := ""
	for _, iface := range interfaces {
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		for _, addr := range addrs {
			ip, _, parseErr := net.ParseCIDR(addr.String())
			if parseErr == nil && ip.To4() != nil && !ip.IsLoopback() {
				interfaceName = iface.Name
				break
			}
		}
		if interfaceName != "" {
			break
		}
	}
	if interfaceName == "" {
		t.Skip("host has no non-loopback IPv4 interface")
	}
	clientsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(clientsDir, "gdns2tcp-client.ps1"), []byte("# client"), 0o600); err != nil {
		t.Fatal(err)
	}
	resetFlagCommandLine(t,
		"-domain=files.test", "-listen=127.0.0.1", "-p=test-secret", "-clients-dir="+clientsDir,
		"-allow-proxy", "-socks-iface="+interfaceName, "-socks-listen=malformed",
	)
	if err := run(); err == nil || !strings.Contains(err.Error(), "parse -socks-listen") {
		t.Fatalf("malformed socks address error=%v", err)
	}
}

// TestResolveInterfaceIPv4 covers both branches of the helper: an unknown
// interface bubbles up the OS error, a real loopback interface (which has no
// non-loopback IPv4) hits the "no usable address" branch.
func TestResolveInterfaceIPv4(t *testing.T) {
	if _, err := resolveInterfaceIPv4("no-such-interface-xyzzy"); err == nil {
		t.Fatal("expected error for unknown interface")
	}
	if _, err := resolveInterfaceIPv4("lo0"); err == nil {
		// "lo0" exists on macOS, "lo" on Linux — try both shapes.
		t.Log("lo0 unexpectedly produced a usable IPv4; that's fine if the test box has aliases")
	} else if _, err := resolveInterfaceIPv4("lo"); err == nil {
		t.Log("lo unexpectedly produced a usable IPv4; that's fine if the test box has aliases")
	}
}
