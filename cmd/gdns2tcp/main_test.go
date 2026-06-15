package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	resetFlagCommandLine(t, "-listen=127.0.0.1", "-secret=s")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "domain is required") {
		t.Fatalf("error=%v, want 'domain is required'", err)
	}
}

func TestRunMissingListen(t *testing.T) {
	resetFlagCommandLine(t, "-domain=files.test", "-secret=s")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "listen address is required") {
		t.Fatalf("error=%v, want 'listen address is required'", err)
	}
}

func TestRunMissingSecret(t *testing.T) {
	resetFlagCommandLine(t, "-domain=files.test", "-listen=127.0.0.1")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "secret is required") {
		t.Fatalf("error=%v, want 'secret is required'", err)
	}
}

func TestRunInvalidMaxUploadBytes(t *testing.T) {
	resetFlagCommandLine(t,
		"-domain=files.test", "-listen=127.0.0.1", "-secret=s",
		"-max-upload-bytes=0",
	)
	err := run()
	if err == nil || !strings.Contains(err.Error(), "max-upload-bytes must be positive") {
		t.Fatalf("error=%v, want 'max-upload-bytes must be positive'", err)
	}
}

func TestRunInvalidMaxDownloadBytes(t *testing.T) {
	resetFlagCommandLine(t,
		"-domain=files.test", "-listen=127.0.0.1", "-secret=s",
		"-max-download-bytes=-1",
	)
	err := run()
	if err == nil || !strings.Contains(err.Error(), "max-download-bytes must be positive") {
		t.Fatalf("error=%v, want 'max-download-bytes must be positive'", err)
	}
}

// TestRunMissingRequiredClientArtifact verifies that dnsserver.New returns an
// error when the required win (PowerShell) client artifact is absent.
// All validation passes, but the clients-dir points to an empty temp dir.
func TestRunMissingRequiredClientArtifact(t *testing.T) {
	clientsDir := t.TempDir() // no gdns2tcp-client.ps1 inside
	resetFlagCommandLine(t,
		"-domain=files.test", "-listen=127.0.0.1", "-secret=test-secret",
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
		"-domain=files.test", "-listen=256.256.256.256", "-secret=test-secret",
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
