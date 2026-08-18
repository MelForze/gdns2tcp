//go:build bench_e2e

// End-to-end throughput matrix for the file client, wired against a real
// dns.Server on loopback:0 (see startEmbeddedServer / startEmbeddedTCPServer).
// Runs opt-in behind the bench_e2e build tag so `go test ./...` stays cheap.
//
//   go test -tags bench_e2e -run TestThroughputMatrix -v -timeout 30m \
//       ./cmd/gdns2tcp-client
//
// Prints a Markdown table to the log at the end.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type benchRow struct {
	mode, dir, tp, cache string
	sizeBytes            int64
	elapsed              time.Duration
}

func (r benchRow) mbps() float64 {
	return float64(r.sizeBytes*8) / 1_000_000 / r.elapsed.Seconds()
}
func (r benchRow) mibs() float64 {
	return float64(r.sizeBytes) / (1024 * 1024) / r.elapsed.Seconds()
}

// silenceStdout redirects os.Stdout to /dev/null for the duration of fn.
// The client uses fmt.Printf for its progress bar, which resolves
// os.Stdout dynamically; on a 100 MiB transfer that would flood the test
// log with ~800K progress lines.
func silenceStdout(fn func()) {
	orig := os.Stdout
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		fn()
		return
	}
	os.Stdout = devnull
	defer func() {
		os.Stdout = orig
		_ = devnull.Close()
	}()
	fn()
}

func TestThroughputMatrix(t *testing.T) {
	sizesMiB := []int{1, 12, 32, 100}
	// Upload is a single-threaded chunk-serial loop in the client. Plateau
	// on loopback is ~10 Mbps (UDP) / ~24 Mbps (TCP); 100 MiB still fits
	// under a couple of minutes so include it in the matrix.
	uploadSizesMiB := map[int]bool{1: true, 12: true, 32: true, 100: true}
	rows := make([]benchRow, 0, len(sizesMiB)*6)

	// Fixture cache under scratchpad so we don't hit fs.WriteFile 4x per run.
	fixDir := t.TempDir()
	fixtures := make(map[int]string, len(sizesMiB))
	shas := make(map[int]string, len(sizesMiB))
	for _, mb := range sizesMiB {
		p := filepath.Join(fixDir, fmt.Sprintf("bench-%dm.bin", mb))
		if err := writeRandom(p, int64(mb)*1024*1024); err != nil {
			t.Fatalf("fixture %d MiB: %v", mb, err)
		}
		fixtures[mb] = p
		shas[mb] = shaOf(t, p)
	}

	for _, mb := range sizesMiB {
		sizeBytes := int64(mb) * 1024 * 1024

		for _, useTCP := range []bool{false, true} {
			tpLabel := "UDP"
			if useTCP {
				tpLabel = "TCP"
			}
			t.Run(fmt.Sprintf("%dMiB_%s", mb, tpLabel), func(t *testing.T) {
				dataDir := t.TempDir()
				// place source into server data dir under stable name
				serverFile := filepath.Join(dataDir, fmt.Sprintf("bench-%dm.bin", mb))
				if err := copyFile(fixtures[mb], serverFile); err != nil {
					t.Fatal(err)
				}
				cfg := newServerCfg(t, dataDir)
				cfg.MaxUploadBytes = 200 << 20
				cfg.Logger = log.New(io.Discard, "", 0)

				var ip, port string
				if useTCP {
					ip, port = startEmbeddedTCPServer(t, cfg)
				} else {
					ip, port = startEmbeddedServer(t, cfg)
				}

				resolver := &txtResolver{
					server: ip, port: port,
					retries: 3, useTCP: useTCP, timeout: 10 * time.Second,
				}
				t.Cleanup(resolver.close)

				base := config{
					domain:           "files.test",
					pass:             "integration-test-secret",
					dnsServer:        ip,
					dnsPort:          port,
					retries:          3,
					tcp:              useTCP,
					chunkSize:        defaultChunkSize,
					parallelism:      defaultDownloadParallelism,
					batch:            defaultDownloadBatch,
					noResume:         true,
					maxDownloadBytes: 512 << 20,
				}

				// --- COLD download (first pass — server builds cache) ---
				outCold := filepath.Join(t.TempDir(), "dl-cold.bin")
				dc := base
				dc.filename = filepath.Base(serverFile)
				dc.outFile = outCold
				var coldErr error
				start := time.Now()
				silenceStdout(func() { coldErr = downloadFile(resolver, dc) })
				if coldErr != nil {
					t.Fatalf("cold download: %v", coldErr)
				}
				coldDur := time.Since(start)
				if got := shaOf(t, outCold); got != shas[mb] {
					t.Fatalf("cold download sha mismatch: got %s want %s", got, shas[mb])
				}
				rows = append(rows, benchRow{
					mode: "FileClient", dir: "Download", tp: tpLabel,
					sizeBytes: sizeBytes, cache: "Cold", elapsed: coldDur,
				})

				// --- WARM download (cache hit) ---
				outWarm := filepath.Join(t.TempDir(), "dl-warm.bin")
				dc.outFile = outWarm
				var warmErr error
				start = time.Now()
				silenceStdout(func() { warmErr = downloadFile(resolver, dc) })
				if warmErr != nil {
					t.Fatalf("warm download: %v", warmErr)
				}
				warmDur := time.Since(start)
				if got := shaOf(t, outWarm); got != shas[mb] {
					t.Fatalf("warm download sha mismatch")
				}
				rows = append(rows, benchRow{
					mode: "FileClient", dir: "Download", tp: tpLabel,
					sizeBytes: sizeBytes, cache: "Warm", elapsed: warmDur,
				})

				// --- UPLOAD (skipped for sizes where the sequential client
				// path would take multiple minutes) ---
				var upDur time.Duration
				if uploadSizesMiB[mb] {
					uploadSrc := filepath.Join(t.TempDir(), fmt.Sprintf("up-%dm-%s.bin", mb, tpLabel))
					if err := copyFile(fixtures[mb], uploadSrc); err != nil {
						t.Fatal(err)
					}
					uc := base
					uc.inFile = uploadSrc
					var upErr error
					start = time.Now()
					silenceStdout(func() { upErr = uploadFile(resolver, uc) })
					if upErr != nil {
						t.Fatalf("upload: %v", upErr)
					}
					upDur = time.Since(start)
					serverCopy := filepath.Join(dataDir, filepath.Base(uploadSrc))
					if got := shaOf(t, serverCopy); got != shas[mb] {
						t.Fatalf("upload sha mismatch")
					}
					rows = append(rows, benchRow{
						mode: "FileClient", dir: "Upload", tp: tpLabel,
						sizeBytes: sizeBytes, cache: "-", elapsed: upDur,
					})
				}

				line := fmt.Sprintf("  %d MiB / %s: cold %.2fs (%.2f Mbps)  warm %.2fs (%.2f Mbps)",
					mb, tpLabel,
					coldDur.Seconds(), float64(sizeBytes*8)/1_000_000/coldDur.Seconds(),
					warmDur.Seconds(), float64(sizeBytes*8)/1_000_000/warmDur.Seconds())
				if upDur > 0 {
					line += fmt.Sprintf("  upload %.2fs (%.2f Mbps)", upDur.Seconds(), float64(sizeBytes*8)/1_000_000/upDur.Seconds())
				} else {
					line += "  upload SKIPPED (size too large for sequential client)"
				}
				t.Log(line)
			})
		}
	}

	t.Log(renderMarkdownTable(rows))
}

func writeRandom(path string, size int64) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.CopyN(f, rand.Reader, size)
	return err
}

func shaOf(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func renderMarkdownTable(rows []benchRow) string {
	var b strings.Builder
	b.WriteString("\n\n### Throughput matrix (loopback, go test bench_e2e)\n\n")
	b.WriteString("| Mode        | Direction | DNS | Size    | Cache | Elapsed | Throughput      | MiB/s   |\n")
	b.WriteString("| ----------- | --------- | --- | ------- | ----- | ------- | --------------- | ------- |\n")
	for _, r := range rows {
		size := strconv.Itoa(int(r.sizeBytes/(1024*1024))) + " MiB"
		b.WriteString(fmt.Sprintf(
			"| %-11s | %-9s | %-3s | %-7s | %-5s | %6.2fs | %8.2f Mbps    | %6.2f  |\n",
			r.mode, r.dir, r.tp, size, r.cache,
			r.elapsed.Seconds(), r.mbps(), r.mibs()))
	}
	return b.String()
}
