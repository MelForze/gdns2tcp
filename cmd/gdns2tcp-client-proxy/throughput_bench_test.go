//go:build bench_e2e

// Reverse-SOCKS5 throughput matrix (agent ↔ server DNS + operator SOCKS5).
// Opt-in behind the bench_e2e tag; run with:
//
//   go test -tags bench_e2e -run TestReverseSocksThroughput -v -timeout 30m \
//       ./cmd/gdns2tcp-client-proxy
//
// Uses the existing testBulkEcho helper: the operator writes N bytes into
// SOCKS, upstream echoes them back, operator reads N bytes. Bidirectional
// bandwidth = 2·N bytes crossing the DNS tunnel per elapsed second.
package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// bulkEchoBench mirrors testBulkEcho but takes an explicit read deadline so
// large-payload runs on slower transports (e.g. 100 MiB via TCP DNS) do not
// trip the 120 s hard-coded timeout that the ordinary correctness test uses.
func bulkEchoBench(t *testing.T, useTCP bool, payloadSize int, readDeadline time.Duration) {
	t.Helper()
	if testing.Short() {
		t.Skip("integration")
	}
	var dnsIP, dnsPort, socksAddr, secret string
	if useTCP {
		dnsIP, dnsPort, socksAddr, secret = startTCPEmbeddedServer(t)
	} else {
		dnsIP, dnsPort, socksAddr, secret = startEmbeddedServer(t)
	}
	upstream := echoUpstream(t)

	agentCfg := config{
		domain:        "files.test",
		pass:          secret,
		dnsServer:     dnsIP,
		dnsPort:       dnsPort,
		tcp:           useTCP,
		pollMin:       2 * time.Millisecond,
		pollMax:       20 * time.Millisecond,
		maxConn:       4,
		retries:       3,
		targetTimeout: 2 * time.Second,
	}
	_ = startTestAgent(t, agentCfg)

	op := socks5Connect(t, socksAddr, secret, upstream)
	defer op.Close()

	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i*7 ^ (i >> 8))
	}

	writeErr := make(chan error, 1)
	go func() {
		_, err := op.Write(payload)
		writeErr <- err
	}()

	got := make([]byte, payloadSize)
	_ = op.SetReadDeadline(time.Now().Add(readDeadline))
	if _, err := io.ReadFull(op, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		for i := range payload {
			if got[i] != payload[i] {
				t.Fatalf("first divergence at byte %d: got %#x want %#x", i, got[i], payload[i])
			}
		}
	}
	_ = net.IP{} // keep the "net" import used even if reorg
}

type socksBenchRow struct {
	tp        string
	sizeBytes int
	elapsed   time.Duration
}

// Effective one-way throughput of a bidirectional echo.
// Bytes leaving the operator = N; bytes coming back = N; total = 2N.
// We report the 2N/elapsed value as "tunnel throughput" and also the
// per-direction N/elapsed for comparison with the file-client rows.
func (r socksBenchRow) tunnelMbps() float64 {
	return float64(r.sizeBytes*2*8) / 1_000_000 / r.elapsed.Seconds()
}
func (r socksBenchRow) perDirMbps() float64 {
	return float64(r.sizeBytes*8) / 1_000_000 / r.elapsed.Seconds()
}
func (r socksBenchRow) perDirMibs() float64 {
	return float64(r.sizeBytes) / (1024 * 1024) / r.elapsed.Seconds()
}

func TestReverseSocksThroughput(t *testing.T) {
	sizesMiB := []int{1, 12, 32, 100}
	var rows []socksBenchRow

	for _, mb := range sizesMiB {
		size := mb * 1024 * 1024
		for _, useTCP := range []bool{false, true} {
			label := "UDP"
			if useTCP {
				label = "TCP"
			}
			t.Run(fmt.Sprintf("%dMiB_%s", mb, label), func(t *testing.T) {
				// Give TCP-DNS bulk transfers ample time — 100 MiB via
				// TCP DNS in this setup runs at ≈ 6-10 Mbps end-to-end.
				deadline := 5 * time.Minute
				start := time.Now()
				bulkEchoBench(t, useTCP, size, deadline)
				elapsed := time.Since(start)
				rows = append(rows, socksBenchRow{
					tp: label + " DNS", sizeBytes: size, elapsed: elapsed,
				})
				t.Logf("  %d MiB / %s DNS: %.2fs, tunnel %.2f Mbps, per-direction %.2f Mbps",
					mb, label, elapsed.Seconds(),
					float64(size*2*8)/1_000_000/elapsed.Seconds(),
					float64(size*8)/1_000_000/elapsed.Seconds())
			})
		}
	}

	// Render as an extension of the file-client table format.
	var b strings.Builder
	b.WriteString("\n\n### Reverse SOCKS5 throughput (echo — bidirectional)\n\n")
	b.WriteString("| Mode          | Direction        | DNS     | Size    | Elapsed | Tunnel (2× bytes) | Per-direction   | MiB/s   |\n")
	b.WriteString("| ------------- | ---------------- | ------- | ------- | ------- | ----------------- | --------------- | ------- |\n")
	for _, r := range rows {
		size := strconv.Itoa(r.sizeBytes/(1024*1024)) + " MiB"
		b.WriteString(fmt.Sprintf(
			"| ReverseSOCKS5 | Echo (bidir)     | %-7s | %-7s | %6.2fs | %10.2f Mbps    | %8.2f Mbps    | %6.2f  |\n",
			r.tp, size, r.elapsed.Seconds(), r.tunnelMbps(), r.perDirMbps(), r.perDirMibs()))
	}
	t.Log(b.String())
}
