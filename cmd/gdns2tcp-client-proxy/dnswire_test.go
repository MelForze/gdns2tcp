package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"gdns2tcp/internal/dnshelpers"
	gproxy "gdns2tcp/internal/proxy"
)

func TestParseTXTSegmentsErrors(t *testing.T) {
	if _, err := parseTXTSegments([]byte{0x00, 0x01}, 1); err == nil {
		t.Fatal("expected error for too-short response")
	}
	mismatchID := make([]byte, 12)
	mismatchID[0], mismatchID[1] = 0xAB, 0xCD
	if _, err := parseTXTSegments(mismatchID, 1); err == nil {
		t.Fatal("expected error for ID mismatch")
	}
	// Build a NXDOMAIN response (rcode 3 in low nibble of byte 3).
	bad := make([]byte, 12)
	bad[0], bad[1] = 0x00, 0x01
	bad[3] = 0x03
	if _, err := parseTXTSegments(bad, 1); err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Fatalf("expected NXDOMAIN error, got %v", err)
	}
	// TC=1 truncation.
	tc := make([]byte, 12)
	tc[0], tc[1] = 0x00, 0x01
	tc[2] = 0x02
	if _, err := parseTXTSegments(tc, 1); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected TC=1 truncation error, got %v", err)
	}
}

func TestFqdn(t *testing.T) {
	if got := fqdn("example.com"); got != "example.com." {
		t.Fatalf("fqdn missing dot: %q", got)
	}
	if got := fqdn("example.com."); got != "example.com." {
		t.Fatalf("fqdn double-dotted: %q", got)
	}
}

func TestBuildTXTQueryLabelLimit(t *testing.T) {
	if _, err := buildTXTQuery(strings.Repeat("a", 64)+".example.com", 1); err == nil {
		t.Fatal("expected error for 64-char label (>63 limit)")
	}
}

func TestUDPPoolExchange(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 2 {
				continue
			}
			resp := make([]byte, 12)
			copy(resp[:2], buf[:2])
			resp[2] = 0x80
			resp[3] = 0x00
			binary.BigEndian.PutUint16(resp[4:6], 0)
			binary.BigEndian.PutUint16(resp[6:8], 1)
			resp = append(resp, 0x00)
			var trailer [4]byte
			binary.BigEndian.PutUint16(trailer[0:2], 16)
			binary.BigEndian.PutUint16(trailer[2:4], 1)
			resp = append(resp, trailer[:]...)
			resp = append(resp, 0x00, 0x04)
			resp = append(resp, 0x03, 'O', 'K', '!')
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	pool, err := newUDPPool(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.close()

	q, err := buildTXTQuery("test.example.com", 42)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := pool.exchange(q, 2*1000_000_000)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp) < 12 {
		t.Fatal("response too short")
	}
	gotID := binary.BigEndian.Uint16(resp[:2])
	wantID := binary.BigEndian.Uint16(q[:2])
	if gotID != wantID {
		t.Fatalf("ID mismatch: got %d want %d", gotID, wantID)
	}
}

func TestUDPPoolReconnectAfterSocketClose(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 2 {
				continue
			}
			resp := make([]byte, 12)
			copy(resp[:2], buf[:2])
			resp[2] = 0x80
			resp[3] = 0x00
			binary.BigEndian.PutUint16(resp[4:6], 0)
			binary.BigEndian.PutUint16(resp[6:8], 1)
			resp = append(resp, 0x00)
			var trailer [4]byte
			binary.BigEndian.PutUint16(trailer[0:2], 16)
			binary.BigEndian.PutUint16(trailer[2:4], 1)
			resp = append(resp, trailer[:]...)
			resp = append(resp, 0x00, 0x04)
			resp = append(resp, 0x03, 'O', 'K', '!')
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	pool, err := newUDPPool(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.close()

	q, err := buildTXTQuery("test.example.com", 42)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.exchange(q, 2*time.Second); err != nil {
		t.Fatalf("initial exchange: %v", err)
	}

	for _, e := range pool.conns {
		e.mu.Lock()
		conn := e.conn
		e.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
	}
	waitUDPPoolClosedEntries(t, pool)

	q, err = buildTXTQuery("test.example.com", 43)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.exchange(q, 2*time.Second); err != nil {
		t.Fatalf("exchange after socket close: %v", err)
	}
}

func waitUDPPoolClosedEntries(t *testing.T, pool *udpPool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		allClosed := true
		for _, e := range pool.conns {
			e.mu.Lock()
			closed := e.closed || e.conn == nil
			e.mu.Unlock()
			allClosed = allClosed && closed
		}
		if allClosed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("UDP pool entries did not observe forced socket close")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUDPPoolExchangeTimeout(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	pool, err := newUDPPool(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.close()

	q, _ := buildTXTQuery("test.example.com", 99)
	_, err = pool.exchange(q, 50_000_000) // 50ms
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestUDPPoolExchangeClosedPool(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	pool, err := newUDPPool(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	pool.close()

	q, _ := buildTXTQuery("test.example.com", 1)
	_, err = pool.exchange(q, 1_000_000_000)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestUDPPoolExchangeShortQuery(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	pool, err := newUDPPool(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.close()

	_, err = pool.exchange([]byte{0x01}, 1_000_000_000)
	if err == nil {
		t.Fatal("expected error for short query")
	}
}

func TestReserveDNSIDLockedSkipsPendingID(t *testing.T) {
	existing := make(chan []byte, 1)
	ch := make(chan []byte, 1)
	nextID := uint16(41)
	pending := map[uint16]chan []byte{42: existing}

	id, err := dnshelpers.ReserveDNSIDLocked(pending, &nextID, ch)
	if err != nil {
		t.Fatal(err)
	}
	if id != 43 {
		t.Fatalf("reserved id=%d, want 43", id)
	}
	if pending[42] != existing {
		t.Fatal("existing pending id was overwritten")
	}
	dnshelpers.DeletePendingIfOwnedLocked(pending, 42, ch)
	if pending[42] != existing {
		t.Fatal("DeletePendingIfOwnedLocked removed a channel it did not own")
	}
	dnshelpers.DeletePendingIfOwnedLocked(pending, 43, ch)
	if _, ok := pending[43]; ok {
		t.Fatal("owned pending id was not removed")
	}
}

// TestMaxAxchgWritePlaintextBytes checks the plaintext budget against the
// actual axchg wire format. For each transport, it assembles a worst-case
// query (maximum-width seq/nonce, base32-encoded sealed payload at the full
// budget, "x-tcp" label when applicable) and asserts the resulting QNAME fits
// inside the 253-char DNS name limit. The previous test only asserted
// `tcp < udp`, which would have passed a regression that silently shrank
// the budget or one that pushed the assembled query past 253 chars.
func TestMaxAxchgWritePlaintextBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		domain string
		tcp    bool
	}{
		{"short-udp", "example.com", false},
		{"short-tcp", "example.com", true},
		{"medium-udp", "files.example.com", false},
		{"medium-tcp", "files.example.com", true},
		{"long-udp", strings.Repeat("a", 60) + ".example.com", false},
		{"long-tcp", strings.Repeat("a", 60) + ".example.com", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Worst-case hex widths — same as handleTunnel's startup check.
			raw := maxAxchgWritePlaintextBytes(tc.domain, tc.tcp, 8, 8)
			if raw < 16 {
				t.Fatalf("budget %d too small to carry useful plaintext", raw)
			}
			got := assembleAxchgQueryLen(tc.domain, tc.tcp, raw)
			if got > 253 {
				t.Fatalf("assembled axchg QNAME %d chars > 253 limit (domain=%q tcp=%v raw=%d)", got, tc.domain, tc.tcp, raw)
			}
		})
	}

	// TCP must yield a strictly smaller budget than UDP for the same
	// domain because the "x-tcp" label adds 6 chars (label + dot).
	if tcp, udp := maxAxchgWritePlaintextBytes("example.com", true, 8, 8), maxAxchgWritePlaintextBytes("example.com", false, 8, 8); tcp >= udp {
		t.Fatalf("tcp %d should be smaller than udp %d (tcp label costs 6 chars)", tcp, udp)
	}

	// Dynamic budget reclaims overhead when seq/nonce are small (typical
	// at the start of a tunnel). With widths 2+2 vs 8+8, the budget
	// should grow by a measurable margin.
	worst := maxAxchgWritePlaintextBytes("example.com", false, 8, 8)
	dyn := maxAxchgWritePlaintextBytes("example.com", false, 2, 2)
	if dyn-worst < 6 {
		t.Fatalf("dynamic budget gain too small: worst=%d dyn=%d (expected ≥+6 bytes)", worst, dyn)
	}
}

// TestMaxAxchgWritePlaintextBytesRefusesLongDomains pins the contract that a
// domain too long to fit any useful payload yields a budget below the 16-byte
// floor handleTunnel enforces, so the agent fails loudly instead of issuing
// queries that overflow the 253-char QNAME and trigger server FORMERR.
func TestMaxAxchgWritePlaintextBytesRefusesLongDomains(t *testing.T) {
	tooLong := strings.Repeat("a", 200) + ".example.com"
	if raw := maxAxchgWritePlaintextBytes(tooLong, false, 8, 8); raw >= 16 {
		t.Fatalf("expected refusal-grade budget for 212-char domain, got %d", raw)
	}
}

// assembleAxchgQueryLen mimics the wire-format encoding agentExchange uses:
// cid . writeSeq . [base32 data labels] . [x-tcp] . readNonce . smac . axchg
// . domain. It returns the total QNAME char count for a worst-case payload
// of `raw` plaintext bytes (raw + 16-byte AES-GCM tag, base32 expansion,
// split into 63-char labels).
func assembleAxchgQueryLen(domain string, tcp bool, raw int) int {
	const (
		cidLen     = 16
		seqMaxLen  = 8 // hex chars, capped at uint32 in practice
		nonceLen   = 8
		smacLen    = 7
		cmdLen     = 5 // "axchg"
		labelLimit = 63
	)
	sealedBytes := raw + 16
	// base32 (no padding) expansion: ceil(8/5).
	encChars := (sealedBytes*8 + 4) / 5
	dataLabels := (encChars + labelLimit - 1) / labelLimit
	total := cidLen + seqMaxLen + encChars + nonceLen + smacLen + cmdLen + len(domain)
	if tcp {
		total += len(gproxy.AxchgTCPMarker)
	}
	// Dots: between every adjacent label. Labels = 2 (cid,seq) + dataLabels
	// + (1 if tcp) + 3 (nonce, smac, axchg) + 1 (domain).
	labels := 2 + dataLabels + 3 + 1
	if tcp {
		labels++
	}
	total += labels - 1
	return total
}

// fakeTCPDNS spins up a TCP listener that speaks DNS-over-TCP framing and
// echoes a minimal TXT response with one segment "OK". It mimics the
// authoritative-server side just enough for the pool to exercise.
func fakeTCPDNS(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				for {
					var prefix [2]byte
					if _, err := io.ReadFull(conn, prefix[:]); err != nil {
						return
					}
					rlen := int(binary.BigEndian.Uint16(prefix[:]))
					buf := make([]byte, rlen)
					if _, err := io.ReadFull(conn, buf); err != nil {
						return
					}
					id := buf[:2]
					resp := make([]byte, 0, 32)
					resp = append(resp, id...)
					resp = append(resp, 0x80, 0x00) // QR=1
					resp = append(resp, 0x00, 0x00) // qdcount
					resp = append(resp, 0x00, 0x01) // ancount
					resp = append(resp, 0x00, 0x00) // ns
					resp = append(resp, 0x00, 0x00) // ar
					resp = append(resp, 0x00)       // name=root
					resp = append(resp, 0x00, 16)   // TYPE=TXT
					resp = append(resp, 0x00, 1)    // CLASS=IN
					resp = append(resp, 0, 0, 0, 0) // TTL
					resp = append(resp, 0x00, 4)    // RDLEN
					resp = append(resp, 3, 'O', 'K', '!')
					var out [2]byte
					binary.BigEndian.PutUint16(out[:], uint16(len(resp)))
					if _, err := conn.Write(out[:]); err != nil {
						return
					}
					if _, err := conn.Write(resp); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	stop = func() {
		_ = ln.Close()
		close(done)
	}
	return ln.Addr().String(), stop
}

func TestTCPPoolExchange(t *testing.T) {
	addr, stop := fakeTCPDNS(t)
	defer stop()
	pool := newTCPPool(addr)
	defer pool.close()
	q, err := buildTXTQuery("test.example.com", 1234)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := pool.exchange(q, 2*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got, want := binary.BigEndian.Uint16(resp[:2]), binary.BigEndian.Uint16(q[:2]); got != want {
		t.Fatalf("DNS ID mismatch: got %d want %d", got, want)
	}
}

// TestTCPPoolMultiplexedIDs runs concurrent exchanges and verifies each gets
// back the ID assigned by the pool, proving the pending-by-ID dispatch in
// readLoop.
func TestTCPPoolMultiplexedIDs(t *testing.T) {
	addr, stop := fakeTCPDNS(t)
	defer stop()
	pool := newTCPPool(addr)
	defer pool.close()
	const N = 50
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := range N {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			q, err := buildTXTQuery("test.example.com", uint16(i+100))
			if err != nil {
				errs[i] = err
				return
			}
			resp, err := pool.exchange(q, 2*time.Second)
			if err != nil {
				errs[i] = err
				return
			}
			if got, want := binary.BigEndian.Uint16(resp[:2]), binary.BigEndian.Uint16(q[:2]); got != want {
				errs[i] = fmt.Errorf("id mismatch: got %d want %d", got, want)
			}
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Fatalf("exchange %d: %v", i, e)
		}
	}
}

// TestTCPPoolReconnect kills the underlying TCP socket of every conn entry
// and confirms a subsequent exchange transparently redials and succeeds.
func TestTCPPoolReconnect(t *testing.T) {
	addr, stop := fakeTCPDNS(t)
	defer stop()
	pool := newTCPPool(addr)
	defer pool.close()

	// First exchange opens the conn.
	q, _ := buildTXTQuery("a.example.com", 1)
	if _, err := pool.exchange(q, 2*time.Second); err != nil {
		t.Fatalf("first exchange: %v", err)
	}

	// Force-close both pool conns. The next exchange must redial.
	for _, e := range pool.conns {
		e.mu.Lock()
		if e.conn != nil {
			_ = e.conn.Close()
		}
		e.mu.Unlock()
	}
	// Give readLoop a moment to observe the close and mark the entry.
	time.Sleep(50 * time.Millisecond)

	q2, _ := buildTXTQuery("b.example.com", 2)
	if _, err := pool.exchange(q2, 2*time.Second); err != nil {
		t.Fatalf("post-reconnect exchange: %v", err)
	}
}

func TestSkipDNSNameBranches(t *testing.T) {
	// Pointer form (top two bits set) — should consume 2 bytes and return.
	pointed := []byte{0xC0, 0x0C}
	if pos, err := skipDNSName(pointed, 0); err != nil || pos != 2 {
		t.Fatalf("pointer form: pos=%d err=%v", pos, err)
	}
	// Truncated label (length byte says 10 but only 2 bytes follow).
	truncated := []byte{0x0A, 'a', 'b'}
	if _, err := skipDNSName(truncated, 0); err == nil {
		t.Fatal("expected error for truncated label")
	}
	// Invalid length-byte top bits (0x80 / 0x40 alone).
	invalid := []byte{0x80, 0x00}
	if _, err := skipDNSName(invalid, 0); err == nil {
		t.Fatal("expected error for invalid label length byte")
	}
}
