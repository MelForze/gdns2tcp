package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"gdns2tcp/internal/dnshelpers"
)

func TestBuildTXTQueryPresentationLengthLimit(t *testing.T) {
	valid := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if _, err := buildTXTQuery(valid, 1); err != nil {
		t.Fatalf("253-byte name rejected: %v", err)
	}
	if _, err := buildTXTQuery(valid+"x", 1); err == nil {
		t.Fatal("254-byte name accepted")
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

func TestFQDN(t *testing.T) {
	if got := fqdn("example.com"); got != "example.com." {
		t.Fatalf("fqdn missing trailing dot: %q", got)
	}
	if got := fqdn("example.com."); got != "example.com." {
		t.Fatalf("fqdn double-dotted: %q", got)
	}
}

// fakeTCPDNS serves DNS-over-TCP framed TXT="OK" responses. Enough for
// the pool exchange path to round-trip.
func fakeTCPDNS(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
					id := binary.BigEndian.Uint16(buf[:2])
					resp := makeTXTResp(id, "OK")
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
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func makeTXTResp(id uint16, payload string) []byte {
	resp := make([]byte, 0, 64)
	// header: ID, QR=1, ANCOUNT=1
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	hdr[2] = 0x80
	binary.BigEndian.PutUint16(hdr[6:8], 1)
	resp = append(resp, hdr[:]...)
	// name=root, TYPE=TXT, CLASS=IN, TTL=0
	resp = append(resp, 0x00)
	resp = append(resp, 0x00, 16, 0x00, 1, 0, 0, 0, 0)
	rdlen := 1 + len(payload)
	resp = append(resp, byte(rdlen>>8), byte(rdlen))
	resp = append(resp, byte(len(payload)))
	resp = append(resp, payload...)
	return resp
}

func TestTCPPoolExchange(t *testing.T) {
	addr, stop := fakeTCPDNS(t)
	defer stop()
	pool := newTCPPool(addr)
	defer pool.close()
	q, err := buildTXTQuery("x.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := pool.exchange(q, 2*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if len(resp) < 12 {
		t.Fatalf("resp too short: %d", len(resp))
	}
	// ID should be the one the pool assigned (overwritten in q[:2]).
	if binary.BigEndian.Uint16(resp[:2]) == 0 {
		t.Fatal("id=0 leaked into resp")
	}
}

func TestFileResolverCloseWaitsAndRejectsFurtherExchange(t *testing.T) {
	addr, stop := fakeTCPDNS(t)
	defer stop()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &txtResolver{server: host, port: port, retries: 1, useTCP: true, timeout: time.Second}
	if _, err := resolver.query("x.example.com"); err != nil {
		t.Fatal(err)
	}
	resolver.close()
	if _, err := resolver.query("x.example.com"); !errors.Is(err, errResolverClosed) {
		t.Fatalf("query after close error=%v, want %v", err, errResolverClosed)
	}
	resolver.close()
}

func TestFileTCPEntryBlackHoleAndWriteFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()
	pool := newTCPPool(ln.Addr().String())
	entry := pool.conns[0]
	for i := 0; i < tcpPoolBlackHoleThreshold; i++ {
		q, _ := buildTXTQuery("silent.example.com", uint16(i+1))
		if _, err := entry.exchange(q, 20*time.Millisecond); err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("black-hole exchange %d error=%v", i, err)
		}
	}
	entry.mu.Lock()
	closed := entry.closed && entry.conn == nil && entry.timeoutCount == 0
	entry.mu.Unlock()
	if !closed {
		t.Fatal("black-hole threshold did not close the TCP connection")
	}
	pool.close()
	_ = ln.Close()
	<-serverDone

	badPool := newTCPPool("unused")
	badEntry := badPool.conns[0]
	client, peer := net.Pipe()
	_ = peer.Close()
	badEntry.mu.Lock()
	badEntry.conn = client
	badEntry.closed = false
	badEntry.mu.Unlock()
	q, _ := buildTXTQuery("write-error.example.com", 1)
	if _, err := badEntry.exchange(q, time.Second); err == nil {
		t.Fatal("closed pipe write succeeded")
	}
	badPool.close()
}

func TestFileTCPEntryClosedAndMalformedFrameBranches(t *testing.T) {
	pool := newTCPPool("unused")
	pool.close()
	entry := pool.conns[0]
	entry.mu.Lock()
	err := entry.ensureLocked(time.Millisecond)
	entry.mu.Unlock()
	if !errors.Is(err, errResolverClosed) {
		t.Fatalf("ensure after close error=%v", err)
	}
	var nilPool *tcpPool
	nilPool.close()

	parent := newTCPPool("unused")
	e := parent.conns[0]
	client, peer := net.Pipe()
	e.mu.Lock()
	e.conn = client
	e.closed = false
	parent.wg.Add(1)
	e.mu.Unlock()
	go e.readLoop(client)
	if _, err := peer.Write([]byte{0, 1}); err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	parent.close()
}

func TestTCPPoolExchangeDialFail(t *testing.T) {
	pool := newTCPPool("127.0.0.1:1") // port 1 is reserved / usually refused
	q, _ := buildTXTQuery("x.example.com", 1)
	if _, err := pool.exchange(q, 100*time.Millisecond); err == nil {
		t.Fatal("expected dial error, got nil")
	}
}

func TestTCPPoolExchangeShortQuery(t *testing.T) {
	pool := newTCPPool("127.0.0.1:1")
	if _, err := pool.exchange([]byte{0x01}, 50*time.Millisecond); err == nil {
		t.Fatal("expected short-query error")
	}
}

func TestDialTCPConnRefused(t *testing.T) {
	if _, err := dialTCPConn("127.0.0.1:1", 100*time.Millisecond); err == nil {
		t.Fatal("expected refused")
	}
}
