package main

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"gdns2tcp/internal/dnshelpers"
)

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
