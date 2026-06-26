package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gdns2tcp/internal/dnshelpers"
)

const dnsTypeTXT uint16 = 16

// ednsUDPBufferSize is advertised to the server via EDNS0 OPT so it knows it
// can return larger UDP responses (default DNS UDP cap is 512 bytes). 4096 is
// the conventional EDNS0 buffer size and matches what the server can pack
// inside a single UDP datagram when downloads are batched.
const ednsUDPBufferSize uint16 = 4096

var rcodeNames = map[byte]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}

func fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func randomDNSID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	id := binary.BigEndian.Uint16(b[:])
	if id == 0 {
		id = 1
	}
	return id
}

// buildTXTQuery encodes a DNS query for the TXT record of name, including an
// EDNS0 OPT pseudo-RR in the additional section so the server may respond
// with up to ednsUDPBufferSize bytes over UDP.
func buildTXTQuery(name string, id uint16) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	buf := make([]byte, 0, 64+len(name))
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	hdr[2] = 0x01                             // flags: RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)   // QDCOUNT=1
	binary.BigEndian.PutUint16(hdr[10:12], 1) // ARCOUNT=1 (OPT record)
	buf = append(buf, hdr[:]...)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("DNS label too long: %d", len(label))
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	var trailer [4]byte
	binary.BigEndian.PutUint16(trailer[0:2], dnsTypeTXT)
	binary.BigEndian.PutUint16(trailer[2:4], 1) // CLASS=IN
	buf = append(buf, trailer[:]...)
	// EDNS0 OPT pseudo-RR: root name(1) + type(2) + class=bufsize(2) +
	// extended-RCODE/version/flags(4) + RDLEN=0 (2).
	var opt [11]byte
	binary.BigEndian.PutUint16(opt[1:3], 41) // OPT type
	binary.BigEndian.PutUint16(opt[3:5], ednsUDPBufferSize)
	buf = append(buf, opt[:]...)
	return buf, nil
}

// parseTXTResponse concatenates all TXT character strings from every TXT RR
// in the answer section. Returns an error on truncated/malformed responses
// or non-success rcodes.
func parseTXTResponse(resp []byte, expectID uint16) (string, error) {
	if len(resp) < 12 {
		return "", errors.New("DNS response too short")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != expectID {
		return "", errors.New("DNS ID mismatch")
	}
	if rcode := resp[3] & 0x0F; rcode != 0 {
		name := rcodeNames[rcode]
		if name == "" {
			name = fmt.Sprintf("rcode=%d", rcode)
		}
		return "", fmt.Errorf("DNS response code %s", name)
	}
	if resp[2]&0x02 != 0 {
		return "", errors.New("DNS response truncated (TC=1); reduce batch size or use -tcp")
	}
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	pos := 12
	for i := 0; i < qdcount; i++ {
		var err error
		pos, err = skipDNSName(resp, pos)
		if err != nil {
			return "", err
		}
		if pos+4 > len(resp) {
			return "", errors.New("truncated question section")
		}
		pos += 4
	}
	var sb strings.Builder
	for i := 0; i < ancount; i++ {
		var err error
		pos, err = skipDNSName(resp, pos)
		if err != nil {
			return "", err
		}
		if pos+10 > len(resp) {
			return "", errors.New("truncated RR header")
		}
		rtype := binary.BigEndian.Uint16(resp[pos : pos+2])
		pos += 8 // type(2)+class(2)+ttl(4)
		rdlen := int(binary.BigEndian.Uint16(resp[pos : pos+2]))
		pos += 2
		end := pos + rdlen
		if end > len(resp) {
			return "", errors.New("truncated RDATA")
		}
		if rtype == dnsTypeTXT {
			p := pos
			for p < end {
				sl := int(resp[p])
				p++
				if p+sl > end {
					return "", errors.New("malformed TXT character-string")
				}
				sb.Write(resp[p : p+sl])
				p += sl
			}
		}
		pos = end
	}
	if sb.Len() == 0 {
		return "", errors.New("no TXT response")
	}
	return sb.String(), nil
}

func skipDNSName(buf []byte, pos int) (int, error) {
	for pos < len(buf) {
		b := buf[pos]
		if b == 0 {
			return pos + 1, nil
		}
		if b&0xC0 == 0xC0 {
			if pos+1 >= len(buf) {
				return 0, errors.New("truncated name pointer")
			}
			return pos + 2, nil
		}
		if b&0xC0 != 0 {
			return 0, errors.New("invalid label length byte")
		}
		next := pos + 1 + int(b)
		if next > len(buf) {
			return 0, errors.New("truncated label")
		}
		pos = next
	}
	return 0, errors.New("unterminated DNS name")
}

func exchangeUDP(addr string, q []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, ednsUDPBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// tcpPoolConns is the number of persistent TCP DNS connections. With
// parallelism=32 default on downloads, a one-connection-per-query
// approach exhausts ephemeral ports after ~16K queries (macOS default
// range) when the file is in the MB range. 16 conns serve as fan-out
// with per-conn DNS-id pipelining (independent readLoop + pending map).
const tcpPoolConns = 16

// tcpPoolBlackHoleThreshold: a conn that times out this many times in a
// row gets force-closed so the next exchange redials. Catches misbehaving
// middleboxes that ACK queries but never deliver responses; without this
// the conn would stay "alive" for the kernel keepalive period (~30s+).
const tcpPoolBlackHoleThreshold = 2

// tcpPoolMaxRetries: pool.exchange tries this many different conns before
// giving up. With 16 conns, three attempts is enough that a single bad
// conn (or two simultaneously bad) doesn't fail an otherwise-healthy
// download burst.
const tcpPoolMaxRetries = 3

type tcpConnEntry struct {
	parent       *tcpPool
	mu           sync.Mutex // covers conn, pending, closed, timeoutCount
	pending      map[uint16]chan []byte
	nextID       uint16
	conn         net.Conn
	closed       bool
	timeoutCount int
}

type tcpPool struct {
	addr  string
	conns []*tcpConnEntry
	next  atomic.Uint64
}

func newTCPPool(addr string) *tcpPool {
	p := &tcpPool{addr: addr}
	p.conns = make([]*tcpConnEntry, tcpPoolConns)
	for i := range p.conns {
		p.conns[i] = &tcpConnEntry{parent: p, pending: make(map[uint16]chan []byte), nextID: randomDNSID(), closed: true}
	}
	return p
}

// dialTCPConn opens a new TCP DNS conn with the connection tuning that
// matters for long-lived multiplexed use: NoDelay (axchg queries are
// tiny, Nagle hurts), KeepAlive (kernel surfaces dead conns within
// ~30s instead of the OS-default minutes).
func dialTCPConn(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	return conn, nil
}

// ensureLocked makes sure entry has a live TCP conn, redialing after a
// previous read/write error. Caller must hold e.mu. The pending map is
// drained before dial so the new conn starts with a clean slate.
//
// Known limitation: this runs DialTimeout while holding e.mu, so other
// workers round-robined to this entry stall up to `timeout` on dial.
// Mitigated by tcpPoolMaxRetries in pool.exchange — if a conn is busy
// dialing, the worker picks another entry on the next attempt.
func (e *tcpConnEntry) ensureLocked(timeout time.Duration) error {
	if e.conn != nil && !e.closed {
		return nil
	}
	for id, ch := range e.pending {
		close(ch)
		delete(e.pending, id)
	}
	if e.conn != nil {
		_ = e.conn.Close()
		e.conn = nil
	}
	conn, err := dialTCPConn(e.parent.addr, timeout)
	if err != nil {
		e.closed = true
		return err
	}
	e.conn = conn
	e.closed = false
	e.timeoutCount = 0
	go e.readLoop(conn)
	return nil
}

// readLoop reads framed DNS-over-TCP responses and dispatches by DNS
// transaction ID. The deferred cleanup is gated on `e.conn == conn`:
// without that check, an old readLoop firing AFTER the entry has already
// reconnected would close pending channels owned by the NEW conn — a
// race condition that surfaces as spurious "tcp pool conn closed during
// exchange" errors on healthy queries.
func (e *tcpConnEntry) readLoop(conn net.Conn) {
	defer func() {
		e.mu.Lock()
		if e.conn == conn {
			e.closed = true
			e.conn = nil
			for id, ch := range e.pending {
				close(ch)
				delete(e.pending, id)
			}
		}
		e.mu.Unlock()
		_ = conn.Close()
	}()
	var prefix [2]byte
	for {
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		rlen := int(binary.BigEndian.Uint16(prefix[:]))
		if rlen < 2 {
			return
		}
		buf := make([]byte, rlen)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		id := binary.BigEndian.Uint16(buf[:2])
		e.mu.Lock()
		ch, ok := e.pending[id]
		if ok {
			delete(e.pending, id)
			e.timeoutCount = 0 // any successful response clears black-hole counter
		}
		e.mu.Unlock()
		if ok {
			ch <- buf
		}
	}
}

func (e *tcpConnEntry) exchange(q []byte, timeout time.Duration) ([]byte, error) {
	if len(q) < 2 {
		return nil, errors.New("query too short")
	}
	ch := make(chan []byte, 1)

	e.mu.Lock()
	if err := e.ensureLocked(timeout); err != nil {
		e.mu.Unlock()
		return nil, err
	}
	id, err := dnshelpers.ReserveDNSIDLocked(e.pending, &e.nextID, ch)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	conn := e.conn
	binary.BigEndian.PutUint16(q[:2], id)

	// Write prefix+body under e.mu. On any error we hard-close the conn
	// here (not just flag e.closed=true) so the in-flight readLoop
	// returns immediately, and any partial write that desynced the
	// server's framing is followed by a FIN to unblock the server's
	// io.ReadFull.
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(q)))
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	werr := writeAll(conn, prefix[:])
	if werr == nil {
		werr = writeAll(conn, q)
	}
	_ = conn.SetWriteDeadline(time.Time{})
	if werr != nil {
		if e.conn == conn {
			e.closed = true
			e.conn = nil
			for pid, pch := range e.pending {
				close(pch)
				delete(e.pending, pid)
			}
			_ = conn.Close()
		} else {
			dnshelpers.DeletePendingIfOwnedLocked(e.pending, id, ch)
		}
		e.mu.Unlock()
		return nil, werr
	}
	e.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errors.New("tcp pool conn closed during exchange")
		}
		return resp, nil
	case <-timer.C:
		e.mu.Lock()
		dnshelpers.DeletePendingIfOwnedLocked(e.pending, id, ch)
		e.timeoutCount++
		if e.timeoutCount >= tcpPoolBlackHoleThreshold && e.conn == conn {
			// Black-hole: too many timeouts on this conn. Force-close so
			// the next exchange redials instead of waiting for kernel
			// keepalive (~30s) to surface the dead conn.
			e.closed = true
			e.conn = nil
			for pid, pch := range e.pending {
				close(pch)
				delete(e.pending, pid)
			}
			_ = conn.Close()
			e.timeoutCount = 0
		}
		e.mu.Unlock()
		return nil, errors.New("tcp exchange timeout")
	}
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// exchange picks a conn round-robin, retrying on different conns up to
// tcpPoolMaxRetries times. With pool=16 and 3 retries, a single dead
// conn (or two simultaneously dead) doesn't fail an otherwise healthy
// download burst.
func (p *tcpPool) exchange(q []byte, timeout time.Duration) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < tcpPoolMaxRetries; attempt++ {
		idx := int((p.next.Add(1) - 1) % uint64(len(p.conns)))
		resp, err := p.conns[idx].exchange(q, timeout)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
