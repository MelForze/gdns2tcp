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

func exchangeTCP(addr string, q []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(q)))
	if _, err := conn.Write(prefix[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	rlen := int(binary.BigEndian.Uint16(prefix[:]))
	resp := make([]byte, rlen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// tcpPoolConns is the number of persistent TCP DNS connections. With
// parallelism=32 default on downloads, a one-connection-per-query
// approach exhausts ephemeral ports after ~16K queries (macOS default
// range) when the file is in the MB range. 16 conns serve as fan-out
// with per-conn DNS-id pipelining (independent readLoop + pending map).
const tcpPoolConns = 16

type tcpConnEntry struct {
	parent    *tcpPool
	mu        sync.Mutex // serialises writes on this conn
	pendingMu sync.Mutex
	pending   map[uint16]chan []byte
	conn      net.Conn
	closed    bool
}

type tcpPool struct {
	addr string
	mu   sync.Mutex // guards initial setup
	once sync.Once
	conns []*tcpConnEntry
	next atomic.Uint64
}

func newTCPPool(addr string) *tcpPool {
	p := &tcpPool{addr: addr}
	p.conns = make([]*tcpConnEntry, tcpPoolConns)
	for i := range p.conns {
		p.conns[i] = &tcpConnEntry{parent: p, pending: make(map[uint16]chan []byte)}
	}
	return p
}

// ensure opens (or re-opens) the TCP conn. Caller must hold entry.mu.
func (e *tcpConnEntry) ensure(timeout time.Duration) error {
	if e.conn != nil && !e.closed {
		return nil
	}
	if e.closed {
		// Drop any stale pendings from the previous readLoop.
		e.pendingMu.Lock()
		for id, ch := range e.pending {
			close(ch)
			delete(e.pending, id)
		}
		e.pendingMu.Unlock()
	}
	conn, err := net.DialTimeout("tcp", e.parent.addr, timeout)
	if err != nil {
		return err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	e.conn = conn
	e.closed = false
	go e.readLoop(conn)
	return nil
}

func (e *tcpConnEntry) readLoop(conn net.Conn) {
	defer func() {
		e.mu.Lock()
		if e.conn == conn {
			e.closed = true
			_ = e.conn.Close()
			e.conn = nil
		}
		e.mu.Unlock()
		e.pendingMu.Lock()
		for id, ch := range e.pending {
			close(ch)
			delete(e.pending, id)
		}
		e.pendingMu.Unlock()
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
		e.pendingMu.Lock()
		ch, ok := e.pending[id]
		if ok {
			delete(e.pending, id)
		}
		e.pendingMu.Unlock()
		if ok {
			ch <- buf
		}
	}
}

func (e *tcpConnEntry) exchange(q []byte, timeout time.Duration) ([]byte, error) {
	if len(q) < 2 {
		return nil, errors.New("query too short")
	}
	id := binary.BigEndian.Uint16(q[:2])
	ch := make(chan []byte, 1)

	e.mu.Lock()
	if err := e.ensure(timeout); err != nil {
		e.mu.Unlock()
		return nil, err
	}
	e.pendingMu.Lock()
	e.pending[id] = ch
	e.pendingMu.Unlock()

	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(q)))
	_ = e.conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := e.conn.Write(prefix[:]); err != nil {
		e.closed = true
		e.mu.Unlock()
		e.pendingMu.Lock()
		delete(e.pending, id)
		e.pendingMu.Unlock()
		return nil, err
	}
	if _, err := e.conn.Write(q); err != nil {
		e.closed = true
		e.mu.Unlock()
		e.pendingMu.Lock()
		delete(e.pending, id)
		e.pendingMu.Unlock()
		return nil, err
	}
	_ = e.conn.SetWriteDeadline(time.Time{})
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
		e.pendingMu.Lock()
		delete(e.pending, id)
		e.pendingMu.Unlock()
		return nil, errors.New("tcp exchange timeout")
	}
}

// exchange picks a conn round-robin. One retry on closed-pool so a
// reconnect kicks in transparently.
func (p *tcpPool) exchange(q []byte, timeout time.Duration) ([]byte, error) {
	for attempt := 0; attempt < 2; attempt++ {
		idx := int((p.next.Add(1) - 1) % uint64(len(p.conns)))
		resp, err := p.conns[idx].exchange(q, timeout)
		if err == nil {
			return resp, nil
		}
		if attempt == 1 {
			return nil, err
		}
	}
	return nil, errors.New("tcp pool: unreachable")
}
