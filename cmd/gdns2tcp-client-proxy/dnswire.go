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

// ednsUDPBufferSize is the EDNS0 buffer advertised on outgoing queries.
// The proxy assumes a direct agent→server DNS path — pick 8 KB so a
// single aread/axchg response can carry ~28 base64 chunks in one UDP
// datagram. If you tunnel through a 4 KB-capped resolver, use -tcp.
const ednsUDPBufferSize uint16 = 8192

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

func buildTXTQuery(name string, id uint16) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	buf := make([]byte, 0, 64+len(name))
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	hdr[2] = 0x01
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[10:12], 1)
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
	binary.BigEndian.PutUint16(trailer[2:4], 1)
	buf = append(buf, trailer[:]...)
	var opt [11]byte
	binary.BigEndian.PutUint16(opt[1:3], 41)
	binary.BigEndian.PutUint16(opt[3:5], ednsUDPBufferSize)
	buf = append(buf, opt[:]...)
	return buf, nil
}

// parseTXTSegments preserves the character-string boundaries so apoll's
// "OPEN <cid> <target>" and aread's "DATA <seq>" marker stay distinct from
// the payload chunks that follow.
func parseTXTSegments(resp []byte, expectID uint16) ([]string, error) {
	if len(resp) < 12 {
		return nil, errors.New("DNS response too short")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != expectID {
		return nil, errors.New("DNS ID mismatch")
	}
	if rcode := resp[3] & 0x0F; rcode != 0 {
		name := rcodeNames[rcode]
		if name == "" {
			name = fmt.Sprintf("rcode=%d", rcode)
		}
		return nil, fmt.Errorf("DNS response code %s", name)
	}
	if resp[2]&0x02 != 0 {
		return nil, errors.New("DNS response truncated (TC=1); use -tcp")
	}
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	pos := 12
	for range qdcount {
		var err error
		pos, err = skipDNSName(resp, pos)
		if err != nil {
			return nil, err
		}
		if pos+4 > len(resp) {
			return nil, errors.New("truncated question")
		}
		pos += 4
	}
	out := make([]string, 0)
	for range ancount {
		var err error
		pos, err = skipDNSName(resp, pos)
		if err != nil {
			return nil, err
		}
		if pos+10 > len(resp) {
			return nil, errors.New("truncated RR header")
		}
		rtype := binary.BigEndian.Uint16(resp[pos : pos+2])
		pos += 8
		rdlen := int(binary.BigEndian.Uint16(resp[pos : pos+2]))
		pos += 2
		end := pos + rdlen
		if end > len(resp) {
			return nil, errors.New("truncated RDATA")
		}
		if rtype == dnsTypeTXT {
			p := pos
			for p < end {
				sl := int(resp[p])
				p++
				if p+sl > end {
					return nil, errors.New("malformed TXT character-string")
				}
				out = append(out, string(resp[p:p+sl]))
				p += sl
			}
		}
		pos = end
	}
	if len(out) == 0 {
		return nil, errors.New("no TXT response")
	}
	return out, nil
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

// udpPool keeps a single persistent UDP connection and multiplexes queries by
// DNS transaction ID. Avoids per-query socket allocation overhead.
type udpPool struct {
	addr    string
	conn    net.Conn
	mu      sync.Mutex
	pending map[uint16]chan []byte
	closed  bool
}

func newUDPPool(addr string) (*udpPool, error) {
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	p := &udpPool{
		addr:    addr,
		conn:    conn,
		pending: make(map[uint16]chan []byte),
	}
	go p.readLoop()
	return p, nil
}

func (p *udpPool) readLoop() {
	buf := make([]byte, ednsUDPBufferSize)
	for {
		n, err := p.conn.Read(buf)
		if err != nil {
			p.mu.Lock()
			p.closed = true
			for _, ch := range p.pending {
				close(ch)
			}
			p.pending = make(map[uint16]chan []byte)
			p.mu.Unlock()
			return
		}
		if n < 2 {
			continue
		}
		id := binary.BigEndian.Uint16(buf[:2])
		resp := make([]byte, n)
		copy(resp, buf[:n])
		p.mu.Lock()
		ch, ok := p.pending[id]
		if ok {
			delete(p.pending, id)
		}
		p.mu.Unlock()
		if ok {
			ch <- resp
		}
	}
}

func (p *udpPool) exchange(q []byte, timeout time.Duration) ([]byte, error) {
	if len(q) < 2 {
		return nil, errors.New("query too short")
	}
	id := binary.BigEndian.Uint16(q[:2])
	ch := make(chan []byte, 1)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("udp pool closed")
	}
	p.pending[id] = ch
	p.mu.Unlock()
	if _, err := p.conn.Write(q); err != nil {
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return nil, err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case resp, ok := <-ch:
		if !ok {
			return nil, errors.New("udp pool closed during exchange")
		}
		return resp, nil
	case <-timer.C:
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return nil, errors.New("udp exchange timeout")
	}
}

func (p *udpPool) close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	_ = p.conn.Close()
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

// --- persistent TCP-DNS pool ----------------------------------------------
//
// One-shot exchangeTCP above pays a fresh TCP handshake per query, which
// negates the whole point of using -tcp for the bigger payload budget. The
// pool keeps a small fan-out of long-lived TCP-DNS connections; each is
// written under its own mutex, replies are routed back by DNS-ID via a
// per-conn readLoop. Two conns by default round-robin around head-of-line
// blocking in TCP (a slow large reply on one socket doesn't stall the other).

// tcpPoolConns is the default fan-out. Two is enough to hide HoL stalls on
// any single connection; more would dilute connection re-use without much
// extra throughput on a single-resolver path.
const tcpPoolConns = 2

type tcpConnEntry struct {
	parent     *tcpPool
	mu         sync.Mutex // serializes writes on this conn
	pendingMu  sync.Mutex
	pending    map[uint16]chan []byte
	conn       net.Conn
	closed     bool
	connectErr error
}

type tcpPool struct {
	addr  string
	conns []*tcpConnEntry
	next  uint64 // atomic round-robin cursor
	dial  func(addr string, timeout time.Duration) (net.Conn, error)
}

func newTCPPool(addr string) *tcpPool {
	p := &tcpPool{
		addr: addr,
		dial: func(a string, t time.Duration) (net.Conn, error) { return net.DialTimeout("tcp", a, t) },
	}
	p.conns = make([]*tcpConnEntry, tcpPoolConns)
	for i := range p.conns {
		p.conns[i] = &tcpConnEntry{parent: p, pending: make(map[uint16]chan []byte)}
	}
	return p
}

// ensure makes sure entry has an open TCP connection, redialing if needed.
// Caller must hold entry.mu. Returns an error if the redial fails — caller
// returns it to the exchange invoker, who may retry on another conn.
func (e *tcpConnEntry) ensure(timeout time.Duration) error {
	if e.conn != nil && !e.closed {
		return nil
	}
	if e.closed {
		// Drain any pending senders left from the previous readLoop.
		e.pendingMu.Lock()
		for id, ch := range e.pending {
			close(ch)
			delete(e.pending, id)
		}
		e.pendingMu.Unlock()
	}
	conn, err := e.parent.dial(e.parent.addr, timeout)
	if err != nil {
		e.connectErr = err
		return err
	}
	// Шаг G: tune the long-lived DNS-over-TCP socket. NoDelay matters most
	// for axchg's tiny query/response pairs where Nagle would batch them
	// against the previous reply and add a full RTT.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	e.conn = conn
	e.closed = false
	e.connectErr = nil
	go e.readLoop(conn)
	return nil
}

// readLoop reads DNS-over-TCP frames (2-byte length prefix + DNS message),
// looks up the DNS ID's pending channel, and hands the payload over.
// Termination: any read error closes the conn and trips all pending senders,
// so they observe the failure instead of waiting forever.
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

// exchange sends q on this conn entry and waits up to timeout for the reply
// keyed by DNS ID. The mu lock only serializes writes onto the TCP socket;
// concurrent readers from readLoop dispatch responses without blocking new
// writes.
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

// exchange picks a conn round-robin and tries one re-pick on failure. Two
// conns are usually enough to absorb a transient failure on one socket
// without bouncing the call to the caller.
func (p *tcpPool) exchange(q []byte, timeout time.Duration) ([]byte, error) {
	if len(p.conns) == 0 {
		return nil, errors.New("tcp pool empty")
	}
	first := int(atomic.AddUint64(&p.next, 1)-1) % len(p.conns)
	resp, err := p.conns[first].exchange(q, timeout)
	if err == nil {
		return resp, nil
	}
	if len(p.conns) == 1 {
		return nil, err
	}
	second := (first + 1) % len(p.conns)
	return p.conns[second].exchange(q, timeout)
}

func (p *tcpPool) close() {
	for _, e := range p.conns {
		e.mu.Lock()
		if e.conn != nil {
			_ = e.conn.Close()
		}
		e.closed = true
		e.mu.Unlock()
		e.pendingMu.Lock()
		for id, ch := range e.pending {
			close(ch)
			delete(e.pending, id)
		}
		e.pendingMu.Unlock()
	}
}
