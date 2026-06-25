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

// dnsQueryPool recycles DNS query buffers. Each axchg round-trip
// allocates one ~250-byte buffer; with 96 workers × thousands qps the
// GC pressure adds up. Reusing a pool of buffers cuts ~MB/s worth of
// allocations on bulk transfers.
var dnsQueryPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 280)
		return &b
	},
}

// getDNSQueryBuf returns a pooled []byte (length 0, cap ≥ 280). Pair
// with putDNSQueryBuf after pool.exchange returns.
func getDNSQueryBuf() *[]byte {
	bp := dnsQueryPool.Get().(*[]byte)
	*bp = (*bp)[:0]
	return bp
}

func putDNSQueryBuf(bp *[]byte) {
	if bp == nil {
		return
	}
	// Drop oversized buffers (oddball long-domain queries) so the pool
	// doesn't accumulate large slices.
	if cap(*bp) > 1024 {
		return
	}
	dnsQueryPool.Put(bp)
}

func buildTXTQuery(name string, id uint16) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	buf := make([]byte, 0, 64+len(name))
	return buildTXTQueryInto(buf, name, id)
}

// buildTXTQueryInto writes the DNS query into the given pre-allocated
// buffer (extended with append). Returns the resulting slice (which may
// have a different backing array if buf grew). Caller passes a pooled
// buffer from getDNSQueryBuf when on the hot path.
func buildTXTQueryInto(buf []byte, name string, id uint16) ([]byte, error) {
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

// udpPoolSockets is the number of independent UDP sockets multiplexing
// queries. Each socket has its own per-id pending map and readLoop, so
// fanning out across them lets bursts of axchg responses parallelise on
// the kernel's recv-queue path. 4 sockets ≈ matches the TCP pool size
// and is enough to keep 96 workers fed without overloading the resolver.
const udpPoolSockets = 4

// udpConnEntry is one persistent UDP socket + its pending-id dispatcher.
type udpConnEntry struct {
	conn    *net.UDPConn
	mu      sync.Mutex
	pending map[uint16]chan []byte
	nextID  uint16
	closed  bool
}

// udpPool fans out queries across udpPoolSockets independent UDP sockets,
// round-robin. Each socket still multiplexes by DNS transaction ID.
type udpPool struct {
	addr  string
	conns []*udpConnEntry
	next  atomic.Uint64
}

func newUDPPool(addr string) (*udpPool, error) {
	p := &udpPool{addr: addr, conns: make([]*udpConnEntry, udpPoolSockets)}
	for i := range p.conns {
		conn, err := net.DialTimeout("udp", addr, 5*time.Second)
		if err != nil {
			for j := 0; j < i; j++ {
				p.conns[j].close()
			}
			return nil, err
		}
		// Bump kernel UDP recv buffer to 4 MiB per socket. With 96
		// workers fanning across 4 sockets, each socket sees bursts
		// of ~24 in-flight responses; 4 MiB leaves comfortable
		// headroom (≈ 24 × 40 KiB max response × safety). Kernels
		// may silently clamp to net.core.rmem_max.
		if uc, ok := conn.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(4 * 1024 * 1024)
			e := &udpConnEntry{conn: uc, pending: make(map[uint16]chan []byte), nextID: randomDNSID()}
			p.conns[i] = e
			go e.readLoop()
		} else {
			// Shouldn't happen for "udp" network, but defend anyway.
			_ = conn.Close()
			for j := 0; j < i; j++ {
				p.conns[j].close()
			}
			return nil, errors.New("udp pool: unexpected conn type")
		}
	}
	return p, nil
}

func (e *udpConnEntry) readLoop() {
	buf := make([]byte, ednsUDPBufferSize)
	for {
		n, err := e.conn.Read(buf)
		if err != nil {
			e.mu.Lock()
			e.closed = true
			for _, ch := range e.pending {
				close(ch)
			}
			e.pending = make(map[uint16]chan []byte)
			e.mu.Unlock()
			return
		}
		if n < 2 {
			continue
		}
		id := binary.BigEndian.Uint16(buf[:2])
		resp := make([]byte, n)
		copy(resp, buf[:n])
		e.mu.Lock()
		ch, ok := e.pending[id]
		if ok {
			delete(e.pending, id)
		}
		e.mu.Unlock()
		if ok {
			ch <- resp
		}
	}
}

func (p *udpPool) exchange(q []byte, timeout time.Duration) ([]byte, error) {
	if len(q) < 2 {
		return nil, errors.New("query too short")
	}
	idx := int((p.next.Add(1) - 1) % uint64(len(p.conns)))
	return p.conns[idx].exchange(q, timeout)
}

func (e *udpConnEntry) exchange(q []byte, timeout time.Duration) ([]byte, error) {
	ch := make(chan []byte, 1)
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, errors.New("udp pool closed")
	}
	id, err := reserveDNSIDLocked(e.pending, &e.nextID, ch)
	if err != nil {
		e.mu.Unlock()
		return nil, err
	}
	binary.BigEndian.PutUint16(q[:2], id)
	e.mu.Unlock()
	if _, err := e.conn.Write(q); err != nil {
		e.mu.Lock()
		deletePendingIfOwnedLocked(e.pending, id, ch)
		e.mu.Unlock()
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
		e.mu.Lock()
		deletePendingIfOwnedLocked(e.pending, id, ch)
		e.mu.Unlock()
		return nil, errors.New("udp exchange timeout")
	}
}

func (e *udpConnEntry) close() {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	_ = e.conn.Close()
}

func (p *udpPool) close() {
	for _, e := range p.conns {
		if e != nil {
			e.close()
		}
	}
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

// tcpPoolConns is the fan-out across persistent TCP DNS connections. Each
// connection has its own per-id pipelining (independent readLoop + pending
// map), so adding conns linearly reduces HoL contention when axchgWorkers
// keep many round-trips in flight. 16 connections give each worker
// (cap=32) two slots before HoL queueing — empirically necessary to
// avoid stalls on sustained 50 MB+ TCP-DNS bulk transfers where one
// slow query on a conn drags the rest behind it.
const tcpPoolConns = 16

type tcpConnEntry struct {
	parent     *tcpPool
	mu         sync.Mutex // serializes writes on this conn
	pendingMu  sync.Mutex
	pending    map[uint16]chan []byte
	nextID     uint16
	conn       net.Conn
	closed     bool
	connectErr error
}

type tcpPool struct {
	addr  string
	conns []*tcpConnEntry
	next  atomic.Uint64 // round-robin cursor across p.conns
	dial  func(addr string, timeout time.Duration) (net.Conn, error)
}

func newTCPPool(addr string) *tcpPool {
	p := &tcpPool{
		addr: addr,
		dial: func(a string, t time.Duration) (net.Conn, error) { return net.DialTimeout("tcp", a, t) },
	}
	p.conns = make([]*tcpConnEntry, tcpPoolConns)
	for i := range p.conns {
		p.conns[i] = &tcpConnEntry{parent: p, pending: make(map[uint16]chan []byte), nextID: randomDNSID()}
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
	ch := make(chan []byte, 1)

	e.mu.Lock()
	if err := e.ensure(timeout); err != nil {
		e.mu.Unlock()
		return nil, err
	}
	e.pendingMu.Lock()
	id, err := reserveDNSIDLocked(e.pending, &e.nextID, ch)
	if err != nil {
		e.pendingMu.Unlock()
		e.mu.Unlock()
		return nil, err
	}
	binary.BigEndian.PutUint16(q[:2], id)
	e.pendingMu.Unlock()

	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(q)))
	_ = e.conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := e.conn.Write(prefix[:]); err != nil {
		e.closed = true
		e.mu.Unlock()
		e.pendingMu.Lock()
		deletePendingIfOwnedLocked(e.pending, id, ch)
		e.pendingMu.Unlock()
		return nil, err
	}
	if _, err := e.conn.Write(q); err != nil {
		e.closed = true
		e.mu.Unlock()
		e.pendingMu.Lock()
		deletePendingIfOwnedLocked(e.pending, id, ch)
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
		deletePendingIfOwnedLocked(e.pending, id, ch)
		e.pendingMu.Unlock()
		return nil, errors.New("tcp exchange timeout")
	}
}

func reserveDNSIDLocked(pending map[uint16]chan []byte, nextID *uint16, ch chan []byte) (uint16, error) {
	for i := 0; i < 65535; i++ {
		*nextID = *nextID + 1
		if *nextID == 0 {
			*nextID = 1
		}
		id := *nextID
		if _, exists := pending[id]; exists {
			continue
		}
		pending[id] = ch
		return id, nil
	}
	return 0, errors.New("dns transaction id space exhausted")
}

func deletePendingIfOwnedLocked(pending map[uint16]chan []byte, id uint16, ch chan []byte) {
	if pending[id] == ch {
		delete(pending, id)
	}
}

// exchange picks a conn round-robin and tries one re-pick on failure. Two
// conns are usually enough to absorb a transient failure on one socket
// without bouncing the call to the caller.
func (p *tcpPool) exchange(q []byte, timeout time.Duration) ([]byte, error) {
	if len(p.conns) == 0 {
		return nil, errors.New("tcp pool empty")
	}
	first := int(p.next.Add(1)-1) % len(p.conns)
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
