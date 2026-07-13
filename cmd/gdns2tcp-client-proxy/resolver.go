package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

const retryBackoff = 250 * time.Millisecond

type txtResolver struct {
	server  string
	port    string
	retries int
	useTCP  bool
	timeout time.Duration
	pool    *udpPool
	tcpPool *tcpPool
	// hostPort is the pre-joined server:port, computed once at construction
	// to avoid net.JoinHostPort allocations on the fallback exchange paths.
	hostPort string
}

func newTxtResolver(cfg config) *txtResolver {
	// Trim once at construction — cfg values come from flag.String and may
	// contain trailing whitespace on some platforms. Doing this per query
	// (as queryOnce did previously) is O(n) waste on the hot path.
	server := strings.TrimSpace(cfg.dnsServer)
	port := strings.TrimSpace(cfg.dnsPort)
	r := &txtResolver{
		server:   server,
		port:     port,
		retries:  cfg.retries,
		useTCP:   cfg.tcp,
		timeout:  5 * time.Second,
		hostPort: net.JoinHostPort(server, port),
	}
	addr := r.hostPort
	if cfg.tcp {
		// Lazy-dial inside tcpPool: connections aren't opened until first
		// exchange. This keeps newTxtResolver cheap and lets startup proceed
		// even if the DNS server isn't reachable yet.
		r.tcpPool = newTCPPool(addr)
	} else {
		if p, err := newUDPPool(addr); err == nil {
			r.pool = p
		}
	}
	return r
}

func (r *txtResolver) close() {
	if r == nil {
		return
	}
	if r.pool != nil {
		r.pool.close()
	}
	if r.tcpPool != nil {
		r.tcpPool.close()
	}
}

func (r *txtResolver) query(name string) (string, error) {
	segs, err := r.queryStrings(name)
	if err != nil {
		return "", err
	}
	return strings.Join(segs, ""), nil
}

// queryStringsNoRetry skips queryStrings' retry-on-failure loop. axchg needs
// this because every request carries a fresh agent-side nonce that the
// server tracks in a replay window; a textual retry of the same DNS name
// would re-send the same nonce and be rejected as a replay. The dispatcher
// in main.go simply issues another axchg with the next nonce instead.
func (r *txtResolver) queryStringsNoRetry(name string) ([]string, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("empty DNS query name")
	}
	return r.queryOnce(name)
}

func (r *txtResolver) queryStrings(name string) ([]string, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("empty DNS query name")
	}
	retries := r.retries
	if retries < 1 {
		retries = 1
	}
	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		segs, err := r.queryOnce(name)
		if err == nil {
			return segs, nil
		}
		lastErr = err
		if attempt < retries {
			time.Sleep(time.Duration(attempt) * retryBackoff)
		}
	}
	return nil, lastErr
}

func (r *txtResolver) queryOnce(name string) ([]string, error) {
	resp, id, err := r.exchangeName(name)
	if err != nil {
		return nil, err
	}
	return parseTXTSegments(resp, id)
}

// probeAuthoritative sends one ordinary protocol query and inspects AA in the
// validated response. Recursive resolvers clear AA in replies to their
// clients; the gdns2tcp authoritative endpoint sets it. The result controls
// worker fan-out so a system/public resolver is not flooded like a direct
// server connection.
func (r *txtResolver) probeAuthoritative(name string) (bool, error) {
	resp, id, err := r.exchangeName(name)
	if err != nil {
		return false, err
	}
	if _, err := parseTXTSegments(resp, id); err != nil {
		return false, err
	}
	return resp[2]&0x04 != 0, nil
}

// exchangeName performs one raw DNS exchange and returns both the response
// and the transaction ID assigned by the selected pool. Query parsing stays
// in the caller so startup can inspect header metadata without duplicating
// the hot-path transport selection.
func (r *txtResolver) exchangeName(name string) ([]byte, uint16, error) {
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	// r.server was trimmed at construction — a plain length check suffices
	// and avoids O(n) TrimSpace on every query.
	if r.server == "" {
		return nil, 0, errors.New("dns-server is required")
	}
	// ID=0 is fine on pool paths — reserveDNSIDLocked overwrites q[0:2]
	// with a per-conn counter. Only the fallback exchangeTCP/exchangeUDP
	// paths need a real random ID; we set one there.
	qbufPtr := getDNSQueryBuf()
	defer putDNSQueryBuf(qbufPtr)
	q, err := buildTXTQueryInto(*qbufPtr, name, 0)
	if err != nil {
		return nil, 0, err
	}
	*qbufPtr = q
	var resp []byte
	switch {
	case r.useTCP && r.tcpPool != nil:
		resp, err = r.tcpPool.exchange(q, timeout)
	case r.useTCP:
		binary.BigEndian.PutUint16(q[:2], randomDNSID())
		resp, err = exchangeTCP(r.hostPort, q, timeout)
	case r.pool != nil:
		resp, err = r.pool.exchange(q, timeout)
	default:
		binary.BigEndian.PutUint16(q[:2], randomDNSID())
		resp, err = exchangeUDP(r.hostPort, q, timeout)
	}
	if err != nil {
		return nil, 0, err
	}
	return resp, binary.BigEndian.Uint16(q[:2]), nil
}
