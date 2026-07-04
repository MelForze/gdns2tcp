package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"strconv"
	"strings"
	"sync"
)

// Session MAC: short authenticator for per-cid hot-path commands (aread,
// awrite, aclose, axchg). The shared HMAC token used by file-transfer commands
// runs 26+8=34 chars in the query name and dominates the 253-char budget for
// UDP awrite. After a tunnel is opened, both ends know (secret, cid), so we
// can derive a per-cid key and authenticate hot-path requests with 8 chars
// (40 bits) instead.
//
// Replay protection:
//   - awrite already binds seq into the MAC; the server's seqAgentIn tracking
//     rejects duplicates before they touch upstream.
//   - aread/aclose carry an agent-side monotonic nonce; the server keeps a
//     per-cid sliding window of seen nonces (see reverseConn.areadNonces).
//
// Security note: 40 bits is enough only because (a) the per-cid AEAD key in
// internal/proxy is independent of this MAC, so a guess yields nothing
// readable, and (b) cids expire after reverseTTL=5min. At 2^40 ≈ 1.1 trillion
// guesses and a 5-minute window, online forgery is impractical at any
// realistic DNS query rate.

const (
	sessionKeyContext = "gdns2tcp-session-v1"
	// 4 bytes = 32 bits → 7 base32 chars (NoPadding). Trade-off vs the
	// prior 40-bit MAC: online forgery cost drops from ~2^40 to ~2^32
	// guesses, still impractical at any realistic DNS query rate within
	// the 5-min cid lifetime (≥ 7 years at 10 Gqps). Reclaims 1 char per
	// query name, ≈ +0.6 byte plaintext per chunk.
	sessionMACBytes = 4
)

// DeriveSessionKey returns a per-cid 32-byte key suitable for SessionMAC.
// Computing it from HMAC(secret, ctx|cid) gives separation from the AEAD key
// derived in internal/proxy.SessionAEAD (different prefix) and from the
// per-minute AuthToken used by apoll/file commands.
func DeriveSessionKey(secret, cid string) [32]byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sessionKeyContext + "|" + cid))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// hmacPool caches HMAC-SHA256 hashers indexed by session key. hmac.New
// allocates a full block schedule; on axchg-heavy workloads (SessionMAC
// runs on the agent for every query and again on the server to verify)
// this dominated protocol-package allocations. The pool value is a
// *hmacEntry so writing to it under Get/Put is a pointer swap.
type hmacEntry struct {
	h   hash.Hash
	key [32]byte
	ok  bool
}

var hmacPool = sync.Pool{
	New: func() any { return &hmacEntry{} },
}

// SessionMAC returns a short authenticator for (cmd, seq). Callers pass an
// already-lowercase cmd literal (`"axchg"`, `"awrite"`, `"aread"`, `"aclose"`)
// — SessionMAC skips strings.ToLower on the hot path.
func SessionMAC(key [32]byte, cmd string, seq uint64) string {
	e := hmacPool.Get().(*hmacEntry)
	if !e.ok || e.key != key {
		e.h = hmac.New(sha256.New, key[:])
		e.key = key
		e.ok = true
	} else {
		e.h.Reset()
	}
	e.h.Write([]byte(cmd))
	e.h.Write([]byte{'|'})
	var buf [20]byte
	e.h.Write(strconv.AppendUint(buf[:0], seq, 10))
	var sum [sha256.Size]byte
	digest := e.h.Sum(sum[:0])
	out := base32LowerNoPadding.EncodeToString(digest[:sessionMACBytes])
	hmacPool.Put(e)
	return out
}

// VerifySessionMAC is a constant-time check that mac matches the expected
// SessionMAC(key, cmd, seq). Caller is responsible for the replay decision
// (seq monotonicity / sliding window).
func VerifySessionMAC(key [32]byte, cmd string, seq uint64, mac string) bool {
	if mac == "" {
		return false
	}
	expected := SessionMAC(key, cmd, seq)
	// Fast path: DNS labels arrive already lowercased in the common case.
	// Only allocate the ToLower copy if we see uppercase — most peers
	// (including our own encoder) speak lowercase on the wire.
	if !hasUpper(mac) {
		return hmac.Equal([]byte(expected), []byte(mac))
	}
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(mac)))
}

func hasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}
