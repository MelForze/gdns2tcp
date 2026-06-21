package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"strconv"
	"strings"
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
	sessionMACBytes   = 5 // 40 bits → 8 base32 chars (NoPadding)
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

// SessionMAC returns a short authenticator for (cmd, seq). The seq parameter
// is the value caller bound to this request: agent-chosen for awrite (the
// chunk seq) and for aread/aclose (an agent-side request nonce).
func SessionMAC(key [32]byte, cmd string, seq uint64) string {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(strings.ToLower(cmd)))
	mac.Write([]byte{'|'})
	mac.Write([]byte(strconv.FormatUint(seq, 10)))
	sum := mac.Sum(nil)
	return strings.ToLower(base32NoPadding.EncodeToString(sum[:sessionMACBytes]))
}

// VerifySessionMAC is a constant-time check that mac matches the expected
// SessionMAC(key, cmd, seq). Caller is responsible for the replay decision
// (seq monotonicity / sliding window).
func VerifySessionMAC(key [32]byte, cmd string, seq uint64, mac string) bool {
	if strings.TrimSpace(mac) == "" {
		return false
	}
	expected := SessionMAC(key, cmd, seq)
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(mac)))
}
