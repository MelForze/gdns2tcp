// Package proxy holds the wire-level helpers shared between the gdns2tcp
// proxy client (cmd/gdns2tcp-proxy) and the server-side TCP relay
// (internal/dnsserver). Keeping these in one place ensures both ends agree
// on the per-stream session key derivation, the nonce shape, and the
// host:port label encoding the popen handler expects.
package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Constants live in one place so the server response sizing logic and the
// client poll loop can never drift.
const (
	// MaxReadBytes caps the plaintext size of a single aread/axchg response
	// so the resulting (AEAD-sealed → base64-chunked) TXT record fits inside
	// an 8192-byte EDNS0 UDP buffer with headroom. Sized for axchg which
	// adds an "ACK <seq>" segment on top of the aread payload; pure-aread
	// has a few hundred bytes of extra slack. The proxy assumes a direct
	// agent→server DNS path; if you tunnel through a 4 KB-capped resolver,
	// switch the agent to -tcp.
	MaxReadBytes    = 5600
	MaxReadBytesTCP = 48000

	// DirClientToServer / DirServerToClient become the high 4 bytes of the
	// AEAD nonce, guaranteeing the two directions can never collide on a
	// (direction, seq) pair even though both start at seq=0.
	DirClientToServer uint32 = 1
	DirServerToClient uint32 = 2

	cidByteLen = 8 // 16 hex chars
)

var base32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewCID returns a random 16-character hex connection identifier suitable
// for keying server-side per-stream state. Mirrors the shape of
// protocol.NewSID.
func NewCID() (string, error) {
	var b [cidByteLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate cid: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidCID reports whether s is the 16-lowercase-hex form NewCID produces.
// Used by server handlers to reject malformed query labels cheaply before
// touching shared state.
func ValidCID(s string) bool {
	if len(s) != 2*cidByteLen {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// EncodeTarget converts a "host:port" tuple into DNS-safe lowercase base32
// labels (no padding) split at 63 chars so each label is below the DNS
// per-label limit. The popen handler reverses this with DecodeTarget.
func EncodeTarget(host string, port int) ([]string, error) {
	if host == "" {
		return nil, errors.New("empty host")
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("port out of range: %d", port)
	}
	raw := fmt.Sprintf("%s:%d", host, port)
	encoded := strings.ToLower(base32Enc.EncodeToString([]byte(raw)))
	if encoded == "" {
		return nil, errors.New("encoded target is empty")
	}
	var labels []string
	for i := 0; i < len(encoded); i += 63 {
		end := i + 63
		if end > len(encoded) {
			end = len(encoded)
		}
		labels = append(labels, encoded[i:end])
	}
	return labels, nil
}

// DecodeTarget is the inverse of EncodeTarget. It rejects malformed input
// (non-base32, missing colon, out-of-range port) so the popen handler can
// trust its return values without further validation.
func DecodeTarget(labels []string) (host string, port int, err error) {
	if len(labels) == 0 {
		return "", 0, errors.New("no target labels")
	}
	joined := strings.ToUpper(strings.Join(labels, ""))
	raw, err := base32Enc.DecodeString(joined)
	if err != nil {
		return "", 0, fmt.Errorf("decode target: %w", err)
	}
	s := string(raw)
	idx := strings.LastIndex(s, ":")
	if idx <= 0 || idx == len(s)-1 {
		return "", 0, errors.New("target missing host:port separator")
	}
	host = s[:idx]
	port, err = strconv.Atoi(s[idx+1:])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %w", err)
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("port out of range: %d", port)
	}
	return host, port, nil
}

// SessionAEAD derives a per-cid AES-256-GCM cipher from the shared secret.
// Both client and server compute the same key from the same (secret, cid)
// pair, so the popen response only needs to carry the cid.
//
// The construction deliberately avoids PBKDF2: this code path runs dozens
// of times per second on a busy stream, so a 100k-iteration KDF would burn
// the CPU. Confidentiality of the secret is already handled by the HMAC
// layer of the DNS query auth.
func SessionAEAD(secret, cid string) (cipher.AEAD, error) {
	if secret == "" {
		return nil, errors.New("empty secret")
	}
	if !ValidCID(cid) {
		return nil, fmt.Errorf("invalid cid %q", cid)
	}
	h := sha256.Sum256([]byte("gdns2tcp-stream-v1|" + secret + "|" + cid))
	block, err := aes.NewCipher(h[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// SealChunk encrypts plaintext under the AEAD with a deterministic nonce
// derived from (direction, seq). The same plaintext produces the same
// ciphertext under the same (direction, seq) — so the client can safely
// retry a pwrite with the same seq if the previous query timed out, and
// the server's seqIn-tracking will catch the duplicate before re-applying
// it to the upstream TCP socket.
func SealChunk(aead cipher.AEAD, direction uint32, seq uint64, plaintext []byte) []byte {
	nonce := composeNonce(direction, seq)
	return aead.Seal(nil, nonce, plaintext, nil)
}

// OpenChunk reverses SealChunk. A FAILED authentication tag bubbles up as
// an error and the caller MUST drop the chunk — never partially apply it,
// since the bytes are unverified.
func OpenChunk(aead cipher.AEAD, direction uint32, seq uint64, ciphertext []byte) ([]byte, error) {
	nonce := composeNonce(direction, seq)
	return aead.Open(nil, nonce, ciphertext, nil)
}

func composeNonce(direction uint32, seq uint64) []byte {
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], direction)
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return nonce[:]
}
