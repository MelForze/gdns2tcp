package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gdns2tcp/internal/dnshelpers"
)

const (
	AuthVersion    = "gdns2tcp-auth-v1"
	FilenamePrefix = "f1"
)

// base32NoPadding is the uppercase RFC 4648 alphabet, kept for the
// decoder path (some places accept legacy uppercase input).
var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

// base32LowerNoPadding produces lowercase base32 output directly, so
// callers don't need to allocate a second string via strings.ToLower.
// The two encodings are wire-compatible (same code points 2-7 for
// digits, a-z <-> A-Z case fold) so a decoder that accepts either
// case can read output from either encoder.
var base32LowerNoPadding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func AuthDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

// ParseDomainCSV splits the -domain flag value used by every gdns2tcp
// binary (server, agent, file client). Single-domain input (no comma)
// is fully backward compatible: canonical == input, shardDomains has
// one entry. For CSV input the first entry becomes canonical (drives
// HMAC), and every entry (deduped, whitespace-trimmed, trailing-dot-
// stripped) joins shardDomains so the QNAME rotator can fan out
// across all of them.
//
// Returns (canonical, shardDomains, shardAuthDomains, longest, error). An
// empty raw input yields ("", [""], [""], "", nil) — the caller sees the
// empty canonical and rejects with "domain is required".
func ParseDomainCSV(raw string) (canonical string, shardDomains, shardAuthDomains []string, longest string, err error) {
	parts := strings.Split(raw, ",")
	shardDomains = make([]string, 0, len(parts))
	shardAuthDomains = make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		d := strings.TrimSuffix(strings.TrimSpace(p), ".")
		if d == "" {
			continue
		}
		if validateErr := ValidateDomain(d); validateErr != nil {
			return "", nil, nil, "", validateErr
		}
		key := strings.ToLower(d)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		shardDomains = append(shardDomains, d)
		shardAuthDomains = append(shardAuthDomains, AuthDomain(d))
		if canonical == "" {
			canonical = d
		}
		if len(d) > len(longest) {
			longest = d
		}
	}
	if canonical == "" {
		// Preserve len==1 invariant callers rely on for the "skip
		// atomic on single-domain configs" fast path.
		return "", []string{""}, []string{""}, "", nil
	}
	return canonical, shardDomains, shardAuthDomains, longest, nil
}

// ValidateDomain enforces the DNS wire constraints shared by every client and
// server entry point. The presentation form omits the optional trailing dot;
// 253 bytes is therefore the largest value that still fits the terminating
// root label in the 255-byte DNS wire limit.
func ValidateDomain(domain string) error {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return errors.New("domain is required")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain is %d bytes; DNS limit is 253", len(domain))
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid domain label %q", label)
		}
	}
	return nil
}

func CurrentTimestamp(now time.Time) string {
	return strconv.FormatInt(now.UTC().Unix()/60, 10)
}

func AuthToken(secret, domain, command, timestamp string, args []string) string {
	parts := []string{AuthVersion, AuthDomain(domain), strings.ToLower(command), timestamp}
	// Lowercase every arg so a resolver that randomizes DNS-label case
	// (RFC 5452 0x20 anti-spoofing) or upcases a whole label in transit
	// can't invalidate a legitimate MAC. Client-side callers still pass
	// lowercase by convention; this ensures the wire-observed case has
	// no effect either way.
	for _, a := range args {
		parts = append(parts, strings.ToLower(a))
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strings.Join(parts, "|")))
	sum := mac.Sum(nil)
	// 16 bytes (128 bits) is sufficient for a MAC used as a single-use
	// per-minute token and keeps the DNS label short.
	return base32LowerNoPadding.EncodeToString(sum[:16])
}

// VerifyAuthWindowMinutes is the clock-drift tolerance VerifyAuth accepts
// on either side of the server's current minute. Set wide because the
// usual failure mode is a VPS without NTP that drifts by 5–10 minutes;
// replay is bounded for the only mutating endpoint (apoll), since apoll
// just hands out the next queued cid and per-cid state is gated by the
// independent session-MAC chain.
const VerifyAuthWindowMinutes = 15

func VerifyAuth(secret, domain, command string, args []string, timestamp, token string, now time.Time) bool {
	// Server callers pass their normalized secret (trimmed at startup) and
	// DNS labels never contain leading/trailing whitespace after label
	// decoding — a plain length check suffices without an O(n) TrimSpace.
	if secret == "" || timestamp == "" || token == "" {
		return false
	}
	minute, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	current := now.UTC().Unix() / 60
	if minute < current-VerifyAuthWindowMinutes || minute > current+VerifyAuthWindowMinutes {
		return false
	}
	expected := AuthToken(secret, domain, command, timestamp, args)
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(token)))
}

// AuthDriftMinutes returns how far the client's timestamp is from the
// server's now, in minutes (positive if client clock is behind, negative
// if ahead). Used by server handlers for diagnostic logging when auth
// fails — admin can immediately tell whether the failure is clock drift
// (-d=12 → run ntpdate) or actual MAC mismatch (-d=0 → wrong secret).
//
// Returns (drift, ok). ok=false if timestamp is unparseable.
func AuthDriftMinutes(timestamp string, now time.Time) (int64, bool) {
	minute, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return 0, false
	}
	return now.UTC().Unix()/60 - minute, true
}

func NewSID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate sid: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func ValidSID(sid string) bool {
	if len(sid) < 8 || len(sid) > 64 {
		return false
	}
	for _, r := range sid {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

func EncodeFilenameLabels(filename string) ([]string, error) {
	if strings.TrimSpace(filename) == "" {
		return nil, errors.New("filename is empty")
	}
	encoded := base32LowerNoPadding.EncodeToString([]byte(filename))
	labels := []string{FilenamePrefix}
	labels = append(labels, ChunkString(encoded, 63)...)
	return labels, nil
}

func DecodeFilenameLabels(labels []string) (string, error) {
	if len(labels) < 2 || labels[0] != FilenamePrefix {
		return "", errors.New("missing filename encoding prefix")
	}
	// New wire is lowercase (base32LowerNoPadding); older peers may still
	// send uppercase. Try the lowercase decoder first and fall back only
	// if it fails — this avoids the strings.ToUpper allocation on the
	// hot path when both sides speak the new encoding.
	joined := strings.Join(labels[1:], "")
	raw, err := base32LowerNoPadding.DecodeString(joined)
	if err != nil {
		raw, err = base32NoPadding.DecodeString(strings.ToUpper(joined))
	}
	if err != nil {
		return "", fmt.Errorf("decode filename: %w", err)
	}
	if !utf8.Valid(raw) {
		return "", errors.New("filename is not valid UTF-8")
	}
	return string(raw), nil
}

func ValidateFilename(filename string) error {
	if filename == "" || filename == "." || filename == ".." {
		return errors.New("empty filename")
	}
	if strings.ContainsAny(filename, "/\\") {
		return errors.New("path separators are not allowed")
	}
	for _, r := range filename {
		if unicode.IsControl(r) {
			return errors.New("control characters are not allowed")
		}
		// Block Unicode format characters (category Cf): bidirectional
		// overrides/isolates, zero-width spaces, soft hyphen and BOM. All of
		// these are invisible and can disguise the true filename in a terminal.
		if unicode.Is(unicode.Cf, r) {
			return errors.New("formatting control characters are not allowed in filenames")
		}
	}
	if filepath.Base(filename) != filename {
		return errors.New("filename must be a basename")
	}
	return nil
}

// ChunkString is a thin wrapper around dnshelpers.ChunkString kept for
// backwards compatibility. New code should call dnshelpers directly.
func ChunkString(value string, size int) []string {
	return dnshelpers.ChunkString(value, size)
}

func JoinName(domain, command string, args []string) string {
	return JoinNameFast(AuthDomain(domain), strings.ToLower(command), args)
}

// JoinNameFast is JoinName with the caller-side normalization pre-applied:
// authDomain must already be lowercase and dot-trimmed (AuthDomain output);
// lowerCmd must already be lowercase. Hot-path callers should compute both
// once per tunnel and reuse across every DNS query in that tunnel to skip
// the strings.ToLower / AuthDomain allocations on each round-trip.
func JoinNameFast(authDomain, lowerCmd string, args []string) string {
	labels := make([]string, 0, len(args)+2)
	labels = append(labels, args...)
	labels = append(labels, lowerCmd, authDomain)
	return strings.Join(labels, ".")
}
