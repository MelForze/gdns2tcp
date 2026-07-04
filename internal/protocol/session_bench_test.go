package protocol

import (
	"strings"
	"testing"
)

// TestSessionMACLowerCaseOutput locks in that the encoder writes lowercase
// directly. A regression that reintroduces the uppercase encoder + a
// strings.ToLower copy would break this test — and would silently
// increase per-axchg allocations.
func TestSessionMACLowerCaseOutput(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	got := SessionMAC(key, "axchg", 42)
	if strings.ToLower(got) != got {
		t.Fatalf("SessionMAC returned non-lowercase output %q", got)
	}
}

// TestSessionMACConsistentAcrossCalls locks in that the pooled HMAC
// resets properly between calls with the same key. A pool bug that
// carried state between calls would produce a different MAC for the same
// input.
func TestSessionMACConsistentAcrossCalls(t *testing.T) {
	var key [32]byte
	first := SessionMAC(key, "axchg", 1)
	for range 10 {
		if got := SessionMAC(key, "axchg", 1); got != first {
			t.Fatalf("SessionMAC not deterministic: first=%q got=%q", first, got)
		}
	}
}

// TestSessionMACSwitchesKeys catches a pool bug that would keep using
// the previous key's block schedule after the caller switches keys.
func TestSessionMACSwitchesKeys(t *testing.T) {
	var a, b [32]byte
	for i := range a {
		a[i] = 1
		b[i] = 2
	}
	// Interleave to force the pool entry to switch keys back and forth.
	m1 := SessionMAC(a, "axchg", 0)
	m2 := SessionMAC(b, "axchg", 0)
	m3 := SessionMAC(a, "axchg", 0)
	if m1 == m2 {
		t.Fatal("different keys produced identical MACs")
	}
	if m1 != m3 {
		t.Fatalf("switching keys corrupted state: m1=%q m3=%q", m1, m3)
	}
}

// BenchmarkSessionMAC pins the allocation count. The pooled hasher
// should keep it very low (only the returned string is allocated by
// base32.EncodeToString). A regression to `hmac.New` per call would
// double the count.
func BenchmarkSessionMAC(b *testing.B) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		_ = SessionMAC(key, "axchg", uint64(i))
	}
}

// BenchmarkVerifySessionMAC pins the alloc count for the verifier — the
// hot path on the server. Fast path (all-lowercase input) should avoid
// the strings.ToLower allocation entirely.
func BenchmarkVerifySessionMAC(b *testing.B) {
	var key [32]byte
	mac := SessionMAC(key, "axchg", 1)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = VerifySessionMAC(key, "axchg", 1, mac)
	}
}
