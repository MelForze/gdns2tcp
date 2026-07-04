package dnshelpers

import (
	"strings"
	"testing"
)

// TestB32LowerNoPadIsLowercase locks in the invariant that hot-path
// encoders never emit uppercase — a regression here would re-introduce
// the strings.ToLower allocation the whole point of B32LowerNoPad avoids.
func TestB32LowerNoPadIsLowercase(t *testing.T) {
	in := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0xAB, 0xCD, 0xEF}
	out := B32LowerNoPad.EncodeToString(in)
	if out == "" {
		t.Fatal("empty encoding")
	}
	if strings.ToLower(out) != out {
		t.Fatalf("encoder produced uppercase characters: %q", out)
	}
	for _, r := range out {
		if !((r >= 'a' && r <= 'z') || (r >= '2' && r <= '7')) {
			t.Fatalf("unexpected char %q in output", r)
		}
	}
}

// TestB32DecodeAnyRoundtripsBothCases catches a regression where the
// server-side decoder forgets one of the two cases (e.g. drops the
// stdlib uppercase fallback and rejects legacy peers, or drops the
// lowercase decoder and re-introduces strings.ToUpper allocations).
func TestB32DecodeAnyRoundtripsBothCases(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A}

	lower := B32LowerNoPad.EncodeToString(payload)
	if got, err := B32DecodeAny(lower); err != nil || string(got) != string(payload) {
		t.Fatalf("lowercase roundtrip: got %v, err %v", got, err)
	}
	upper := stdB32NoPad.EncodeToString(payload)
	if got, err := B32DecodeAny(upper); err != nil || string(got) != string(payload) {
		t.Fatalf("uppercase roundtrip: got %v, err %v", got, err)
	}
	// Digits-only input (rare but valid) — decoder must pick a branch
	// without erroring.
	digits := "23456723"
	if _, err := B32DecodeAny(digits); err != nil {
		t.Fatalf("digits-only decode: %v", err)
	}
	// Invalid input yields an error, not a panic.
	if _, err := B32DecodeAny("not-base32!"); err == nil {
		t.Fatal("expected error for invalid input")
	}
	// Mixed-case: some resolvers randomize label case per RFC 5452
	// 0x20 (Cloudflare 1.1.1.1). Decoder must fold to a single case
	// and decode successfully instead of hitting the wrong-alphabet
	// path and returning "illegal base32 data".
	if got, err := B32DecodeAny(strings.ToUpper(lower[:len(lower)/2]) + lower[len(lower)/2:]); err != nil || string(got) != string(payload) {
		t.Fatalf("mixed-case roundtrip: got %v, err %v", got, err)
	}
}

// BenchmarkB32LowerEncode pins the alloc count. Should be exactly 1
// allocation (the returned string). If someone re-introduces
// strings.ToLower on the output, this count doubles and CI catches it.
func BenchmarkB32LowerEncode(b *testing.B) {
	buf := make([]byte, 100)
	for i := range buf {
		buf[i] = byte(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = B32LowerNoPad.EncodeToString(buf)
	}
}
