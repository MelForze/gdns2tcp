package dnshelpers

import (
	"strings"
	"testing"
)

// TestChunkStringZeroCap catches a regression where somebody swaps out
// the pre-sized allocation for a make([]string, 0) — resulting in slice
// growth reallocations on every call.
func TestChunkStringZeroCap(t *testing.T) {
	got := ChunkString("abcdefghij", 3)
	want := []string{"abc", "def", "ghi", "j"}
	if len(got) != len(want) {
		t.Fatalf("len: got %d want %d (%v)", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("chunk %d: got %q want %q", i, got[i], w)
		}
	}
}

// TestChunkStringInvalidSize returns nil for size <= 0. A regression that
// panics on the boundary would break several downstream callers.
func TestChunkStringInvalidSize(t *testing.T) {
	if got := ChunkString("abc", 0); got != nil {
		t.Fatalf("size=0: expected nil, got %v", got)
	}
	if got := ChunkString("abc", -1); got != nil {
		t.Fatalf("size=-1: expected nil, got %v", got)
	}
}

// TestChunkStringFitsExactly stresses the (len % size == 0) boundary; a
// regression that miscounts the final chunk here would silently drop the
// last few bytes of every axchg-write payload.
func TestChunkStringFitsExactly(t *testing.T) {
	in := strings.Repeat("x", 60)
	got := ChunkString(in, 20)
	if len(got) != 3 {
		t.Fatalf("want 3 chunks, got %d", len(got))
	}
	if strings.Join(got, "") != in {
		t.Fatal("roundtrip mismatch")
	}
}

// BenchmarkChunkString pins the allocation count — the caller-side
// pre-size (based on cap) means this should be exactly 1 allocation for
// the returned []string.
func BenchmarkChunkString(b *testing.B) {
	in := strings.Repeat("abcd", 100) // 400 chars
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = ChunkString(in, 63)
	}
}
