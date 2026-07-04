package proxy

import "testing"

// TestSealChunkToRespectsDstCap catches a regression where SealChunkTo
// forgets to append into dst (e.g. re-passing dst instead of dst[:0])
// and returns a wrongly-sized ciphertext.
func TestSealChunkToRespectsDstCap(t *testing.T) {
	aead, err := SessionAEAD("secret", "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("hello, world")
	// dst with sufficient cap — should be reused, no allocation.
	dst := make([]byte, 0, len(plaintext)+aead.Overhead())
	ct := SealChunkTo(dst, aead, DirClientToServer, 1, plaintext)
	if len(ct) != len(plaintext)+aead.Overhead() {
		t.Fatalf("SealChunkTo returned wrong size: got %d want %d", len(ct), len(plaintext)+aead.Overhead())
	}
	// Roundtrip via OpenChunkTo.
	ptDst := make([]byte, 0, len(plaintext))
	pt, err := OpenChunkTo(ptDst, aead, DirClientToServer, 1, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("roundtrip mismatch: got %q want %q", pt, plaintext)
	}
}

// TestSealChunkToNilDstStillWorks catches a regression where the fallback
// path forgets that nil dst is legal (aead.Seal will allocate).
func TestSealChunkToNilDstStillWorks(t *testing.T) {
	aead, _ := SessionAEAD("secret", "0123456789abcdef")
	ct := SealChunkTo(nil, aead, DirClientToServer, 1, []byte("x"))
	if len(ct) == 0 {
		t.Fatal("SealChunkTo(nil, …) returned empty")
	}
	pt, err := OpenChunkTo(nil, aead, DirClientToServer, 1, ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "x" {
		t.Fatalf("roundtrip: got %q", pt)
	}
}

// BenchmarkSealChunk vs BenchmarkSealChunkTo — a regression that starts
// re-allocating every call (or forgets to reuse dst) will show up as
// higher allocs/op in BenchmarkSealChunkTo.
func BenchmarkSealChunk(b *testing.B) {
	aead, _ := SessionAEAD("secret", "0123456789abcdef")
	plaintext := make([]byte, 100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		_ = SealChunk(aead, DirClientToServer, uint64(i), plaintext)
	}
}

func BenchmarkSealChunkTo(b *testing.B) {
	aead, _ := SessionAEAD("secret", "0123456789abcdef")
	plaintext := make([]byte, 100)
	dst := make([]byte, 0, len(plaintext)+aead.Overhead())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		_ = SealChunkTo(dst, aead, DirClientToServer, uint64(i), plaintext)
	}
}
