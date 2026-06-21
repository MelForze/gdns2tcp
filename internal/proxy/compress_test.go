package proxy

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestCompressorRoundtripCompressible(t *testing.T) {
	c, err := GetCompressor()
	if err != nil {
		t.Fatal(err)
	}
	src := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200))
	enc := c.Encode(src)
	if enc[0] != 0x01 {
		t.Fatalf("expected compressed flag, got %#x (encoded=%d raw=%d)", enc[0], len(enc), len(src))
	}
	if len(enc) >= len(src) {
		t.Fatalf("compressed length %d not smaller than raw %d", len(enc), len(src))
	}
	dec, err := c.Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(dec, src) {
		t.Fatal("roundtrip mismatch on compressible input")
	}
}

// TestCompressorPassthroughOnRandom: random bytes are incompressible; the
// Compressor must detect this and emit the pass-through branch instead of
// blowing the payload up with a zstd frame header.
func TestCompressorPassthroughOnRandom(t *testing.T) {
	c, err := GetCompressor()
	if err != nil {
		t.Fatal(err)
	}
	src := make([]byte, 256)
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}
	enc := c.Encode(src)
	if enc[0] != 0x00 {
		t.Fatalf("expected pass-through flag for random data, got %#x", enc[0])
	}
	if len(enc) != len(src)+1 {
		t.Fatalf("pass-through length got %d want %d", len(enc), len(src)+1)
	}
	dec, err := c.Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(dec, src) {
		t.Fatal("pass-through roundtrip mismatch")
	}
}

func TestCompressorRoundtripEmpty(t *testing.T) {
	c, err := GetCompressor()
	if err != nil {
		t.Fatal(err)
	}
	enc := c.Encode(nil)
	// 0x01 + zstd-empty or 0x00 + nothing — both legal as long as Decode
	// reproduces empty.
	dec, err := c.Decode(enc)
	if err != nil {
		t.Fatalf("Decode empty: %v", err)
	}
	if len(dec) != 0 {
		t.Fatalf("expected empty decode, got %d bytes", len(dec))
	}
}

func TestCompressorDecodeBadInput(t *testing.T) {
	c, err := GetCompressor()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decode(nil); err == nil {
		t.Fatal("expected error on empty input")
	}
	if _, err := c.Decode([]byte{0x7F, 'x'}); err == nil {
		t.Fatal("expected error on unknown flag")
	}
	if _, err := c.Decode([]byte{0x01, 'g', 'a', 'r', 'b'}); err == nil {
		t.Fatal("expected error on malformed zstd payload")
	}
}

func BenchmarkCompressorThroughput(b *testing.B) {
	c, _ := GetCompressor()
	src := []byte(strings.Repeat("hello world ", 1024))
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc := c.Encode(src)
		dec, err := c.Decode(enc)
		if err != nil || len(dec) != len(src) {
			b.Fatal(err)
		}
	}
}
