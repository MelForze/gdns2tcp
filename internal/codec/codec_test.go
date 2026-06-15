package codec

import (
	"strings"
	"testing"
)

func TestChunkString(t *testing.T) {
	got := ChunkString("abcdef", 2)
	want := []string{"ab", "cd", "ef"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chunk %d=%q want %q", i, got[i], want[i])
		}
	}
}

func TestCompressRoundTrip(t *testing.T) {
	input := []byte("portable dns txt transfer")
	compressed, err := Compress(input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := DecompressLimit(compressed, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != string(input) {
		t.Fatalf("output=%q want %q", output, input)
	}
}

func TestDNSPayloadRoundTrip(t *testing.T) {
	for _, encoding := range []string{"base64", "base32"} {
		encoded, err := EncodeDNSPayload([]byte("payload"), encoding)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeDNSPayload(encoded, encoding)
		if err != nil {
			t.Fatal(err)
		}
		if string(decoded) != "payload" {
			t.Fatalf("%s decoded=%q", encoding, decoded)
		}
	}
}

// TestDecompressLimitExceeded verifies that DecompressLimit returns an error
// when the decompressed data exceeds the given byte limit.
func TestDecompressLimitExceeded(t *testing.T) {
	compressed, err := Compress([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecompressLimit(compressed, 2)
	if err == nil {
		t.Fatal("expected error when decompressed size exceeds limit, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds") && !strings.Contains(err.Error(), "limit") {
		t.Fatalf("error %q does not mention 'exceeds' or 'limit'", err.Error())
	}
}

// TestDecompressLimitOK verifies that DecompressLimit succeeds when the limit
// is larger than the decompressed data.
func TestDecompressLimitOK(t *testing.T) {
	input := []byte("hello")
	compressed, err := Compress(input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecompressLimit(compressed, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(input) {
		t.Fatalf("got=%q want=%q", got, input)
	}
}

// TestChunkStringEdgeCases covers empty input, input shorter than chunk size,
// and a chunk size of zero.
func TestChunkStringEdgeCases(t *testing.T) {
	// Empty string should return nil or an empty slice.
	got := ChunkString("", 5)
	if len(got) != 0 {
		t.Fatalf("ChunkString(\"\", 5): expected empty result, got %v", got)
	}

	// Input shorter than chunk size should return a single chunk.
	got = ChunkString("abc", 10)
	if len(got) != 1 || got[0] != "abc" {
		t.Fatalf("ChunkString(\"abc\", 10): got %v, want [\"abc\"]", got)
	}

	// Zero chunk size should return nil.
	got = ChunkString("abc", 0)
	if got != nil {
		t.Fatalf("ChunkString(\"abc\", 0): expected nil, got %v", got)
	}
}

// TestEncodeDNSPayloadUnsupported verifies that an unknown encoding returns an error.
func TestEncodeDNSPayloadUnsupported(t *testing.T) {
	_, err := EncodeDNSPayload([]byte("x"), "unknown")
	if err == nil {
		t.Fatal("expected error for unsupported encoding, got nil")
	}
}

// TestDecodeDNSPayloadUnsupported verifies that an unknown encoding returns an error.
func TestDecodeDNSPayloadUnsupported(t *testing.T) {
	_, err := DecodeDNSPayload("x", "unknown")
	if err == nil {
		t.Fatal("expected error for unsupported encoding, got nil")
	}
}

// TestDecodeDNSPayloadBase64NoPadding verifies that base64-encoded data with
// trailing '=' padding stripped is still decoded correctly via modLikePython.
func TestDecodeDNSPayloadBase64NoPadding(t *testing.T) {
	input := []byte("dns-payload-test")
	encoded, err := EncodeDNSPayload(input, "base64")
	if err != nil {
		t.Fatal(err)
	}
	// Strip any trailing padding characters.
	stripped := strings.TrimRight(encoded, "=")

	got, err := DecodeDNSPayload(stripped, "base64")
	if err != nil {
		t.Fatalf("DecodeDNSPayload with stripped padding returned error: %v", err)
	}
	if string(got) != string(input) {
		t.Fatalf("got=%q want=%q", got, input)
	}
}
