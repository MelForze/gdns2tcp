package codec

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStreamingFileCodecs(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.bin")
	encoded := filepath.Join(dir, "encoded.txt")
	decoded := filepath.Join(dir, "decoded.bin")
	want := bytes.Repeat([]byte{0, 1, 2, 3, 4, 250, 251, 252}, 8192)
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{"base64", "base32"} {
		if _, err := EncodeDNSFile(src, encoded, encoding); err != nil {
			t.Fatalf("EncodeDNSFile(%s): %v", encoding, err)
		}
		if _, err := DecodeDNSFile(encoded, decoded, encoding); err != nil {
			t.Fatalf("DecodeDNSFile(%s): %v", encoding, err)
		}
		got, err := os.ReadFile(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("streaming %s mismatch", encoding)
		}
	}
}

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

func TestStreamingFileHelpersAndLimits(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.bin")
	compressed := filepath.Join(dir, "source.gz")
	decoded := filepath.Join(dir, "decoded.bin")
	payload := bytes.Repeat([]byte("streaming-codec-"), 4096)
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CompressFile(src, compressed); err != nil {
		t.Fatal(err)
	}
	n, err := DecompressFileLimit(compressed, decoded, int64(len(payload)))
	if err != nil || n != int64(len(payload)) {
		t.Fatalf("decompress n=%d err=%v", n, err)
	}
	got, err := os.ReadFile(decoded)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("decoded mismatch err=%v", err)
	}
	if _, err := DecompressFileLimit(compressed, decoded, int64(len(payload)-1)); err == nil {
		t.Fatal("decompression over limit succeeded")
	}
	if _, err := os.Stat(decoded); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed output retained: %v", err)
	}
	if _, err := DecompressFileLimit(src, decoded, 100); err == nil {
		t.Fatal("invalid gzip succeeded")
	}
}

func TestStreamingCodecErrorCleanupAndDNSAlphabet(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.bin")
	dst := filepath.Join(dir, "output.bin")
	if err := os.WriteFile(src, []byte{0xfb, 0xff, 0xef, 0x01}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeDNSFile(src, dst, "rot13"); err == nil {
		t.Fatal("unsupported file encoding succeeded")
	}
	if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed encoded output retained: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte{0xfb, 0xff, 0xef, 0x01})
	encoded = strings.NewReplacer("+", "_", "/", "-").Replace(encoded)
	if err := os.WriteFile(src, []byte(" \n"+encoded+"=\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDNSFile(src, dst, "base64"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(dst); err != nil || !bytes.Equal(got, []byte{0xfb, 0xff, 0xef, 0x01}) {
		t.Fatalf("DNS alphabet decode=%x err=%v", got, err)
	}
	if _, err := DecodeDNSFile(src, dst, "rot13"); err == nil {
		t.Fatal("unsupported decode succeeded")
	}
	if _, err := EncodeDNSFile(filepath.Join(dir, "missing"), dst, "base64"); err == nil {
		t.Fatal("missing source encode succeeded")
	}
	if _, err := DecodeDNSFile(filepath.Join(dir, "missing"), dst, "base64"); err == nil {
		t.Fatal("missing source decode succeeded")
	}
}

func TestStreamingAdapters(t *testing.T) {
	var lower bytes.Buffer
	input := []byte("AbCZ09")
	if _, err := (&lowerWriter{w: &lower}).Write(input); err != nil || lower.String() != "abcz09" {
		t.Fatalf("lower writer=%q err=%v", lower.String(), err)
	}
	// Regression: lowerWriter must not mutate the caller's buffer (io.Writer
	// contract). Prior in-place implementation happened to work because base32
	// encoder didn't re-read, but violated the contract.
	original := []byte("AbCZ09")
	preserved := make([]byte, len(original))
	copy(preserved, original)
	var sink bytes.Buffer
	if _, err := (&lowerWriter{w: &sink}).Write(preserved); err != nil {
		t.Fatalf("lower writer preserves-input write: %v", err)
	}
	if !bytes.Equal(preserved, original) {
		t.Fatalf("lowerWriter mutated caller buffer: got %q want %q", preserved, original)
	}
	upperBytes, err := io.ReadAll(upperReader{r: strings.NewReader("abCZ09")})
	if err != nil || string(upperBytes) != "ABCZ09" {
		t.Fatalf("upper reader=%q err=%v", upperBytes, err)
	}
	cleaned, err := io.ReadAll(base64DNSReader{r: strings.NewReader(" \n-_==\t")})
	if err != nil || string(cleaned) != "/+" {
		t.Fatalf("base64 DNS reader=%q err=%v", cleaned, err)
	}
	var dst bytes.Buffer
	lw := &limitWriter{w: &dst, remain: 3}
	if _, err := lw.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := lw.Write([]byte("d")); err == nil {
		t.Fatal("limit writer accepted overflow")
	}
}

func TestStreamingCodecRejectsDirectoryDestinations(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source")
	encoded := filepath.Join(dir, "encoded")
	compressed := filepath.Join(dir, "compressed")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeDNSFile(src, dir, "base64"); err == nil {
		t.Fatal("encoding to a directory succeeded")
	}
	if _, err := EncodeDNSFile(src, encoded, "base64"); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDNSFile(encoded, dir, "base64"); err == nil {
		t.Fatal("decoding to a directory succeeded")
	}
	if err := CompressFile(src, dir); err == nil {
		t.Fatal("compression to a directory succeeded")
	}
	if err := CompressFile(src, compressed); err != nil {
		t.Fatal(err)
	}
	if _, err := DecompressFileLimit(compressed, dir, 1024); err == nil {
		t.Fatal("decompression to a directory succeeded")
	}
}
