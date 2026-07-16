package cryptoutil

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestProtectFileOpenFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.bin")
	protected := filepath.Join(dir, "payload.gdt")
	out := filepath.Join(dir, "out.bin")
	want := bytes.Repeat([]byte("streaming-gdt2-"), 8192)
	if err := os.WriteFile(src, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ProtectFile("secret", src, protected); err != nil {
		t.Fatalf("ProtectFile: %v", err)
	}
	if err := OpenFile("secret", protected, out); err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("streaming round trip mismatch")
	}
}

func TestProtectRoundTrip(t *testing.T) {
	input := []byte("sensitive test payload")
	protected, err := Protect("correct horse battery staple", input)
	if err != nil {
		t.Fatal(err)
	}
	output, err := Open("correct horse battery staple", protected)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != string(input) {
		t.Fatalf("output=%q want %q", output, input)
	}
}

func TestOpenRejectsWrongSecret(t *testing.T) {
	protected, err := Protect("one", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open("two", protected); err == nil {
		t.Fatal("expected wrong secret to fail")
	}
}

// TestProtectEmptySecret verifies that Protect rejects an empty secret.
func TestProtectEmptySecret(t *testing.T) {
	_, err := Protect("", []byte("x"))
	if err == nil {
		t.Fatal("expected error for empty secret, got nil")
	}
}

// TestOpenEmptySecret verifies that Open rejects an empty secret.
func TestOpenEmptySecret(t *testing.T) {
	_, err := Open("", []byte("x"))
	if err == nil {
		t.Fatal("expected error for empty secret, got nil")
	}
}

// TestOpenTooShort verifies that Open rejects a protected blob that is too
// short to contain the required header fields.
func TestOpenTooShort(t *testing.T) {
	_, err := Open("secret", []byte("short"))
	if err == nil {
		t.Fatal("expected error for too-short protected data, got nil")
	}
}

// TestOpenWrongMagic verifies that Open rejects a blob whose magic bytes have
// been corrupted.
func TestOpenWrongMagic(t *testing.T) {
	protected, err := Protect("secret", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the first byte of the magic header.
	corrupted := make([]byte, len(protected))
	copy(corrupted, protected)
	corrupted[0] ^= 0xFF

	_, err = Open("secret", corrupted)
	if err == nil {
		t.Fatal("expected error for wrong magic bytes, got nil")
	}
}

// TestProtectToBase64OpenBase64Roundtrip verifies the base64 helper wrappers
// produce the same plaintext as the raw Protect/Open pair.
func TestProtectToBase64OpenBase64Roundtrip(t *testing.T) {
	input := []byte("base64 roundtrip test")
	encoded, err := ProtectToBase64("roundtrip-secret", input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenBase64("roundtrip-secret", encoded)
	if err != nil {
		t.Fatalf("OpenBase64 returned error: %v", err)
	}
	if string(got) != string(input) {
		t.Fatalf("got=%q want=%q", got, input)
	}
}

// TestOpenInvalidPKCS7Padding verifies that a protected blob whose ciphertext
// has been tampered with is rejected. Because the HMAC covers the ciphertext,
// the HMAC check fires before any padding validation attempt.
func TestOpenInvalidPKCS7Padding(t *testing.T) {
	protected, err := Protect("secret", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// Flip the last byte of the protected blob (part of the ciphertext).
	tampered := make([]byte, len(protected))
	copy(tampered, protected)
	tampered[len(tampered)-1] ^= 0x01

	_, err = Open("secret", tampered)
	if err == nil {
		t.Fatal("expected error after ciphertext tampering, got nil")
	}
}

// TestProtectOpenEmptyPlaintext verifies that encrypting and decrypting an
// empty plaintext succeeds and returns an empty byte slice.
func TestProtectOpenEmptyPlaintext(t *testing.T) {
	protected, err := Protect("secret", []byte{})
	if err != nil {
		t.Fatalf("Protect with empty plaintext returned error: %v", err)
	}
	got, err := Open("secret", protected)
	if err != nil {
		t.Fatalf("Open with empty plaintext returned error: %v", err)
	}
	if !bytes.Equal(got, []byte{}) {
		t.Fatalf("got=%v want empty slice", got)
	}
}

func TestPKCS7ValidationBranches(t *testing.T) {
	padded := pkcs7Pad([]byte("abc"), 8)
	if got, err := pkcs7Unpad(padded, 8); err != nil || string(got) != "abc" {
		t.Fatalf("unpad=%q err=%v", got, err)
	}
	for _, invalid := range [][]byte{
		nil,
		{1, 2, 3},
		{1, 2, 3, 4, 5, 6, 7, 0},
		{1, 2, 3, 4, 5, 6, 7, 9},
		{1, 2, 3, 4, 5, 6, 3, 2},
	} {
		if _, err := pkcs7Unpad(invalid, 8); err == nil {
			t.Fatalf("invalid padding accepted: %v", invalid)
		}
	}
}

func TestOpenRejectsInvalidBase64AndMisalignedCiphertext(t *testing.T) {
	if _, err := OpenBase64("secret", "%%%"); err == nil {
		t.Fatal("invalid Base64 accepted")
	}
	protected, err := Protect("secret", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open("secret", protected[:len(protected)-1]); err == nil {
		t.Fatal("misaligned ciphertext accepted")
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

type partialErrorWriter struct{ wrote bool }

func (w *partialErrorWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.wrote = true
		return len(p) / 2, nil
	}
	return 0, io.ErrClosedPipe
}

func TestWriteAllShortAndPartialErrors(t *testing.T) {
	if err := writeAll(zeroWriter{}, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero write error=%v", err)
	}
	if err := writeAll(&partialErrorWriter{}, []byte("abcd")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("partial write error=%v", err)
	}
}

func TestStreamingCryptoRejectsMalformedInputsAndCleansOutput(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "plain.bin")
	protected := filepath.Join(dir, "protected.gdt")
	out := filepath.Join(dir, "out.bin")
	if err := os.WriteFile(src, []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ProtectFile("", src, protected); err == nil {
		t.Fatal("empty secret ProtectFile succeeded")
	}
	if err := ProtectFile("secret", filepath.Join(dir, "missing"), protected); err == nil {
		t.Fatal("missing source ProtectFile succeeded")
	}
	if err := OpenFile("", protected, out); err == nil {
		t.Fatal("empty secret OpenFile succeeded")
	}
	if err := os.WriteFile(protected, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := OpenFile("secret", protected, out); err == nil {
		t.Fatal("short protected file accepted")
	}
	if err := ProtectFile("secret", src, protected); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(protected)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	if err := os.WriteFile(protected, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := OpenFile("secret", protected, out); err == nil {
		t.Fatal("wrong magic accepted")
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed decrypt retained output: %v", err)
	}
}

func TestStreamingCryptoRejectsWrongSecretAndDirectoryOutputs(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "plain")
	protected := filepath.Join(dir, "protected")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ProtectFile("secret", src, dir); err == nil {
		t.Fatal("ProtectFile accepted a directory destination")
	}
	if err := ProtectFile("secret", src, protected); err != nil {
		t.Fatal(err)
	}
	if err := OpenFile("wrong", protected, filepath.Join(dir, "wrong")); err == nil {
		t.Fatal("OpenFile accepted the wrong secret")
	}
	if err := OpenFile("secret", protected, dir); err == nil {
		t.Fatal("OpenFile accepted a directory destination")
	}
}
