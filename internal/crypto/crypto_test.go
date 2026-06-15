package cryptoutil

import (
	"bytes"
	"testing"
)

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
