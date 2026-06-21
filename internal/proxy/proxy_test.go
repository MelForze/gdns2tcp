package proxy

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeTargetRoundtrip(t *testing.T) {
	cases := []struct {
		host string
		port int
	}{
		{"example.com", 443},
		{"127.0.0.1", 22},
		{"::1", 80},
		{"a-very-very-long-internal-hostname.corp.example.test", 8080},
		{"2001:db8::1", 65535},
		{"x", 1},
	}
	for _, c := range cases {
		labels, err := EncodeTarget(c.host, c.port)
		if err != nil {
			t.Fatalf("encode %q:%d: %v", c.host, c.port, err)
		}
		for _, l := range labels {
			if len(l) == 0 || len(l) > 63 {
				t.Fatalf("encoded label has invalid length %d: %q", len(l), l)
			}
		}
		gotHost, gotPort, err := DecodeTarget(labels)
		if err != nil {
			t.Fatalf("decode %q:%d: %v", c.host, c.port, err)
		}
		if gotHost != c.host || gotPort != c.port {
			t.Fatalf("roundtrip mismatch: encoded %q:%d, decoded %q:%d", c.host, c.port, gotHost, gotPort)
		}
	}
}

func TestEncodeTargetRejectsBadInput(t *testing.T) {
	if _, err := EncodeTarget("", 80); err == nil {
		t.Fatal("expected error for empty host")
	}
	if _, err := EncodeTarget("example.com", 0); err == nil {
		t.Fatal("expected error for port 0")
	}
	if _, err := EncodeTarget("example.com", 70000); err == nil {
		t.Fatal("expected error for port > 65535")
	}
}

func TestDecodeTargetRejectsBadInput(t *testing.T) {
	if _, _, err := DecodeTarget(nil); err == nil {
		t.Fatal("expected error for nil labels")
	}
	if _, _, err := DecodeTarget([]string{"%%%"}); err == nil {
		t.Fatal("expected error for non-base32")
	}
	// Valid base32 but no colon → "hello"
	if _, _, err := DecodeTarget([]string{"nbswy3dp"}); err == nil {
		t.Fatal("expected error when separator missing")
	}
}

func TestNewCIDUnique(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		cid, err := NewCID()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidCID(cid) {
			t.Fatalf("NewCID returned invalid form %q", cid)
		}
		if _, dup := seen[cid]; dup {
			t.Fatalf("duplicate cid %q in 1000-sample batch", cid)
		}
		seen[cid] = struct{}{}
	}
}

func TestValidCID(t *testing.T) {
	good := []string{"0123456789abcdef", "ffffffffffffffff", "0000000000000000"}
	for _, g := range good {
		if !ValidCID(g) {
			t.Fatalf("ValidCID rejected legitimate cid %q", g)
		}
	}
	bad := []string{"", "abc", "0123456789ABCDEF", "0123456789abcdefg", "0123456789abcde!"}
	for _, b := range bad {
		if ValidCID(b) {
			t.Fatalf("ValidCID accepted malformed cid %q", b)
		}
	}
}

func TestSessionAEADInteropAndKeySeparation(t *testing.T) {
	cid, _ := NewCID()
	otherCid, _ := NewCID()

	a, err := SessionAEAD("shared-secret", cid)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SessionAEAD("shared-secret", cid)
	if err != nil {
		t.Fatal(err)
	}

	// Same (secret, cid) → identical key → identical ciphertext for the same
	// plaintext under the same nonce.
	plaintext := []byte("hello tunnel")
	ct1 := SealChunk(a, DirClientToServer, 1, plaintext)
	ct2 := SealChunk(b, DirClientToServer, 1, plaintext)
	if !bytes.Equal(ct1, ct2) {
		t.Fatal("same (secret, cid, dir, seq) produced different ciphertexts")
	}

	// Different cid → different key → ciphertexts differ.
	c, err := SessionAEAD("shared-secret", otherCid)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct1, SealChunk(c, DirClientToServer, 1, plaintext)) {
		t.Fatal("different cid produced identical ciphertext")
	}

	// Different secret → different key.
	d, err := SessionAEAD("OTHER-secret", cid)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct1, SealChunk(d, DirClientToServer, 1, plaintext)) {
		t.Fatal("different secret produced identical ciphertext")
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	cid, _ := NewCID()
	aead, err := SessionAEAD("k", cid)
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("the quick brown fox jumps over the lazy dog")
	ct := SealChunk(aead, DirServerToClient, 42, pt)
	got, err := OpenChunk(aead, DirServerToClient, 42, ct)
	if err != nil {
		t.Fatalf("OpenChunk: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, pt)
	}
}

func TestOpenChunkRejectsWrongNonce(t *testing.T) {
	cid, _ := NewCID()
	aead, _ := SessionAEAD("k", cid)
	ct := SealChunk(aead, DirClientToServer, 5, []byte("payload"))

	// Right seq, wrong direction → must fail.
	if _, err := OpenChunk(aead, DirServerToClient, 5, ct); err == nil {
		t.Fatal("OpenChunk accepted wrong-direction nonce")
	}
	// Right direction, wrong seq → must fail.
	if _, err := OpenChunk(aead, DirClientToServer, 6, ct); err == nil {
		t.Fatal("OpenChunk accepted wrong-seq nonce")
	}
}

func TestOpenChunkRejectsTamper(t *testing.T) {
	cid, _ := NewCID()
	aead, _ := SessionAEAD("k", cid)
	ct := SealChunk(aead, DirClientToServer, 0, []byte("payload"))
	ct[0] ^= 0x01
	if _, err := OpenChunk(aead, DirClientToServer, 0, ct); err == nil {
		t.Fatal("OpenChunk accepted tampered ciphertext")
	}
}

func TestSessionAEADRejectsBadInputs(t *testing.T) {
	if _, err := SessionAEAD("", "0123456789abcdef"); err == nil {
		t.Fatal("expected error for empty secret")
	}
	if _, err := SessionAEAD("k", "not-a-cid"); err == nil {
		t.Fatal("expected error for invalid cid")
	}
}
