package protocol

import (
	"strings"
	"testing"
)

func TestSessionMACRoundtrip(t *testing.T) {
	key := DeriveSessionKey("k", "0123456789abcdef")
	mac := SessionMAC(key, "awrite", 42)
	if len(mac) != 8 {
		t.Fatalf("MAC length: got %d want 8", len(mac))
	}
	if !VerifySessionMAC(key, "awrite", 42, mac) {
		t.Fatal("roundtrip failed")
	}
}

func TestSessionMACSeparation(t *testing.T) {
	k1 := DeriveSessionKey("k", "0123456789abcdef")
	k2 := DeriveSessionKey("k", "fedcba9876543210")
	if SessionMAC(k1, "awrite", 1) == SessionMAC(k2, "awrite", 1) {
		t.Fatal("different cids produced identical MAC")
	}

	kSame := DeriveSessionKey("OTHER", "0123456789abcdef")
	if SessionMAC(k1, "awrite", 1) == SessionMAC(kSame, "awrite", 1) {
		t.Fatal("different secrets produced identical MAC")
	}
}

func TestSessionMACBindsToCommand(t *testing.T) {
	key := DeriveSessionKey("k", "0123456789abcdef")
	if SessionMAC(key, "awrite", 1) == SessionMAC(key, "aread", 1) {
		t.Fatal("MAC ignored command")
	}
}

func TestSessionMACBindsToSeq(t *testing.T) {
	key := DeriveSessionKey("k", "0123456789abcdef")
	if SessionMAC(key, "awrite", 1) == SessionMAC(key, "awrite", 2) {
		t.Fatal("MAC ignored seq")
	}
}

func TestVerifySessionMACRejects(t *testing.T) {
	key := DeriveSessionKey("k", "0123456789abcdef")
	good := SessionMAC(key, "awrite", 1)

	if VerifySessionMAC(key, "awrite", 2, good) {
		t.Fatal("verifier accepted wrong seq")
	}
	if VerifySessionMAC(key, "aread", 1, good) {
		t.Fatal("verifier accepted wrong command")
	}
	if VerifySessionMAC(key, "awrite", 1, "") {
		t.Fatal("verifier accepted empty MAC")
	}
	if VerifySessionMAC(key, "awrite", 1, strings.Repeat("a", 8)) {
		t.Fatal("verifier accepted random MAC")
	}
}

// TestDeriveSessionKeyDistinctFromAEADKey: SessionMAC must not be derivable
// from the AEAD key the chunks are sealed under (or vice-versa). A
// regression here would let an attacker who somehow learned one key forge
// the other. We can't import internal/proxy from internal/protocol, so this
// just pins that the context prefix is namespace-distinct (anti-typo).
func TestDeriveSessionKeyContextNamespaced(t *testing.T) {
	if !strings.HasPrefix(sessionKeyContext, "gdns2tcp-session") {
		t.Fatalf("session key context drift: %q", sessionKeyContext)
	}
}
