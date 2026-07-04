package main

import "testing"

// TestNonceGuardExceededBoundaries pins the trigger points of the
// long-lived-tunnel guard. A regression that shifts the threshold up or
// down would either leak silently past 32 bits (silent FORMERR loop) or
// tear healthy tunnels down early.
func TestNonceGuardExceededBoundaries(t *testing.T) {
	cases := []struct {
		name         string
		seq          uint64
		currentNonce uint64
		workers      int
		want         bool
	}{
		{"fresh tunnel", 0, 0, 96, false},
		{"1 M seqs in", 1_000_000, 1_000_000, 96, false},
		{"1 B seqs in", 1_000_000_000, 1_000_000_000, 96, false},
		// Just before 32-bit cap on seq (guard checks seq+1 > 0xFFFFFFFF).
		{"seq one below cap", 0xFFFFFFFE, 0, 96, false},
		{"seq at cap", 0xFFFFFFFF, 0, 96, true},
		{"seq over cap", 0xFFFFFFFF + 1, 0, 96, true},
		// Nonce side: guard checks currentNonce+workers > 0xFFFFFFFF.
		{"nonce safe", 0, 0xFFFFFFFF - 200, 96, false},
		{"nonce just below with 96 workers", 0, 0xFFFFFFFF - 96, 96, false},
		{"nonce reaches cap with 96 workers", 0, 0xFFFFFFFF - 95, 96, true},
		{"nonce well over cap", 0, 0xFFFFFFFF, 96, true},
	}
	for _, tc := range cases {
		if got := nonceGuardExceeded(tc.seq, tc.currentNonce, tc.workers); got != tc.want {
			t.Errorf("%s: seq=%#x nonce=%#x workers=%d → got %v want %v",
				tc.name, tc.seq, tc.currentNonce, tc.workers, got, tc.want)
		}
	}
}

// TestNonceGuardMatchesBudgetAssumption locks in the invariant that the
// guard fires strictly *before* hexWidth of seq or nonce would exceed 8
// hex characters — because 8 chars is what the budget calc reserves.
// A regression that widens the guard past this point would break the
// 253-char QNAME budget silently.
func TestNonceGuardMatchesBudgetAssumption(t *testing.T) {
	// Right at the boundary: seq = 0xFFFFFFFF (fits in 8 hex chars).
	// Guard must fire so we don't try seq+1 = 0x100000000 (9 chars).
	if !nonceGuardExceeded(0xFFFFFFFF, 0, 96) {
		t.Fatal("guard should fire at seq=0xFFFFFFFF (next seq needs 9 hex chars)")
	}
	// Just under (safe): seq = 0xFFFFFFFE. Next seq = 0xFFFFFFFF (8 chars).
	if nonceGuardExceeded(0xFFFFFFFE, 0, 96) {
		t.Fatal("guard should not fire at seq=0xFFFFFFFE (next seq still fits 8 hex chars)")
	}
	// The seq width used by the budget calc is exactly 8.
	if got := hexWidth(0xFFFFFFFF); got != 8 {
		t.Fatalf("hexWidth(0xFFFFFFFF) = %d, want 8", got)
	}
	if got := hexWidth(0x100000000); got != 9 {
		t.Fatalf("hexWidth(0x100000000) = %d, want 9", got)
	}
}
