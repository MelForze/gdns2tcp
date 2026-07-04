package main

import (
	"sync/atomic"
	"testing"

	"gdns2tcp/internal/protocol"
)

// TestPickShardAuthDomainRoundRobin verifies that non-worker callers
// (apoll / aclose) actually rotate. A regression that pins them to
// shardAuthDomains[0] would negate the whole point of multi-domain
// sharding for those endpoints — every apoll would land on the same
// resolver-side zone and eat that zone's rate-limit alone.
func TestPickShardAuthDomainRoundRobin(t *testing.T) {
	cfg := config{
		domain:           "a.com",
		shardAuthDomains: []string{"a.com", "b.com", "c.com"},
		shardRotor:       new(atomic.Uint64),
	}
	seen := map[string]int{}
	const N = 300
	for i := 0; i < N; i++ {
		seen[cfg.pickShardAuthDomain()]++
	}
	// Even split gives 100 each; allow ±10% for atomic-add scheduling.
	for _, d := range []string{"a.com", "b.com", "c.com"} {
		if seen[d] < 90 || seen[d] > 110 {
			t.Errorf("shard %q got %d hits out of %d (want ~%d ±10%%)", d, seen[d], N, N/3)
		}
	}
}

// TestPickShardAuthDomainSingleDomain checks the fast-path: a config
// with exactly one shard must never touch the atomic (would be wasted
// contention on the single-domain deployments that are the majority).
// Testing behavior: the returned value is stable across many calls.
func TestPickShardAuthDomainSingleDomain(t *testing.T) {
	cfg := config{
		domain:           "only.com",
		shardAuthDomains: []string{"only.com"},
		shardRotor:       new(atomic.Uint64),
	}
	for i := 0; i < 100; i++ {
		if got := cfg.pickShardAuthDomain(); got != "only.com" {
			t.Fatalf("iter %d got %q want only.com", i, got)
		}
	}
	// Rotor must remain untouched — proves we didn't pay the atomic
	// cost on the single-domain hot path.
	if r := cfg.shardRotor.Load(); r != 0 {
		t.Errorf("shardRotor bumped to %d on single-domain config; fast path leaked into the atomic", r)
	}
}

// TestPickShardAuthDomainFallbackFromCanonical guards against config
// fixtures that skip parseFlags (every _test.go in this package builds
// config{...} literally). Those must still resolve to a usable
// AuthDomain suffix — otherwise agentExchange builds QNAMEs with an
// empty suffix and the server FORMERRs everything.
func TestPickShardAuthDomainFallbackFromCanonical(t *testing.T) {
	cfg := config{domain: "raw.example.com"} // no shardAuthDomains, no rotor
	got := cfg.pickShardAuthDomain()
	want := protocol.AuthDomain("raw.example.com")
	if got != want {
		t.Fatalf("fallback got %q want %q", got, want)
	}
}

// TestLongestBudgetDomainPrefersShardLongest pins the budget calc
// invariant: the QNAME-length worst case must be driven by the *widest*
// configured shard, otherwise a shorter canonical would let the rotator
// send a query to a wider shard whose QNAME then exceeds 253 chars.
func TestLongestBudgetDomainPrefersShardLongest(t *testing.T) {
	cfg := config{
		domain:       "short.io",
		shardLongest: "much-longer-shard.example.com",
	}
	if got := cfg.longestBudgetDomain(); got != "much-longer-shard.example.com" {
		t.Fatalf("longestBudgetDomain=%q want much-longer-shard.example.com", got)
	}
}

// TestLongestBudgetDomainFallback verifies that a test-fixture config
// without shardLongest still returns a non-empty domain — otherwise
// maxAxchgWritePlaintextBytes computes budget for a 0-char domain and
// hands back an over-large chunk size that later overflows QNAME.
func TestLongestBudgetDomainFallback(t *testing.T) {
	cfg := config{domain: "canon.test"}
	if got := cfg.longestBudgetDomain(); got != "canon.test" {
		t.Fatalf("fallback longestBudgetDomain=%q want canon.test", got)
	}
}
