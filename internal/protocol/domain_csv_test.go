package protocol

import (
	"strings"
	"testing"
)

// TestParseDomainCSVSingleDomain pins the single-domain fast path.
// Any config built with the old (comma-less) -domain flag must produce
// canonical == input, len(shard*) == 1, and longest == input — otherwise
// long-standing deployments would silently start behaving as if they
// were multi-domain (rotating suffixes, wider budget worst-case, etc.).
func TestParseDomainCSVSingleDomain(t *testing.T) {
	canonical, shards, auth, longest := ParseDomainCSV("files.example.com")
	if canonical != "files.example.com" {
		t.Errorf("canonical=%q want files.example.com", canonical)
	}
	if len(shards) != 1 || shards[0] != "files.example.com" {
		t.Errorf("shards=%v want [files.example.com]", shards)
	}
	if len(auth) != 1 || auth[0] != "files.example.com" {
		t.Errorf("auth=%v want [files.example.com]", auth)
	}
	if longest != "files.example.com" {
		t.Errorf("longest=%q want files.example.com", longest)
	}
}

// TestParseDomainCSVMultiDomain verifies the canonical-first invariant
// and that every shard survives dedup / whitespace-normalisation.
func TestParseDomainCSVMultiDomain(t *testing.T) {
	canonical, shards, auth, longest := ParseDomainCSV(" a.com ,B.COM,c.com. ,a.com")

	if canonical != "a.com" {
		t.Errorf("canonical=%q want a.com (first CSV entry)", canonical)
	}
	// Dedup keeps first occurrence; case in shardDomains preserved,
	// AuthDomain-normalized copy lower-cased.
	wantShards := []string{"a.com", "B.COM", "c.com"}
	if !equalStrings(shards, wantShards) {
		t.Errorf("shards=%v want %v", shards, wantShards)
	}
	wantAuth := []string{"a.com", "b.com", "c.com"}
	if !equalStrings(auth, wantAuth) {
		t.Errorf("auth=%v want %v", auth, wantAuth)
	}
	// All three are 5 chars; longest picks the first-seen shard.
	if longest != "a.com" {
		t.Errorf("longest=%q want a.com (first among 5-char ties)", longest)
	}
}

// TestParseDomainCSVLongestActuallyLongest checks that the budget-
// driving `longest` return correctly picks the widest shard — a
// regression that returns canonical instead would let a client
// build QNAMEs against a shorter shard and overflow 253 chars when
// the rotator lands on the longer one.
func TestParseDomainCSVLongestActuallyLongest(t *testing.T) {
	_, _, _, longest := ParseDomainCSV("short.io,much-longer-shard.example.com,medium.com")
	if longest != "much-longer-shard.example.com" {
		t.Errorf("longest=%q want much-longer-shard.example.com", longest)
	}
}

// TestParseDomainCSVEmptyInput preserves the invariant callers rely on
// for the single-domain fast path — even on garbage input the returned
// slices are non-nil and length-1 so `len(shardAuthDomains) == 1`
// branches don't panic on nil deref.
func TestParseDomainCSVEmptyInput(t *testing.T) {
	for _, raw := range []string{"", " ", " , , ", ",,,"} {
		canonical, shards, auth, longest := ParseDomainCSV(raw)
		if canonical != "" {
			t.Errorf("raw=%q canonical=%q want empty", raw, canonical)
		}
		if len(shards) != 1 || shards[0] != "" {
			t.Errorf("raw=%q shards=%v want [\"\"]", raw, shards)
		}
		if len(auth) != 1 || auth[0] != "" {
			t.Errorf("raw=%q auth=%v want [\"\"]", raw, auth)
		}
		if longest != "" {
			t.Errorf("raw=%q longest=%q want empty", raw, longest)
		}
	}
}

// TestParseDomainCSVAuthDomainConsistency verifies AuthDomain output
// for every shard matches what a caller signing HMACs against that
// name would compute directly — critical because the server verifies
// HMAC against canonical only, so shardAuthDomains[0] must be the
// AuthDomain the client actually signs under.
func TestParseDomainCSVAuthDomainConsistency(t *testing.T) {
	canonical, _, auth, _ := ParseDomainCSV("Foo.Example.COM,bar.example.com")
	if auth[0] != AuthDomain(canonical) {
		t.Errorf("auth[0]=%q AuthDomain(canonical)=%q — mismatch would break server HMAC verify",
			auth[0], AuthDomain(canonical))
	}
	for i, d := range []string{"Foo.Example.COM", "bar.example.com"} {
		if auth[i] != AuthDomain(d) {
			t.Errorf("auth[%d]=%q AuthDomain(%q)=%q", i, auth[i], d, AuthDomain(d))
		}
	}
	// AuthDomain must lowercase — otherwise JoinNameFast produces
	// upper-case suffix segments and the resolver / server may fail
	// to match (canonical is already lowercased for comparison).
	for _, a := range auth {
		if a != strings.ToLower(a) {
			t.Errorf("auth entry %q not lowercased", a)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
