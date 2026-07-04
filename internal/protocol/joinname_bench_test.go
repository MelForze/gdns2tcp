package protocol

import "testing"

// TestJoinNameFastMatchesJoinName pins the invariant that the fast-path
// helper produces bit-identical output to the historical slow path. A
// regression here would silently corrupt every DNS query.
func TestJoinNameFastMatchesJoinName(t *testing.T) {
	cases := []struct {
		domain, command string
		args            []string
	}{
		{"files.example.com", "axchg", []string{"deadbeef", "1"}},
		{"FILES.EXAMPLE.COM.", "AXCHG", []string{"cid", "seq", "chunk1", "chunk2"}},
		{"a.b.c", "d", nil},
	}
	for _, tc := range cases {
		want := JoinName(tc.domain, tc.command, tc.args)
		got := JoinNameFast(AuthDomain(tc.domain), toLower(tc.command), tc.args)
		if got != want {
			t.Fatalf("mismatch: got %q want %q (domain=%q cmd=%q args=%v)", got, want, tc.domain, tc.command, tc.args)
		}
	}
}

func toLower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// BenchmarkJoinName vs BenchmarkJoinNameFast — the "Fast" path skips
// strings.ToLower(command) + AuthDomain(domain) on every call. A
// regression that removes the pre-normalization would show up as
// higher allocs/op in the "Fast" bench.
func BenchmarkJoinName(b *testing.B) {
	args := []string{"deadbeefdeadbeef", "1", "chunkAAA", "chunkBBB"}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = JoinName("files.example.com", "axchg", args)
	}
}

func BenchmarkJoinNameFast(b *testing.B) {
	args := []string{"deadbeefdeadbeef", "1", "chunkAAA", "chunkBBB"}
	authDomain := AuthDomain("files.example.com")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = JoinNameFast(authDomain, "axchg", args)
	}
}
