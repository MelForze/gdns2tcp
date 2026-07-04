package dnsserver

import (
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"gdns2tcp/internal/protocol"
)

// TestMultiDomainServerAcceptsShardSuffix verifies the end-to-end
// invariant behind CSV-domain sharding: a QNAME whose suffix is any of
// the configured shard domains must reach the same handler as one
// under the canonical suffix, and its HMAC — signed against canonical
// — must still validate. Without this, adding shards to -domain would
// silently break every authenticated command on the shard path.
func TestMultiDomainServerAcceptsShardSuffix(t *testing.T) {
	canonical := "canon.test"
	shards := []string{canonical, "s1.test", "s2.test"}

	s, err := New(Config{
		Domain:           strings.Join(shards, ","),
		Secret:           testSecret,
		DataDir:          t.TempDir(),
		AllowList:        true,
		MaxUploadBytes:   DefaultMaxUploadBytes,
		MaxDownloadBytes: DefaultMaxDownloadBytes,
		Logger:           log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A "catalog" (c) query with an empty listing is a good probe: it
	// exercises the full auth pipeline (VerifyAuth against s.authDomain)
	// and returns the same short "" answer regardless of shard. If auth
	// fails we get the authFailedResponse constant; if the suffix is
	// rejected we get the "Invalid gdns2tcp request." fallback.
	for _, shard := range shards {
		t.Run(shard, func(t *testing.T) {
			ts := protocol.CurrentTimestamp(time.Now().UTC())
			// HMAC is *always* signed under canonical — the server verifies
			// against s.authDomain, which is derived from the first CSV
			// entry. Signing under the shard would fail auth (and would
			// mean clients must know which shard they routed to at sign
			// time, defeating the whole rotate-any-shard design).
			token := protocol.AuthToken(testSecret, canonical, "c", ts, nil)
			labels := []string{ts, token}
			name := protocol.JoinName(shard, "c", labels)

			resp := s.handleTXT(name, "127.0.0.1")
			if len(resp) != 1 {
				t.Fatalf("shard %s: expected 1-segment reply, got %v", shard, resp)
			}
			if resp[0] == authFailedResponse {
				t.Fatalf("shard %s: auth failed — canonical-signed HMAC not accepted on shard suffix", shard)
			}
			if strings.Contains(resp[0], "Invalid gdns2tcp") {
				t.Fatalf("shard %s: suffix rejected by parseCommand — hasAnyDomainSuffix should have picked it up", shard)
			}
			// Empty catalog for a fresh data dir — the concrete happy-path
			// reply. If somebody flips DataDir defaults, this expectation
			// changes, but the auth/suffix mechanics are what we're pinning.
			if resp[0] != "" {
				t.Fatalf("shard %s: unexpected reply %q", shard, resp[0])
			}
		})
	}
}

// TestMultiDomainServerRejectsForeignSuffix guards the negative side:
// a shard-suffix that *isn't* in -domain (a typo or a hostile probe)
// must still get "Invalid gdns2tcp request." — otherwise adding one
// shard would accidentally widen the accept-set to sibling zones.
func TestMultiDomainServerRejectsForeignSuffix(t *testing.T) {
	s, err := New(Config{
		Domain:           "canon.test,s1.test",
		Secret:           testSecret,
		DataDir:          t.TempDir(),
		AllowList:        true,
		MaxUploadBytes:   DefaultMaxUploadBytes,
		MaxDownloadBytes: DefaultMaxDownloadBytes,
		Logger:           log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.handleTXT("something.evil.test.", "127.0.0.1"); len(got) != 1 || got[0] != "Invalid gdns2tcp request." {
		t.Fatalf("foreign suffix should be rejected; got %v", got)
	}
}

// TestParseCommandCaseInsensitiveSuffix pins the fix for the RFC 5452
// 0x20 anti-spoofing scenario: a resolver may deliver the QNAME with
// mixed / all-upper case. hasAnyDomainSuffix already lowercases before
// matching, but parseCommand used to do a case-sensitive TrimSuffix
// against the lowercase-normalized domain — mixed-case would leave the
// suffix un-stripped and the args parsed into garbage.
func TestParseCommandCaseInsensitiveSuffix(t *testing.T) {
	cases := []struct {
		name         string
		qname        string
		wantCmd      string
		wantLastArg  string
	}{
		{"lowercase", "sid.1.d.example.test.", "d", "1"},
		{"upper-suffix", "sid.1.d.EXAMPLE.TEST.", "d", "1"},
		{"mixed-suffix", "sid.1.d.ExAmPlE.tEsT.", "d", "1"},
		{"mixed-cmd", "sid.1.D.example.test.", "d", "1"},
		{"all-upper", "SID.1.D.EXAMPLE.TEST.", "d", "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, cmd, ok := parseCommand(tc.qname, "example.test.")
			if !ok {
				t.Fatalf("parseCommand rejected %q", tc.qname)
			}
			if cmd != tc.wantCmd {
				t.Errorf("cmd=%q want %q", cmd, tc.wantCmd)
			}
			if len(args) == 0 || args[len(args)-1] != tc.wantLastArg {
				t.Errorf("last arg=%v want %q", args, tc.wantLastArg)
			}
		})
	}
}

// TestAuthTokenSurvivesCaseMangling verifies that a HMAC computed on
// lowercase args still verifies when the wire delivers them upper-cased.
// This is the invariant that makes gdns2tcp work through Cloudflare's
// 0x20 anti-spoofing resolver.
func TestAuthTokenSurvivesCaseMangling(t *testing.T) {
	const secret = "s"
	const domain = "example.test"
	const cmd = "d"
	ts := protocol.CurrentTimestamp(time.Now().UTC())
	lowerArgs := []string{"sid12345", "42"}
	upperArgs := []string{"SID12345", "42"}
	tokLower := protocol.AuthToken(secret, domain, cmd, ts, lowerArgs)
	tokUpper := protocol.AuthToken(secret, domain, cmd, ts, upperArgs)
	if tokLower != tokUpper {
		t.Fatalf("AuthToken depends on arg case: lower=%q upper=%q", tokLower, tokUpper)
	}
	if !protocol.VerifyAuth(secret, domain, cmd, upperArgs, ts, tokLower, time.Now().UTC()) {
		t.Fatal("VerifyAuth rejects lowercase-signed MAC against upper-cased args (would break 0x20-mangled queries)")
	}
}

// TestMultiDomainServerDomainsAccessor pins the wire contract Domains()
// exposes so gdns2tcp/main.go can log the shard list.
func TestMultiDomainServerDomainsAccessor(t *testing.T) {
	s, err := New(Config{
		Domain:           "canon.test,s1.test,S2.TEST",
		Secret:           testSecret,
		DataDir:          t.TempDir(),
		AllowList:        true,
		MaxUploadBytes:   DefaultMaxUploadBytes,
		MaxDownloadBytes: DefaultMaxDownloadBytes,
		Logger:           log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	all := s.Domains()
	// normalizeDomain lowercases + trailing-dots.
	want := []string{"canon.test.", "s1.test.", "s2.test."}
	if len(all) != len(want) {
		t.Fatalf("Domains()=%v want %v", all, want)
	}
	for i, w := range want {
		if all[i] != w {
			t.Errorf("Domains()[%d]=%q want %q", i, all[i], w)
		}
	}
	if s.Domain() != want[0] {
		t.Errorf("Domain()=%q want canonical %q", s.Domain(), want[0])
	}
}
