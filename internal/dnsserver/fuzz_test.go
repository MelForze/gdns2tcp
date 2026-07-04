package dnsserver

import "testing"

// FuzzParseCommand exercises the server-side name-decomposer that turns
// an inbound DNS query name into (args, command). A panic here would
// crash the DNS server on any hostile / malformed query — a trivial
// remote DoS. The fuzzer generates arbitrary (name, domain) pairs;
// the function must always return without panicking, whatever the
// input.
func FuzzParseCommand(f *testing.F) {
	// Seed with realistic shapes the parser actually meets in prod.
	f.Add("abc.deadbeef.axchg.files.example.com.", "files.example.com")
	f.Add("EnCoDiNg.test.files.example.com.", "files.example.com")
	f.Add("files.example.com.", "files.example.com")
	f.Add("", "files.example.com")
	f.Add(".", "files.example.com")
	f.Add("bad.mismatched.domain.other.tld.", "files.example.com")
	f.Add("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.files.example.com.", "files.example.com")

	f.Fuzz(func(t *testing.T, name, domain string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseCommand panicked on name=%q domain=%q: %v", name, domain, r)
			}
		}()
		_, _, _ = parseCommand(name, domain)
	})
}

// FuzzSplitAuthenticatedArgs exercises the trailer-splitter that
// separates payload args from the (timestamp, token) HMAC trailer on
// file-command requests. The fuzzer generates a raw '.'-joined string
// which is then Split back into args — this mirrors how the real code
// gets its args (via parseCommand's strings.Split of the query name).
func FuzzSplitAuthenticatedArgs(f *testing.F) {
	f.Add("sid.1.chunk.1700000000.aabbccdd")
	f.Add("1700000000.aabbccdd") // minimum shape
	f.Add("onlyone")             // too few
	f.Add("")                    // empty
	f.Add(".")                   // empty parts

	f.Fuzz(func(t *testing.T, joined string) {
		args := splitOnDots(joined)
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("splitAuthenticatedArgs panicked on args=%q: %v", args, r)
			}
		}()
		_, _, _, _ = splitAuthenticatedArgs(args)
	})
}

func splitOnDots(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{""}
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, "")
		} else {
			out[len(out)-1] += string(s[i])
		}
	}
	return out
}
