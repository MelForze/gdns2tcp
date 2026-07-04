package dnshelpers

import "encoding/base32"

// B32LowerNoPad is a base32 encoding using the RFC 4648 alphabet in
// **lowercase**, with padding disabled. It's the encoding the whole
// project uses for DNS-label-safe binary blobs: DNS is
// case-insensitive on the wire but many stubs / caches lowercase
// labels, so we produce lowercase directly and skip a strings.ToLower
// copy on every encode call.
//
// A matching case-insensitive decoder is available as B32DecodeAny —
// it accepts either case by upper-folding into a small stack buffer.
var B32LowerNoPad = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// stdB32NoPad is the uppercase RFC 4648 alphabet with no padding —
// what stdlib base32.StdEncoding.WithPadding(NoPadding) produces.
// Kept package-local so B32DecodeAny can consult it without callers
// having to think about the alphabet.
var stdB32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// B32DecodeAny decodes a base32 string whose letters may be any mix of
// upper and lower case. Some DNS resolvers randomize case per-character
// (RFC 5452 0x20 anti-spoofing, e.g. Cloudflare 1.1.1.1) and some caches
// upcase whole labels; either way we can't trust that every rune matches
// the encoder's original case.
//
// Single-case (or digits-only) input decodes without an allocation.
// Mixed case is folded to lowercase once and then decoded.
func B32DecodeAny(s string) ([]byte, error) {
	seenLower, seenUpper := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			seenLower = true
		} else if c >= 'A' && c <= 'Z' {
			seenUpper = true
		}
		if seenLower && seenUpper {
			break
		}
	}
	switch {
	case seenUpper && !seenLower:
		return stdB32NoPad.DecodeString(s)
	case !seenUpper:
		// pure lowercase, or digits-only, or empty
		return B32LowerNoPad.DecodeString(s)
	}
	// Mixed case: fold to lowercase once and decode. Only path that
	// allocates a copy; hit only when a middlebox randomized case.
	buf := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	return B32LowerNoPad.DecodeString(string(buf))
}
