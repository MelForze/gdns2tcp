package dnshelpers

import "testing"

// FuzzB32DecodeAny exercises the case-detecting base32 decoder used on
// every reverse-SOCKS5 awrite chunk. A hostile / broken agent could
// otherwise crash the server with a specially crafted label containing
// mixed case or high-bit bytes.
func FuzzB32DecodeAny(f *testing.F) {
	f.Add("abc23")            // lowercase branch
	f.Add("ABC23")            // uppercase branch
	f.Add("234567")           // digits-only branch
	f.Add("")                 // empty
	f.Add("abcABC")           // mixed — hits lowercase branch on first char
	f.Add("!@#$")             // non-base32 garbage
	f.Add("abcdefghijklmnop") // long, all lowercase

	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("B32DecodeAny panicked on %q: %v", s, r)
			}
		}()
		_, _ = B32DecodeAny(s)
	})
}
