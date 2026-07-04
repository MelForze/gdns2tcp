package main

import (
	"encoding/binary"
	"testing"
)

// FuzzParseTXTSegments feeds arbitrary bytes into the agent's DNS-over-
// wire response parser. The parser must never panic — every malformed
// input must surface as an error return. Panics found by the fuzzer
// would be latent DoS bugs (a hostile / broken authoritative could
// crash every agent in the field with a single response).
//
// Seed corpus: a well-formed empty-answer response plus a couple of
// malformed shapes that historically triggered edge cases (truncated
// TXT character-string, oversized rdlen, invalid label-length byte).
func FuzzParseTXTSegments(f *testing.F) {
	// Well-formed: header only, ID=1234, ancount=0.
	good := make([]byte, 12)
	binary.BigEndian.PutUint16(good[0:2], 1234)
	good[2] = 0x80 // QR=1
	f.Add(good, uint16(1234))

	// TXT response with a "Hello" segment.
	txt := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(txt[6:8], 1)         // ANCOUNT=1
	txt = append(txt, 0)                            // name=root
	txt = append(txt, 0, 16, 0, 1, 0, 0, 0, 0)      // type=TXT, class=IN, TTL=0
	txt = append(txt, 0, 6)                         // RDLEN=6
	txt = append(txt, 5, 'H', 'e', 'l', 'l', 'o')   // "Hello"
	f.Add(txt, uint16(1234))

	// Malformed: character-string length exceeds RDATA.
	bad := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(bad[6:8], 1)
	bad = append(bad, 0)                          // name
	bad = append(bad, 0, 16, 0, 1, 0, 0, 0, 0)    // TXT header
	bad = append(bad, 0, 3)                       // RDLEN=3
	bad = append(bad, 10, 'x', 'x')               // len=10 but only 2 bytes present
	f.Add(bad, uint16(1234))

	// Pointer-form name (RFC 1035 §4.1.4) at offset 12.
	ptr := make([]byte, 12)
	binary.BigEndian.PutUint16(ptr[0:2], 1)
	ptr[2] = 0x80
	binary.BigEndian.PutUint16(ptr[6:8], 1)
	ptr = append(ptr, 0xC0, 0x0C) // pointer back to offset 12
	ptr = append(ptr, 0, 16, 0, 1, 0, 0, 0, 0, 0, 1, 0)
	f.Add(ptr, uint16(1))

	f.Fuzz(func(t *testing.T, resp []byte, id uint16) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseTXTSegments panicked on resp=%x id=%d: %v", resp, id, r)
			}
		}()
		// Return values ignored — we only care that we don't panic.
		_, _ = parseTXTSegments(resp, id)
	})
}

// FuzzSkipDNSName targets the label-walker used by both the query and
// response parsers. A regression here would let a hostile response
// crash the agent via runtime bounds-check panic, unterminated loop,
// or infinite pointer chase.
func FuzzSkipDNSName(f *testing.F) {
	f.Add([]byte{0}, 0)                                     // root
	f.Add([]byte{3, 'a', 'b', 'c', 0}, 0)                   // "abc."
	f.Add([]byte{0xC0, 0x0C}, 0)                            // pointer
	f.Add([]byte{0xC0}, 0)                                  // truncated pointer
	f.Add([]byte{0x80, 0}, 0)                               // invalid label-length top bits
	f.Add([]byte{5, 'a', 'b'}, 0)                           // truncated label
	f.Add([]byte{1, 'x', 1, 'y', 1, 'z', 1, 'w', 0}, 0)     // x.y.z.w.

	f.Fuzz(func(t *testing.T, buf []byte, pos int) {
		if pos < 0 || pos > 1<<20 {
			return // filter unreasonable seeds
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("skipDNSName panicked on buf=%x pos=%d: %v", buf, pos, r)
			}
		}()
		_, _ = skipDNSName(buf, pos)
	})
}
