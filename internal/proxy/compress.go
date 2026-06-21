package proxy

import (
	"errors"
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Compressor wraps a klauspost zstd encoder + decoder and exposes a
// length-prefixed Encode/Decode pair that picks pass-through when the
// compressed form would not actually save bytes (typical for already-encoded
// payloads like JPEG, ZIP, or AEAD ciphertext).
//
// Wire byte layout per chunk:
//
//	0x00 + raw   — zstd would not shrink it, sent as-is
//	0x01 + zstd  — zstd-encoded, decoder restores the plaintext
//
// The 1-byte prefix is included inside the AEAD plaintext so the integrity
// tag covers the flag bit too: tampering with the flag breaks the seal.
type Compressor struct {
	enc *zstd.Encoder
	dec *zstd.Decoder
}

var (
	sharedCompressor    *Compressor
	sharedCompressorErr error
	sharedCompressorMu  sync.Mutex
)

// GetCompressor returns a process-wide shared Compressor. Both the
// klauspost encoder and decoder are safe for concurrent use, so a single
// instance services every cid without per-tunnel allocations.
func GetCompressor() (*Compressor, error) {
	sharedCompressorMu.Lock()
	defer sharedCompressorMu.Unlock()
	if sharedCompressor != nil || sharedCompressorErr != nil {
		return sharedCompressor, sharedCompressorErr
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		sharedCompressorErr = err
		return nil, err
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		_ = enc.Close()
		sharedCompressorErr = err
		return nil, err
	}
	sharedCompressor = &Compressor{enc: enc, dec: dec}
	return sharedCompressor, nil
}

// Encode returns src wrapped with a single-byte flag indicating whether
// the body is raw or zstd-compressed. The pass-through branch fires when
// zstd's frame overhead would make the payload bigger — which happens on
// small or already-incompressible inputs.
func (c *Compressor) Encode(src []byte) []byte {
	encoded := c.enc.EncodeAll(src, nil)
	if len(encoded) < len(src) {
		out := make([]byte, 1+len(encoded))
		out[0] = 0x01
		copy(out[1:], encoded)
		return out
	}
	out := make([]byte, 1+len(src))
	out[0] = 0x00
	copy(out[1:], src)
	return out
}

// Decode is Encode's inverse. An empty input or an unrecognized flag byte
// is treated as a protocol error so the caller can reset the tunnel rather
// than feed garbage to upstream.
func (c *Compressor) Decode(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, errors.New("empty compressed payload")
	}
	switch src[0] {
	case 0x00:
		out := make([]byte, len(src)-1)
		copy(out, src[1:])
		return out, nil
	case 0x01:
		return c.dec.DecodeAll(src[1:], nil)
	default:
		return nil, fmt.Errorf("unknown compression flag %#x", src[0])
	}
}
