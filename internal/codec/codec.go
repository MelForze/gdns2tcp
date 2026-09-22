package codec

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"gdns2tcp/internal/dnshelpers"
)

const TXTChunkSize = 254

func DecodeDNSPayload(value, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "", "base64":
		padded := value + strings.Repeat("=", positiveMod(-len(value), 4))
		out, err := base64.StdEncoding.DecodeString(padded)
		if err != nil {
			return nil, fmt.Errorf("decode base64 payload: %w", err)
		}
		return out, nil
	case "base32":
		upper := strings.ToUpper(value)
		upper += strings.Repeat("=", (8-len(upper)%8)%8)
		out, err := base32.StdEncoding.DecodeString(upper)
		if err != nil {
			return nil, fmt.Errorf("decode base32 payload: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported payload encoding %q", encoding)
	}
}

func EncodeDNSPayload(data []byte, encoding string) (string, error) {
	switch strings.ToLower(encoding) {
	case "", "base64":
		return base64.StdEncoding.EncodeToString(data), nil
	case "base32":
		return base32.StdEncoding.EncodeToString(data), nil
	default:
		return "", fmt.Errorf("unsupported payload encoding %q", encoding)
	}
}

// ChunkString is a thin wrapper around dnshelpers.ChunkString kept for
// backwards compatibility with callers that already import this package
// for other codec helpers. New code should call dnshelpers directly.
func ChunkString(value string, size int) []string {
	return dnshelpers.ChunkString(value, size)
}

func Compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	// bytes.Buffer.Write never returns an error; the only fallible
	// operation is Close (flushes gzip trailer).
	zw.Write(data) //nolint:errcheck
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}
	return buf.Bytes(), nil
}

// DecompressLimit decompresses gzip data. If maxBytes > 0, returns an error if the
// decompressed size would exceed maxBytes, preventing gzip-bomb OOM attacks.
func DecompressLimit(data []byte, maxBytes int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer zr.Close()

	var buf bytes.Buffer
	reader := io.Reader(zr)
	if maxBytes > 0 {
		reader = io.LimitReader(zr, maxBytes+1)
	}
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("gzip copy: %w", err)
	}
	if maxBytes > 0 && int64(buf.Len()) > maxBytes {
		return nil, fmt.Errorf("decompressed data exceeds %d byte limit", maxBytes)
	}
	return buf.Bytes(), nil
}

// MaxEncodedSizeForSource returns a conservative upper bound on the
// base64-encoded output of the pipeline source → gzip → GDT2 AES-CBC
// container → base64 for an incompressible source of the given byte
// length. Use it instead of a fixed 2× multiplier when bounding encoded
// wire size from a source/decompressed size limit.
func MaxEncodedSizeForSource(sourceSize int64) int64 {
	if sourceSize < 0 {
		return 0
	}
	// Worst-case gzip for incompressible data: stored deflate blocks.
	//   header(10) + one block header(5) + raw data(N) + trailer(8) = N+23
	//   Each additional 65535-byte block adds a 5-byte header.
	gzipOverhead := int64(23)
	if sourceSize > 65535 {
		gzipOverhead += (sourceSize / 65535) * 5
	}
	compressed := sourceSize + gzipOverhead
	if compressed < sourceSize {
		return 1<<63 - 1
	}

	// GDT2 container: magic(4) + salt(16) + iv(16) + mac(32) = 68-byte
	// header, then PKCS7 padding adds 1–16 bytes.
	const cryptoOverhead = 84 // 68 header + 16 max padding
	encrypted := compressed + cryptoOverhead
	if encrypted < compressed {
		return 1<<63 - 1
	}

	// Standard base64: ceil(n/3)*4
	encoded := ((encrypted + 2) / 3) * 4
	if encoded < encrypted {
		return 1<<63 - 1
	}
	return encoded
}

func positiveMod(d, m int) int {
	res := d % m
	if res != 0 && (res < 0) != (m < 0) {
		return res + m
	}
	return res
}
