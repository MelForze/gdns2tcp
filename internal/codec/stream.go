package codec

import (
	"bufio"
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

// EncodeDNSFile writes the unpadded DNS payload representation of src to dst
// without retaining the file in memory.  Base32 output is lowercased to keep
// QNAME construction compatible with resolvers that fold label case.
func EncodeDNSFile(src, dst, encoding string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	failed := true
	defer func() {
		_ = out.Close()
		if failed {
			_ = os.Remove(dst)
		}
	}()

	var encoder io.WriteCloser
	switch strings.ToLower(encoding) {
	case "", "base64":
		// Keep standard padding for download/artifact compatibility.  Upload
		// QNAME construction removes it later; DecodeDNSFile accepts both.
		encoder = base64.NewEncoder(base64.StdEncoding, out)
	case "base32":
		encoder = base32.NewEncoder(base32.StdEncoding.WithPadding(base32.NoPadding), &lowerWriter{w: out})
	default:
		return 0, fmt.Errorf("unsupported payload encoding %q", encoding)
	}
	if _, err := io.CopyBuffer(encoder, in, make([]byte, 64*1024)); err != nil {
		_ = encoder.Close()
		return 0, err
	}
	if err := encoder.Close(); err != nil {
		return 0, err
	}
	if err := out.Close(); err != nil {
		return 0, err
	}
	info, err := os.Stat(dst)
	if err != nil {
		return 0, err
	}
	failed = false
	return info.Size(), nil
}

// DecodeDNSFile reverses EncodeDNSFile using streaming decoders.  The input
// may be unpadded (as transmitted in DNS labels), and base64 may use the URL
// safe substitutions accepted by DecodeDNSPayload.
func DecodeDNSFile(src, dst, encoding string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	failed := true
	defer func() {
		_ = out.Close()
		if failed {
			_ = os.Remove(dst)
		}
	}()

	reader := io.Reader(bufio.NewReaderSize(in, 64*1024))
	switch strings.ToLower(encoding) {
	case "", "base64":
		reader = base64.NewDecoder(base64.RawStdEncoding, base64DNSReader{r: reader})
	case "base32":
		reader = base32.NewDecoder(base32.StdEncoding.WithPadding(base32.NoPadding), upperReader{r: reader})
	default:
		return 0, fmt.Errorf("unsupported payload encoding %q", encoding)
	}
	n, err := io.CopyBuffer(out, reader, make([]byte, 64*1024))
	if err != nil {
		return 0, err
	}
	if err := out.Close(); err != nil {
		return 0, err
	}
	failed = false
	return n, nil
}

// CompressFile is gzip.Compress for files.  It is intentionally separate
// from Compress so callers that still need a []byte keep their old API.
func CompressFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	failed := true
	defer func() {
		_ = out.Close()
		if failed {
			_ = os.Remove(dst)
		}
	}()
	zw := gzip.NewWriter(out)
	if _, err := io.CopyBuffer(zw, in, make([]byte, 64*1024)); err != nil {
		_ = zw.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	failed = false
	return nil
}

// DecompressFileLimit expands a gzip file into dst while enforcing the
// decompressed byte limit before a large allocation can occur.
func DecompressFileLimit(src, dst string, maxBytes int64) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	zr, err := gzip.NewReader(in)
	if err != nil {
		return 0, fmt.Errorf("gzip reader: %w", err)
	}
	defer zr.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	failed := true
	defer func() {
		_ = out.Close()
		if failed {
			_ = os.Remove(dst)
		}
	}()
	lw := &limitWriter{w: out, remain: maxBytes}
	n, err := io.CopyBuffer(lw, zr, make([]byte, 64*1024))
	if err != nil {
		return 0, err
	}
	if err := out.Close(); err != nil {
		return 0, err
	}
	failed = false
	return n, nil
}

// lowerWriter is an io.Writer that lowercases A–Z as it writes.  It owns
// a scratch buffer so the caller's slice is never mutated — the strict
// io.Writer contract says "implementations must not modify the slice
// data, even temporarily", and the earlier in-place variant happened to
// work only because base32.NewEncoder does not re-read its output
// buffer.  Any future encoder swap would silently corrupt.
type lowerWriter struct {
	w   io.Writer
	buf []byte
}

func (w *lowerWriter) Write(p []byte) (int, error) {
	if cap(w.buf) < len(p) {
		w.buf = make([]byte, len(p))
	} else {
		w.buf = w.buf[:len(p)]
	}
	for i, b := range p {
		if b >= 'A' && b <= 'Z' {
			w.buf[i] = b + ('a' - 'A')
		} else {
			w.buf[i] = b
		}
	}
	n, err := w.w.Write(w.buf)
	if n > len(p) {
		n = len(p)
	}
	return n, err
}

// upperReader is an io.Reader that uppercases a–z as it reads.  Reader
// contract is looser than Writer's (io.Reader doesn't forbid mutating
// the passed-in buffer during Read), so we keep the in-place transform
// here — the buffer is the caller's read target and by definition
// receives whatever bytes we produce.
type upperReader struct{ r io.Reader }

func (r upperReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	for i := 0; i < n; i++ {
		if p[i] >= 'a' && p[i] <= 'z' {
			p[i] -= 'a' - 'A'
		}
	}
	return n, err
}

// base64DNSReader normalises DNS-safe base64 (`_`→`+`, `-`→`/`) and drops
// padding/whitespace on the way to base64.NewDecoder.  Reads write into
// the caller's buffer, so in-place compaction is fine — the resulting
// slice is exactly the returned length and never re-read from beyond
// that point.
type base64DNSReader struct{ r io.Reader }

func (r base64DNSReader) Read(p []byte) (int, error) {
	for {
		n, err := r.r.Read(p)
		out := 0
		for i := 0; i < n; i++ {
			switch p[i] {
			case '_':
				p[out] = '+'
				out++
			case '-':
				p[out] = '/'
				out++
			case '=', ' ', '\n', '\r', '\t':
				// RawStdEncoding accepts an unpadded stream.  Drop padding and
				// incidental presentation whitespace so either wire form works.
			default:
				p[out] = p[i]
				out++
			}
		}
		if out > 0 || err != nil {
			return out, err
		}
	}
}

type limitWriter struct {
	w      io.Writer
	remain int64
}

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.remain >= 0 && int64(len(p)) > w.remain {
		return 0, fmt.Errorf("decompressed data exceeds configured byte limit")
	}
	n, err := w.w.Write(p)
	w.remain -= int64(n)
	return n, err
}
