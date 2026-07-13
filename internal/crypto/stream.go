package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ProtectFile is the streaming counterpart to Protect.  It intentionally
// retains the established GDT2 wire container so existing PowerShell and Go
// clients remain interoperable, while moving compression/encryption payloads
// out of RAM.  GDT2 places the MAC before ciphertext, therefore ciphertext is
// spooled briefly to disk before the final container is assembled.
func ProtectFile(secret, src, dst string) error {
	if secret == "" {
		return fmt.Errorf("secret is empty")
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	salt := make([]byte, saltSize)
	iv := make([]byte, ivSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("generate iv: %w", err)
	}
	encKey, macKey := deriveKeys(secret, salt)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	cipherTmp, err := os.CreateTemp(filepath.Dir(dst), ".gdns2tcp-cipher-*")
	if err != nil {
		return err
	}
	cipherTmpName := cipherTmp.Name()
	defer os.Remove(cipherTmpName)
	defer cipherTmp.Close()

	header := make([]byte, 0, len(magic)+saltSize+ivSize)
	header = append(header, magic...)
	header = append(header, salt...)
	header = append(header, iv...)
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(header)
	encrypter := cipher.NewCBCEncrypter(block, iv)
	pending := make([]byte, 0, 64*1024+aes.BlockSize)
	buf := make([]byte, 64*1024)
	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
			full := len(pending) / aes.BlockSize * aes.BlockSize
			if full > 0 {
				chunk := pending[:full]
				encrypter.CryptBlocks(chunk, chunk)
				if err := writeAll(cipherTmp, chunk); err != nil {
					return err
				}
				_, _ = mac.Write(chunk)
				pending = append(pending[:0], pending[full:]...)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	padding := aes.BlockSize - len(pending)%aes.BlockSize
	pending = append(pending, make([]byte, padding)...)
	for i := len(pending) - padding; i < len(pending); i++ {
		pending[i] = byte(padding)
	}
	encrypter.CryptBlocks(pending, pending)
	if err := writeAll(cipherTmp, pending); err != nil {
		return err
	}
	_, _ = mac.Write(pending)
	if err := cipherTmp.Close(); err != nil {
		return err
	}

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
	if err := writeAll(out, header); err != nil {
		return err
	}
	if err := writeAll(out, mac.Sum(nil)); err != nil {
		return err
	}
	cipherIn, err := os.Open(cipherTmpName)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyBuffer(out, cipherIn, make([]byte, 64*1024))
	closeErr := cipherIn.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := out.Close(); err != nil {
		return err
	}
	failed = false
	return nil
}

// OpenFile authenticates a GDT2 file before decrypting it to dst.  It makes a
// verification pass over ciphertext first, preventing a corrupt spool from
// producing any output file.
func OpenFile(secret, src, dst string) error {
	if secret == "" {
		return fmt.Errorf("secret is empty")
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	const headerLen = len(magic) + saltSize + ivSize
	const cipherOffset = headerLen + macSize
	if info.Size() < int64(cipherOffset+aes.BlockSize) || (info.Size()-int64(cipherOffset))%int64(aes.BlockSize) != 0 {
		return fmt.Errorf("invalid protected data block size")
	}
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(in, header); err != nil {
		return err
	}
	if string(header[:len(magic)]) != magic {
		return fmt.Errorf("invalid protected data format")
	}
	expectedMAC := make([]byte, macSize)
	if _, err := io.ReadFull(in, expectedMAC); err != nil {
		return err
	}
	salt := header[len(magic) : len(magic)+saltSize]
	iv := header[len(magic)+saltSize:]
	encKey, macKey := deriveKeys(secret, salt)
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(header)
	if _, err := io.CopyBuffer(mac, in, make([]byte, 64*1024)); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expectedMAC, mac.Sum(nil)) != 1 {
		return fmt.Errorf("authenticate protected data")
	}
	if _, err := in.Seek(int64(cipherOffset), io.SeekStart); err != nil {
		return err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	decrypter := cipher.NewCBCDecrypter(block, iv)
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

	// The ciphertext length is authenticated and known up front, so decrypt
	// aligned 64 KiB blocks and reserve only the final AES block for PKCS#7.
	// Reading/writing one 16-byte block at a time turns a 256 MiB transfer into
	// more than sixteen million syscalls and allocations.
	remaining := info.Size() - int64(cipherOffset)
	buf := make([]byte, 64*1024)
	var finalBlock []byte
	for remaining > 0 {
		want := int64(len(buf))
		if remaining < want {
			want = remaining
		}
		chunk := buf[:int(want)]
		if _, err := io.ReadFull(in, chunk); err != nil {
			return err
		}
		decrypter.CryptBlocks(chunk, chunk)
		remaining -= want
		if remaining == 0 {
			bodyEnd := len(chunk) - aes.BlockSize
			if bodyEnd > 0 {
				if err := writeAll(out, chunk[:bodyEnd]); err != nil {
					return err
				}
			}
			finalBlock = chunk[bodyEnd:]
			break
		}
		if err := writeAll(out, chunk); err != nil {
			return err
		}
	}
	if len(finalBlock) != aes.BlockSize {
		return fmt.Errorf("invalid protected data block size")
	}
	plainLast, err := pkcs7Unpad(finalBlock, aes.BlockSize)
	if err != nil {
		return err
	}
	if err := writeAll(out, plainLast); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	failed = false
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
