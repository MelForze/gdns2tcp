package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
)

const (
	magic           = "GDT2"
	saltSize        = 16
	ivSize          = aes.BlockSize
	macSize         = sha256.Size
	keySize         = 32
	keyMaterialSize = keySize * 2
	iterations      = 100_000
)

func ProtectToBase64(secret string, plaintext []byte) (string, error) {
	protected, err := Protect(secret, plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(protected), nil
}

func Protect(secret string, plaintext []byte) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("secret is empty")
	}

	salt := make([]byte, saltSize)
	iv := make([]byte, ivSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generate iv: %w", err)
	}

	encKey, macKey := deriveKeys(secret, salt)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	out := make([]byte, 0, len(magic)+saltSize+ivSize+macSize+len(ciphertext))
	out = append(out, []byte(magic)...)
	out = append(out, salt...)
	out = append(out, iv...)
	mac := protectMAC(macKey, out, ciphertext)
	out = append(out, mac...)
	out = append(out, ciphertext...)
	return out, nil
}

func OpenBase64(secret, encoded string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode protected data: %w", err)
	}
	return Open(secret, raw)
}

func Open(secret string, protected []byte) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("secret is empty")
	}
	minLen := len(magic) + saltSize + ivSize + macSize + aes.BlockSize
	if len(protected) < minLen || string(protected[:len(magic)]) != magic {
		return nil, fmt.Errorf("invalid protected data format")
	}

	offset := len(magic)
	salt := protected[offset : offset+saltSize]
	offset += saltSize
	iv := protected[offset : offset+ivSize]
	offset += ivSize
	expectedMAC := protected[offset : offset+macSize]
	offset += macSize
	ciphertext := protected[offset:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid protected data block size")
	}

	encKey, macKey := deriveKeys(secret, salt)
	actualMAC := protectMAC(macKey, protected[:len(magic)+saltSize+ivSize], ciphertext)
	if subtle.ConstantTimeCompare(expectedMAC, actualMAC) != 1 {
		return nil, fmt.Errorf("authenticate protected data")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func deriveKeys(secret string, salt []byte) ([]byte, []byte) {
	keyMaterial := pbkdf2Key([]byte(secret), salt, iterations, keyMaterialSize, sha256.New)
	return keyMaterial[:keySize], keyMaterial[keySize:]
}

// pbkdf2Key is an inline RFC 2898 PBKDF2 implementation (replaces the
// dependency on golang.org/x/crypto/pbkdf2 for a smaller binary).
func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	t := make([]byte, hashLen)
	var idx [4]byte
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(idx[:], uint32(block))
		prf.Write(idx[:])
		u = prf.Sum(u[:0])
		copy(t, u)
		for i := 2; i <= iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func protectMAC(macKey, header, ciphertext []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(header)
	mac.Write(ciphertext)
	return mac.Sum(nil)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+padding)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(padding)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("invalid PKCS7 data length")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize || padding > len(data) {
		return nil, fmt.Errorf("invalid PKCS7 padding")
	}
	for _, value := range data[len(data)-padding:] {
		if int(value) != padding {
			return nil, fmt.Errorf("invalid PKCS7 padding")
		}
	}
	return data[:len(data)-padding], nil
}
