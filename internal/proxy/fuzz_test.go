package proxy

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzSealOpenRoundTrip проверяет roundtrip шифрования/дешифрования чанков.
func FuzzSealOpenRoundTrip(f *testing.F) {
	f.Add([]byte{}, uint64(0))
	f.Add([]byte("hello"), uint64(1))
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF}, uint64(42))

	f.Fuzz(func(t *testing.T, plaintext []byte, seq uint64) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("SealChunk/OpenChunk паника: %v", r)
			}
		}()

		aead, err := SessionAEAD("testsecret", "abcdef0123456789")
		if err != nil {
			t.Fatalf("SessionAEAD ошибка: %v", err)
		}

		ciphertext := SealChunk(aead, DirClientToServer, seq, plaintext)
		decrypted, err := OpenChunk(aead, DirClientToServer, seq, ciphertext)
		if err != nil {
			t.Fatalf("OpenChunk ошибка: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("roundtrip не совпал: вход длина=%d, результат длина=%d", len(plaintext), len(decrypted))
		}
	})
}

// FuzzOpenChunkMalformed проверяет, что OpenChunk не паникует на повреждённых данных.
func FuzzOpenChunkMalformed(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA})
	f.Add([]byte("randomgarbage"))

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("OpenChunk паника: %v", r)
			}
		}()

		aead, err := SessionAEAD("testsecret", "abcdef0123456789")
		if err != nil {
			t.Fatalf("SessionAEAD ошибка: %v", err)
		}

		// Не должно паниковать; для мусорных данных ожидается ошибка.
		_, _ = OpenChunk(aead, DirClientToServer, 0, ciphertext)
	})
}

// FuzzValidCID проверяет, что ValidCID не паникует и возвращает корректный результат.
func FuzzValidCID(f *testing.F) {
	f.Add("abcdef0123456789")
	f.Add("")
	f.Add("ABCDEF0123456789")
	f.Add("ghij")
	f.Add("short")
	f.Add(strings.Repeat("a", 16))

	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ValidCID паника: %v", r)
			}
		}()

		ok := ValidCID(s)
		if ok {
			// Если ValidCID вернул true, проверяем инварианты:
			// длина 16, все символы из [0-9a-f].
			if len(s) != 16 {
				t.Fatalf("ValidCID(true) но длина %d != 16", len(s))
			}
			for _, c := range s {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Fatalf("ValidCID(true) но символ %q недопустим", c)
				}
			}
		}
	})
}

// FuzzEncodeDecodeTarget проверяет roundtrip кодирования/декодирования target.
func FuzzEncodeDecodeTarget(f *testing.F) {
	f.Add("localhost", 8080)
	f.Add("192.168.1.1", 443)

	f.Fuzz(func(t *testing.T, host string, port int) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("EncodeTarget/DecodeTarget паника: %v", r)
			}
		}()

		// Пропускаем невалидные входные данные.
		if host == "" || port <= 0 || port > 65535 {
			return
		}

		labels, err := EncodeTarget(host, port)
		if err != nil {
			t.Fatalf("EncodeTarget(%q, %d) ошибка: %v", host, port, err)
		}

		gotHost, gotPort, err := DecodeTarget(labels)
		if err != nil {
			t.Fatalf("DecodeTarget(%v) ошибка: %v", labels, err)
		}

		if gotHost != host || gotPort != port {
			t.Fatalf("roundtrip не совпал: вход=(%q, %d), результат=(%q, %d)", host, port, gotHost, gotPort)
		}
	})
}

// FuzzDecodeTarget проверяет, что DecodeTarget не паникует на произвольных метках.
func FuzzDecodeTarget(f *testing.F) {
	f.Add("orsxg5a")
	f.Add("")
	f.Add("abc.def.ghi")
	f.Add("!!!invalid!!!")

	f.Fuzz(func(t *testing.T, joined string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeTarget паника: %v", r)
			}
		}()
		labels := strings.Split(joined, ".")
		DecodeTarget(labels)
	})
}

// FuzzCompressDecompress проверяет roundtrip сжатия/распаковки данных.
func FuzzCompressDecompress(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("hello"))
	f.Add([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Compress/Decompress паника: %v", r)
			}
		}()

		comp, err := GetCompressor()
		if err != nil {
			t.Fatalf("GetCompressor ошибка: %v", err)
		}

		// Проверяем roundtrip: Encode -> Decode.
		encoded := comp.Encode(data)
		decoded, err := comp.Decode(encoded)
		if err != nil {
			t.Fatalf("Decode ошибка: %v", err)
		}

		if !bytes.Equal(data, decoded) {
			t.Fatalf("roundtrip не совпал: вход длина=%d, результат длина=%d", len(data), len(decoded))
		}

		// Проверяем, что Decode на произвольных данных не паникует.
		comp.Decode(data)
	})
}

// FuzzBufPool проверяет, что GetBuf/PutBuf не паникуют на различных размерах.
func FuzzBufPool(f *testing.F) {
	f.Add(0)
	f.Add(1)
	f.Add(100)
	f.Add(2048)
	f.Add(8192)
	f.Add(16384)
	f.Add(65536)
	f.Add(100000)

	f.Fuzz(func(t *testing.T, size int) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("GetBuf/PutBuf паника: %v", r)
			}
		}()

		// Пропускаем слишком большие и отрицательные размеры.
		if size < 0 || size > 1<<20 {
			return
		}

		bp := GetBuf(size)
		if bp == nil {
			t.Fatal("GetBuf вернул nil")
		}

		if len(*bp) != size {
			t.Fatalf("GetBuf(%d) вернул буфер длины %d", size, len(*bp))
		}

		PutBuf(bp)
	})
}
