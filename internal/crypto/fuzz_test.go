package cryptoutil

import (
	"bytes"
	"crypto/aes"
	"testing"
)

// FuzzProtectOpenRoundTrip -- проверяет раунд-трип шифрования и расшифровки
// для произвольных данных и секретов.
func FuzzProtectOpenRoundTrip(f *testing.F) {
	// Сиды: различные комбинации открытого текста и секрета
	f.Add([]byte{}, "mysecret")
	f.Add([]byte("hello world"), "password123")
	f.Add([]byte{0xFF, 0x00, 0xAB, 0xCD, 0xEF}, "s3cr3t!")
	f.Add([]byte("short"), "k")
	f.Add(bytes.Repeat([]byte("A"), 1024), "long-secret-key-for-testing")
	f.Add([]byte{0x00}, "test")
	f.Add(bytes.Repeat([]byte{0xFF}, 256), "another-secret")

	f.Fuzz(func(t *testing.T, plaintext []byte, secret string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ProtectOpenRoundTrip паника: len(plaintext)=%d secret=%q panic=%v",
					len(plaintext), secret, r)
			}
		}()

		// Пропускаем пустой секрет -- Protect возвращает ошибку по спецификации
		if secret == "" {
			return
		}

		protected, err := Protect(secret, plaintext)
		if err != nil {
			t.Fatalf("Protect вернул ошибку: %v", err)
		}

		decrypted, err := Open(secret, protected)
		if err != nil {
			t.Fatalf("Open вернул ошибку: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("раунд-трип не совпал: исходные %d байт, получено %d байт",
				len(plaintext), len(decrypted))
		}
	})
}

// FuzzOpenMalformed -- проверяет, что Open не паникует
// при произвольных (некорректных) входных данных.
func FuzzOpenMalformed(f *testing.F) {
	// Сид: слишком короткие данные
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x02, 0x03})
	f.Add([]byte("GDT2")) // Только магическое число

	// Сид: валидный заголовок, но неправильная магия
	wrongMagic := make([]byte, 120)
	copy(wrongMagic, "XXXX")
	f.Add(wrongMagic)

	// Сид: правильная магия, но мусор после неё
	rightMagic := make([]byte, 120)
	copy(rightMagic, "GDT2")
	f.Add(rightMagic)

	// Сид: случайный мусор
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})

	// Сид: данные с правильной длиной, но невалидным содержимым
	minLen := len("GDT2") + 16 + aes.BlockSize + 32 + aes.BlockSize
	almostValid := make([]byte, minLen)
	copy(almostValid, "GDT2")
	f.Add(almostValid)

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("OpenMalformed паника: len(data)=%d panic=%v", len(data), r)
			}
		}()

		// Должен вернуть ошибку, но не паниковать
		_, err := Open("test-secret", data)
		if err == nil {
			// Если ошибки нет, данные случайно оказались валидными --
			// это крайне маловероятно, но допустимо
		}
	})
}

// FuzzPKCS7PadUnpad -- проверяет раунд-трип pkcs7Pad/pkcs7Unpad,
// а также что pkcs7Unpad не паникует при произвольных данных.
// Функции неэкспортированные, но доступны из _test.go (тот же пакет).
func FuzzPKCS7PadUnpad(f *testing.F) {
	f.Add([]byte{}, true)
	f.Add([]byte("hello"), true)
	f.Add([]byte{0x00, 0x01, 0x02}, true)
	f.Add(bytes.Repeat([]byte("X"), 16), true)
	f.Add(bytes.Repeat([]byte("Y"), 31), true)
	f.Add([]byte{0xFF}, true)

	// Сиды для тестирования pkcs7Unpad с произвольными данными
	f.Add([]byte{}, false)
	f.Add([]byte{0x10}, false) // padding=16, но длина=1
	f.Add([]byte{0x00}, false) // padding=0 -- невалидно
	f.Add(bytes.Repeat([]byte{0x01}, 16), false)
	f.Add(bytes.Repeat([]byte{0x05}, 16), false)

	f.Fuzz(func(t *testing.T, data []byte, testRoundTrip bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PKCS7PadUnpad паника: len(data)=%d testRoundTrip=%v panic=%v",
					len(data), testRoundTrip, r)
			}
		}()

		if testRoundTrip {
			// Тест раунд-трипа: pad, затем unpad
			padded := pkcs7Pad(data, aes.BlockSize)

			// Проверяем, что длина кратна размеру блока
			if len(padded)%aes.BlockSize != 0 {
				t.Fatalf("pkcs7Pad: длина %d не кратна %d", len(padded), aes.BlockSize)
			}

			// Проверяем, что padded длиннее data
			if len(padded) <= len(data) {
				t.Fatalf("pkcs7Pad: padded (%d) должен быть длиннее data (%d)", len(padded), len(data))
			}

			unpadded, err := pkcs7Unpad(padded, aes.BlockSize)
			if err != nil {
				t.Fatalf("pkcs7Unpad вернул ошибку после pkcs7Pad: %v", err)
			}

			if !bytes.Equal(data, unpadded) {
				t.Fatalf("PKCS7 раунд-трип не совпал: исходные %d байт, получено %d байт",
					len(data), len(unpadded))
			}
		} else {
			// Тест pkcs7Unpad с произвольными данными -- не должно паниковать
			pkcs7Unpad(data, aes.BlockSize)
		}
	})
}
