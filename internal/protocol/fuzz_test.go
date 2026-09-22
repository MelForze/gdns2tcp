package protocol

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzValidateDomain проверяет, что ValidateDomain не паникует на произвольных входных данных.
func FuzzValidateDomain(f *testing.F) {
	f.Add("example.com")
	f.Add("a.b.c.d.e")
	f.Add("")
	f.Add(strings.Repeat("x", 254))
	f.Add(".leading.dot")
	f.Add("trailing.dot.")
	f.Add(strings.Repeat("a", 64) + ".example.com")

	f.Fuzz(func(t *testing.T, domain string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ValidateDomain паника: %v", r)
			}
		}()
		ValidateDomain(domain)
	})
}

// FuzzParseDomainCSV проверяет, что ParseDomainCSV не паникует и возвращает корректные результаты.
func FuzzParseDomainCSV(f *testing.F) {
	f.Add("example.com")
	f.Add("a.com,b.com,c.com")
	f.Add("")
	f.Add("a.com,,b.com")
	f.Add("a.com, b.com , c.com")

	f.Fuzz(func(t *testing.T, raw string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseDomainCSV паника: %v", r)
			}
		}()
		canonical, shardDomains, _, _, err := ParseDomainCSV(raw)
		if err != nil {
			return
		}
		// Если ошибки нет, canonical должен быть непустым,
		// либо shardDomains содержит ровно один пустой элемент.
		if canonical == "" {
			if len(shardDomains) != 1 || shardDomains[0] != "" {
				t.Fatalf("canonical пуст, но shardDomains = %v (ожидался [\"\"])", shardDomains)
			}
		}
	})
}

// FuzzAuthTokenVerify проверяет, что сгенерированный токен всегда проходит верификацию,
// а модифицированный токен всегда отклоняется.
func FuzzAuthTokenVerify(f *testing.F) {
	f.Add("mysecret", "example.com", "download")
	f.Add("s3cr3t", "test.org", "upload")
	f.Add("key123", "a.b.c", "poll")
	f.Add("", "example.com", "cmd")
	f.Add("secret", "", "cmd")

	f.Fuzz(func(t *testing.T, secret, domain, command string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("AuthToken/VerifyAuth паника: %v", r)
			}
		}()

		now := time.Now()
		ts := CurrentTimestamp(now)
		args := []string{"sid12345", "0"}

		token := AuthToken(secret, domain, command, ts, args)

		// VerifyAuth возвращает false при пустом secret — пропускаем проверку roundtrip.
		if secret != "" {
			if !VerifyAuth(secret, domain, command, args, ts, token, now) {
				t.Fatalf("токен не прошёл верификацию: secret=%q domain=%q command=%q", secret, domain, command)
			}
		}

		// Проверяем, что модифицированный токен не проходит верификацию.
		if len(token) > 0 && secret != "" {
			modified := []byte(token)
			if modified[0] == 'a' {
				modified[0] = 'b'
			} else {
				modified[0] = 'a'
			}
			if VerifyAuth(secret, domain, command, args, ts, string(modified), now) {
				t.Fatalf("модифицированный токен прошёл верификацию")
			}
		}
	})
}

// FuzzValidSID проверяет, что ValidSID не паникует и возвращает корректный результат.
func FuzzValidSID(f *testing.F) {
	f.Add("abcdef01")
	f.Add("a-b-c")
	f.Add("")
	f.Add("UPPERCASE")
	f.Add("abc!@#")
	f.Add(strings.Repeat("a", 65))

	f.Fuzz(func(t *testing.T, sid string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ValidSID паника: %v", r)
			}
		}()
		ok := ValidSID(sid)
		if ok {
			// Если ValidSID вернул true, проверяем инварианты:
			// длина 8–64, символы из [a-z0-9-].
			if len(sid) < 8 || len(sid) > 64 {
				t.Fatalf("ValidSID(true) но длина %d не в диапазоне [8, 64]", len(sid))
			}
			for _, r := range sid {
				if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
					t.Fatalf("ValidSID(true) но символ %q недопустим", r)
				}
			}
		}
	})
}

// FuzzEncodeDecodeFilenameLabels проверяет roundtrip кодирования/декодирования имён файлов.
func FuzzEncodeDecodeFilenameLabels(f *testing.F) {
	f.Add("test.txt")
	f.Add("hello world.bin")
	f.Add("файл.txt")
	f.Add("")
	f.Add("a")

	f.Fuzz(func(t *testing.T, filename string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("EncodeFilenameLabels/DecodeFilenameLabels паника: %v", r)
			}
		}()

		// Пропускаем пустые, пробельные и не-UTF-8 строки.
		if strings.TrimSpace(filename) == "" {
			return
		}
		if !utf8.ValidString(filename) {
			return
		}

		labels, err := EncodeFilenameLabels(filename)
		if err != nil {
			t.Fatalf("EncodeFilenameLabels(%q) ошибка: %v", filename, err)
		}

		decoded, err := DecodeFilenameLabels(labels)
		if err != nil {
			t.Fatalf("DecodeFilenameLabels(%v) ошибка: %v", labels, err)
		}

		if decoded != filename {
			t.Fatalf("roundtrip не совпал: вход=%q, результат=%q", filename, decoded)
		}
	})
}

// FuzzDecodeFilenameLabels проверяет, что DecodeFilenameLabels не паникует на произвольных метках.
func FuzzDecodeFilenameLabels(f *testing.F) {
	f.Add("abcdefgh")
	f.Add("")
	f.Add("MFRA.AAAA")
	f.Add("!!!invalid!!!")
	f.Add("orsxg5a")

	f.Fuzz(func(t *testing.T, joined string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeFilenameLabels паника: %v", r)
			}
		}()
		labels := append([]string{FilenamePrefix}, strings.Split(joined, ".")...)
		DecodeFilenameLabels(labels)
	})
}

// FuzzValidateFilename проверяет, что ValidateFilename не паникует на произвольных данных.
func FuzzValidateFilename(f *testing.F) {
	f.Add("test.txt")
	f.Add("..")
	f.Add("/etc/passwd")
	f.Add("normal")
	f.Add("a\x00b")
	f.Add("")

	f.Fuzz(func(t *testing.T, filename string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ValidateFilename паника: %v", r)
			}
		}()
		ValidateFilename(filename)
	})
}

// FuzzSessionMACVerify проверяет, что SessionMAC/VerifySessionMAC корректно работают:
// валидный MAC проходит, а модифицированный — нет.
func FuzzSessionMACVerify(f *testing.F) {
	f.Add("axchg", uint64(0))
	f.Add("awrite", uint64(42))
	f.Add("aread", uint64(1000))
	f.Add("aclose", uint64(999999))

	f.Fuzz(func(t *testing.T, cmd string, seq uint64) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("SessionMAC/VerifySessionMAC паника: %v", r)
			}
		}()

		key := DeriveSessionKey("secret", "abcdef0123456789")
		mac := SessionMAC(key, cmd, seq)

		// Проверяем, что валидный MAC проходит верификацию.
		if !VerifySessionMAC(key, cmd, seq, mac) {
			t.Fatalf("VerifySessionMAC не прошёл для cmd=%q seq=%d mac=%q", cmd, seq, mac)
		}

		// Проверяем, что модифицированный MAC не проходит верификацию.
		if len(mac) > 0 {
			modified := []byte(mac)
			if modified[0] == 'a' {
				modified[0] = 'b'
			} else {
				modified[0] = 'a'
			}
			if VerifySessionMAC(key, cmd, seq, string(modified)) {
				t.Fatalf("модифицированный MAC прошёл верификацию для cmd=%q seq=%d", cmd, seq)
			}
		}
	})
}
