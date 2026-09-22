package codec

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

// FuzzDecodeDNSPayload -- проверяет, что DecodeDNSPayload не паникует
// при любых входных данных и кодировках.
func FuzzDecodeDNSPayload(f *testing.F) {
	// Сиды: валидный base64, base32, пустая строка, строки с паддингом,
	// строки с DNS-безопасными заменами
	f.Add("SGVsbG8=", "base64")
	f.Add("SGVsbG8", "base64")
	f.Add("JBSWY3DP", "base32")
	f.Add("jbswy3dp", "base32")
	f.Add("", "base64")
	f.Add("", "base32")
	f.Add("", "")
	f.Add("SGVs_G8=", "base64")
	f.Add("SGVs-G8=", "base64")
	f.Add("SGVsbG8===", "base64")
	f.Add("AAAA", "base64")
	f.Add("AA==", "base64")
	f.Add("////", "base64")
	f.Add("____", "base64")
	f.Add("----", "base64")
	f.Add("test", "unknown_encoding")

	f.Fuzz(func(t *testing.T, value string, encoding string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeDNSPayload паника: value=%q encoding=%q panic=%v", value, encoding, r)
			}
		}()
		// Просто вызываем -- не должно паниковать
		DecodeDNSPayload(value, encoding)
	})
}

// FuzzCodecRoundTrip -- проверяет, что кодирование и декодирование
// дают исходные данные для обоих кодировок.
func FuzzCodecRoundTrip(f *testing.F) {
	// Сиды: различные срезы байтов
	f.Add([]byte{}, true)
	f.Add([]byte("hello"), false)
	f.Add([]byte("hello world"), true)
	f.Add([]byte{0, 1, 2, 3, 255, 254, 253}, false)
	f.Add([]byte{0xFF, 0x00, 0xAB, 0xCD}, true)
	f.Add(make([]byte, 256), false)

	f.Fuzz(func(t *testing.T, data []byte, useBase32 bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("CodecRoundTrip паника: len(data)=%d useBase32=%v panic=%v", len(data), useBase32, r)
			}
		}()

		encoding := "base64"
		if useBase32 {
			encoding = "base32"
		}

		encoded, err := EncodeDNSPayload(data, encoding)
		if err != nil {
			t.Fatalf("EncodeDNSPayload вернул ошибку: %v", err)
		}

		decoded, err := DecodeDNSPayload(encoded, encoding)
		if err != nil {
			t.Fatalf("DecodeDNSPayload вернул ошибку: %v", err)
		}

		if !bytes.Equal(data, decoded) {
			t.Fatalf("раунд-трип не совпал: исходные %d байт, получено %d байт", len(data), len(decoded))
		}
	})
}

// FuzzCompressDecompressRoundTrip -- проверяет раунд-трип сжатия и распаковки,
// а также поведение DecompressLimit при различных лимитах.
func FuzzCompressDecompressRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("hello"))
	f.Add([]byte("hello world, this is a longer test string for compression"))
	f.Add([]byte{0x00, 0xFF, 0x01, 0xFE, 0x02, 0xFD})
	f.Add(bytes.Repeat([]byte("A"), 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("CompressDecompressRoundTrip паника: len(data)=%d panic=%v", len(data), r)
			}
		}()

		compressed, err := Compress(data)
		if err != nil {
			t.Fatalf("Compress вернул ошибку: %v", err)
		}

		// Распаковка без лимита (maxBytes=0)
		decompressed, err := DecompressLimit(compressed, 0)
		if err != nil {
			t.Fatalf("DecompressLimit(0) вернул ошибку: %v", err)
		}
		if !bytes.Equal(data, decompressed) {
			t.Fatalf("раунд-трип не совпал: исходные %d байт, получено %d байт", len(data), len(decompressed))
		}

		// Распаковка с достаточным лимитом
		decompressed2, err := DecompressLimit(compressed, int64(len(data)))
		if err != nil {
			t.Fatalf("DecompressLimit(len(data)) вернул ошибку: %v", err)
		}
		if !bytes.Equal(data, decompressed2) {
			t.Fatalf("раунд-трип с лимитом не совпал")
		}

		// Распаковка с недостаточным лимитом -- должна вернуть ошибку
		if len(data) > 1 {
			_, err := DecompressLimit(compressed, 1)
			if err == nil {
				t.Fatalf("DecompressLimit(1) должен вернуть ошибку для данных длиной %d", len(data))
			}
		}
	})
}

// FuzzDecompressLimit -- проверяет, что DecompressLimit не паникует
// при произвольных входных данных.
func FuzzDecompressLimit(f *testing.F) {
	// Сид: валидные gzip данные
	validGzip, _ := Compress([]byte("test data"))
	f.Add(validGzip, int64(1024))

	// Сид: обрезанные gzip данные
	if len(validGzip) > 5 {
		f.Add(validGzip[:5], int64(100))
	}

	// Сид: случайный мусор
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF}, int64(50))
	f.Add([]byte{}, int64(0))
	f.Add([]byte{0x1f, 0x8b}, int64(10)) // Начало gzip магического числа
	f.Add(validGzip, int64(-1))
	f.Add(validGzip, int64(0))

	f.Fuzz(func(t *testing.T, data []byte, maxBytes int64) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecompressLimit паника: len(data)=%d maxBytes=%d panic=%v", len(data), maxBytes, r)
			}
		}()
		// Просто вызываем -- не должно паниковать
		DecompressLimit(data, maxBytes)
	})
}

// FuzzBase64DNSReaderNormalization -- проверяет, что base64DNSReader корректно
// нормализует DNS-безопасные символы: _->+, ->/
// base64DNSReader -- неэкспортированный тип, но доступен из того же пакета.
// Тестируем напрямую: кодируем данные стандартным base64, подменяем символы
// на DNS-безопасные, пропускаем через base64DNSReader + base64.NewDecoder.
func FuzzBase64DNSReaderNormalization(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB}) // Данные, порождающие +/ в base64
	f.Add([]byte{0x3E, 0x3F, 0x40})
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(bytes.Repeat([]byte{0xFF}, 100))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Base64DNSReaderNormalization паника: len(data)=%d panic=%v", len(data), r)
			}
		}()

		// Кодируем стандартным base64 (без паддинга -- RawStdEncoding)
		standard := base64.RawStdEncoding.EncodeToString(data)

		// Заменяем + на _, / на - (DNS-безопасная замена)
		dnsSafe := strings.ReplaceAll(standard, "+", "_")
		dnsSafe = strings.ReplaceAll(dnsSafe, "/", "-")

		// Декодируем через base64DNSReader + base64.NewDecoder
		reader := base64.NewDecoder(
			base64.RawStdEncoding,
			base64DNSReader{r: strings.NewReader(dnsSafe)},
		)
		decoded, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("не смогли декодировать через base64DNSReader: %v", err)
		}

		if !bytes.Equal(data, decoded) {
			t.Fatalf("нормализация DNS-безопасных символов не совпала: исходные %d байт, получено %d байт",
				len(data), len(decoded))
		}
	})
}
