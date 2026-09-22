package main

import (
	"encoding/binary"
	"testing"
)

// FuzzParseTXTResponse скармливает произвольные байты парсеру DNS-ответов
// клиента. Парсер не должен паниковать ни на каком входе — любой
// некорректный пакет должен возвращаться как ошибка. Паника от фаззера
// означала бы скрытую DoS-уязвимость (злонамеренный/сломанный авторитетный
// сервер мог бы уронить клиент одним ответом).
func FuzzParseTXTResponse(f *testing.F) {
	// Корректный ответ: заголовок 12 байт, ID=0xABCD, QR=1, ANCOUNT=1,
	// имя=root, type=TXT, class=IN, TTL=0, RDLEN=6, строка "Hello".
	good := make([]byte, 12)
	binary.BigEndian.PutUint16(good[0:2], 0xABCD)
	good[2] = 0x80 // QR=1
	binary.BigEndian.PutUint16(good[6:8], 1) // ANCOUNT=1
	txt := append([]byte(nil), good...)
	txt = append(txt, 0)                          // имя = root
	txt = append(txt, 0, 16, 0, 1, 0, 0, 0, 0)   // type=TXT, class=IN, TTL=0
	txt = append(txt, 0, 6)                       // RDLEN=6
	txt = append(txt, 5, 'H', 'e', 'l', 'l', 'o') // char-string "Hello"
	f.Add(txt, uint16(0xABCD))

	// Слишком короткий ответ (менее 12 байт).
	f.Add([]byte{0x00, 0x01, 0x80}, uint16(1))

	// Несовпадение ID.
	wrongID := make([]byte, 12)
	binary.BigEndian.PutUint16(wrongID[0:2], 0x1234)
	wrongID[2] = 0x80
	f.Add(wrongID, uint16(0x5678))

	// TC=1 (ответ усечён).
	tc := make([]byte, 12)
	binary.BigEndian.PutUint16(tc[0:2], 42)
	tc[2] = 0x82 // QR=1 + TC=1
	f.Add(tc, uint16(42))

	// RCODE != 0 (SERVFAIL).
	rcode := make([]byte, 12)
	binary.BigEndian.PutUint16(rcode[0:2], 99)
	rcode[2] = 0x80
	rcode[3] = 0x02 // SERVFAIL
	f.Add(rcode, uint16(99))

	// Указатель-компрессия в имени ответа.
	ptr := make([]byte, 12)
	binary.BigEndian.PutUint16(ptr[0:2], 7)
	ptr[2] = 0x80
	binary.BigEndian.PutUint16(ptr[6:8], 1) // ANCOUNT=1
	ptr = append(ptr, 0xC0, 0x00)           // указатель на смещение 0
	ptr = append(ptr, 0, 16, 0, 1, 0, 0, 0, 0)
	ptr = append(ptr, 0, 1, 0) // RDLEN=1, пустая char-string
	f.Add(ptr, uint16(7))

	// Ответ с QDCOUNT=1 и вопросной секцией.
	withQ := make([]byte, 12)
	binary.BigEndian.PutUint16(withQ[0:2], 50)
	withQ[2] = 0x80
	binary.BigEndian.PutUint16(withQ[4:6], 1) // QDCOUNT=1
	binary.BigEndian.PutUint16(withQ[6:8], 1) // ANCOUNT=1
	withQ = append(withQ, 3, 'f', 'o', 'o', 0) // qname = foo.
	withQ = append(withQ, 0, 16, 0, 1)         // qtype=TXT, qclass=IN
	withQ = append(withQ, 0)                    // answer name = root
	withQ = append(withQ, 0, 16, 0, 1, 0, 0, 0, 0)
	withQ = append(withQ, 0, 4)                    // RDLEN=4
	withQ = append(withQ, 3, 'a', 'b', 'c')       // char-string "abc"
	f.Add(withQ, uint16(50))

	f.Fuzz(func(t *testing.T, resp []byte, id uint16) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseTXTResponse panicked on resp=%x id=%d: %v", resp, id, r)
			}
		}()
		_, _ = parseTXTResponse(resp, id)
	})
}

// FuzzSkipDNSName нацелен на обходчик меток, используемый парсером
// ответов. Регрессия здесь позволит вредоносному ответу уронить клиент
// через панику проверки границ, незавершённый цикл или бесконечную
// погоню за указателями.
func FuzzSkipDNSName(f *testing.F) {
	// Корневое имя.
	f.Add([]byte{0}, 0)
	// Обычная метка: abc.
	f.Add([]byte{3, 'a', 'b', 'c', 0}, 0)
	// Указатель-компрессия.
	f.Add([]byte{0xC0, 0x0C}, 0)
	// Усечённый указатель.
	f.Add([]byte{0xC0}, 0)
	// Некорректный байт длины метки (старшие биты 10xxxxxx).
	f.Add([]byte{0x80, 0}, 0)
	// Усечённая метка: длина=5, но данных всего 2 байта.
	f.Add([]byte{5, 'a', 'b'}, 0)
	// Многоуровневое имя: x.y.z.w.
	f.Add([]byte{1, 'x', 1, 'y', 1, 'z', 1, 'w', 0}, 0)
	// Начальная позиция не с нуля.
	f.Add([]byte{0xFF, 0xFF, 3, 'a', 'b', 'c', 0}, 2)
	// Пустой буфер.
	f.Add([]byte{}, 0)

	f.Fuzz(func(t *testing.T, buf []byte, pos int) {
		// Фильтруем неразумные начальные позиции.
		if pos < 0 || pos > 1<<20 {
			return
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("skipDNSName panicked on buf=%x pos=%d: %v", buf, pos, r)
			}
		}()
		_, _ = skipDNSName(buf, pos)
	})
}

// FuzzBuildTXTQuery проверяет, что построитель DNS-запросов не паникует
// ни на каком имени. При отсутствии ошибки верифицируем, что результат
// содержит корректный 12-байтовый заголовок с ожидаемым ID и QDCOUNT=1.
func FuzzBuildTXTQuery(f *testing.F) {
	f.Add("example.com", uint16(1))
	f.Add("a.b.c.d", uint16(0xFFFF))
	f.Add("", uint16(0))
	// Длинное имя — 253 символа (максимально допустимое).
	long := ""
	for len(long)+4 <= 253 {
		long += "aaa."
	}
	if len(long) > 0 && long[len(long)-1] == '.' {
		long = long[:len(long)-1]
	}
	f.Add(long, uint16(100))
	// Слишком длинная метка — 64 символа (>63, должна вернуть ошибку).
	longLabel := ""
	for i := 0; i < 64; i++ {
		longLabel += "x"
	}
	f.Add(longLabel+".com", uint16(200))
	// Имя с точкой на конце (FQDN).
	f.Add("example.com.", uint16(300))
	// Имя, состоящее целиком из точек.
	f.Add("...", uint16(400))

	f.Fuzz(func(t *testing.T, name string, id uint16) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("buildTXTQuery panicked on name=%q id=%d: %v", name, id, r)
			}
		}()
		result, err := buildTXTQuery(name, id)
		if err != nil {
			return
		}
		// Проверяем минимальную корректность результата.
		if len(result) < 12 {
			t.Fatalf("buildTXTQuery returned %d bytes (< 12) for name=%q id=%d", len(result), name, id)
		}
		gotID := binary.BigEndian.Uint16(result[0:2])
		if gotID != id {
			t.Fatalf("buildTXTQuery: ID mismatch: got %d, want %d (name=%q)", gotID, id, name)
		}
		qdcount := binary.BigEndian.Uint16(result[4:6])
		if qdcount != 1 {
			t.Fatalf("buildTXTQuery: QDCOUNT=%d, want 1 (name=%q id=%d)", qdcount, name, id)
		}
	})
}

// FuzzBuildThenParse — round-trip-тест: buildTXTQuery строит запрос,
// затем мы убеждаемся, что для любого допустимого имени вывод корректно
// структурирован (12-байтовый заголовок, QDCOUNT=1, ARCOUNT=1 для OPT).
// Полноценный round-trip невозможен без сервера, но мы можем проверить
// инварианты формата.
func FuzzBuildThenParse(f *testing.F) {
	f.Add("test.example.com", uint16(1000))
	f.Add("a", uint16(1))
	f.Add("sub.domain.example.org", uint16(0x7FFF))
	f.Add("x.y", uint16(0))

	f.Fuzz(func(t *testing.T, name string, id uint16) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("buildTXTQuery panicked during round-trip on name=%q id=%d: %v", name, id, r)
			}
		}()
		q, err := buildTXTQuery(name, id)
		if err != nil {
			return
		}
		// Структурные инварианты заголовка.
		if len(q) < 12 {
			t.Fatalf("query too short: %d bytes", len(q))
		}
		gotID := binary.BigEndian.Uint16(q[0:2])
		if gotID != id {
			t.Fatalf("round-trip ID mismatch: got %d, want %d", gotID, id)
		}
		qdcount := binary.BigEndian.Uint16(q[4:6])
		if qdcount != 1 {
			t.Fatalf("round-trip QDCOUNT=%d, want 1", qdcount)
		}
		arcount := binary.BigEndian.Uint16(q[10:12])
		if arcount != 1 {
			t.Fatalf("round-trip ARCOUNT=%d, want 1 (OPT record)", arcount)
		}
		// Проверяем, что вопросная секция начинается с позиции 12
		// и может быть пропущена skipDNSName.
		pos, err := skipDNSName(q, 12)
		if err != nil {
			t.Fatalf("round-trip: skipDNSName failed at question name: %v", err)
		}
		// После имени — type(2) + class(2) = 4 байта для вопроса,
		// затем должна остаться OPT-запись (11 байт).
		remaining := len(q) - pos
		if remaining < 4 {
			t.Fatalf("round-trip: not enough bytes after question name: %d", remaining)
		}
		qtype := binary.BigEndian.Uint16(q[pos : pos+2])
		if qtype != dnsTypeTXT {
			t.Fatalf("round-trip: qtype=%d, want %d (TXT)", qtype, dnsTypeTXT)
		}
		qclass := binary.BigEndian.Uint16(q[pos+2 : pos+4])
		if qclass != 1 {
			t.Fatalf("round-trip: qclass=%d, want 1 (IN)", qclass)
		}
	})
}
