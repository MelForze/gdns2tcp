package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const dnsTypeTXT uint16 = 16

var rcodeNames = map[byte]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
}

func fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func randomDNSID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	id := binary.BigEndian.Uint16(b[:])
	if id == 0 {
		id = 1
	}
	return id
}

// buildTXTQuery encodes a DNS query for the TXT record of name.
func buildTXTQuery(name string, id uint16) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	buf := make([]byte, 0, 32+len(name))
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:2], id)
	hdr[2] = 0x01                            // flags: RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)  // QDCOUNT=1
	buf = append(buf, hdr[:]...)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("DNS label too long: %d", len(label))
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	var trailer [4]byte
	binary.BigEndian.PutUint16(trailer[0:2], dnsTypeTXT)
	binary.BigEndian.PutUint16(trailer[2:4], 1) // CLASS=IN
	buf = append(buf, trailer[:]...)
	return buf, nil
}

// parseTXTResponse concatenates all TXT character strings from every TXT RR
// in the answer section. Returns an error on truncated/malformed responses
// or non-success rcodes.
func parseTXTResponse(resp []byte, expectID uint16) (string, error) {
	if len(resp) < 12 {
		return "", errors.New("DNS response too short")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != expectID {
		return "", errors.New("DNS ID mismatch")
	}
	if rcode := resp[3] & 0x0F; rcode != 0 {
		name := rcodeNames[rcode]
		if name == "" {
			name = fmt.Sprintf("rcode=%d", rcode)
		}
		return "", fmt.Errorf("DNS response code %s", name)
	}
	qdcount := int(binary.BigEndian.Uint16(resp[4:6]))
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	pos := 12
	for i := 0; i < qdcount; i++ {
		var err error
		pos, err = skipDNSName(resp, pos)
		if err != nil {
			return "", err
		}
		if pos+4 > len(resp) {
			return "", errors.New("truncated question section")
		}
		pos += 4
	}
	var sb strings.Builder
	for i := 0; i < ancount; i++ {
		var err error
		pos, err = skipDNSName(resp, pos)
		if err != nil {
			return "", err
		}
		if pos+10 > len(resp) {
			return "", errors.New("truncated RR header")
		}
		rtype := binary.BigEndian.Uint16(resp[pos : pos+2])
		pos += 8 // type(2)+class(2)+ttl(4)
		rdlen := int(binary.BigEndian.Uint16(resp[pos : pos+2]))
		pos += 2
		end := pos + rdlen
		if end > len(resp) {
			return "", errors.New("truncated RDATA")
		}
		if rtype == dnsTypeTXT {
			p := pos
			for p < end {
				sl := int(resp[p])
				p++
				if p+sl > end {
					return "", errors.New("malformed TXT character-string")
				}
				sb.Write(resp[p : p+sl])
				p += sl
			}
		}
		pos = end
	}
	if sb.Len() == 0 {
		return "", errors.New("no TXT response")
	}
	return sb.String(), nil
}

func skipDNSName(buf []byte, pos int) (int, error) {
	for pos < len(buf) {
		b := buf[pos]
		if b == 0 {
			return pos + 1, nil
		}
		if b&0xC0 == 0xC0 {
			if pos+1 >= len(buf) {
				return 0, errors.New("truncated name pointer")
			}
			return pos + 2, nil
		}
		if b&0xC0 != 0 {
			return 0, errors.New("invalid label length byte")
		}
		next := pos + 1 + int(b)
		if next > len(buf) {
			return 0, errors.New("truncated label")
		}
		pos = next
	}
	return 0, errors.New("unterminated DNS name")
}

func exchangeUDP(addr string, q []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func exchangeTCP(addr string, q []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(q)))
	if _, err := conn.Write(prefix[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	rlen := int(binary.BigEndian.Uint16(prefix[:]))
	resp := make([]byte, rlen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
