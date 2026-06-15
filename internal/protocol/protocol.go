package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	AuthVersion    = "gdns2tcp-auth-v1"
	FilenamePrefix = "f1"
)

var base32NoPadding = base32.StdEncoding.WithPadding(base32.NoPadding)

func AuthDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func CurrentTimestamp(now time.Time) string {
	return strconv.FormatInt(now.UTC().Unix()/60, 10)
}

func AuthToken(secret, domain, command, timestamp string, args []string) string {
	parts := []string{AuthVersion, AuthDomain(domain), strings.ToLower(command), timestamp}
	parts = append(parts, args...)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strings.Join(parts, "|")))
	sum := mac.Sum(nil)
	// 16 bytes (128 bits) is sufficient for a MAC used as a single-use
	// per-minute token and keeps the DNS label short.
	return strings.ToLower(base32NoPadding.EncodeToString(sum[:16]))
}

func VerifyAuth(secret, domain, command string, args []string, timestamp, token string, now time.Time) bool {
	if strings.TrimSpace(secret) == "" || strings.TrimSpace(timestamp) == "" || strings.TrimSpace(token) == "" {
		return false
	}
	minute, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	current := now.UTC().Unix() / 60
	if minute < current-1 || minute > current+1 {
		return false
	}
	expected := AuthToken(secret, domain, command, timestamp, args)
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(token)))
}

func NewSID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate sid: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func ValidSID(sid string) bool {
	if len(sid) < 8 || len(sid) > 64 {
		return false
	}
	for _, r := range sid {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return true
}

func EncodeFilenameLabels(filename string) ([]string, error) {
	if strings.TrimSpace(filename) == "" {
		return nil, errors.New("filename is empty")
	}
	encoded := strings.ToLower(base32NoPadding.EncodeToString([]byte(filename)))
	labels := []string{FilenamePrefix}
	labels = append(labels, ChunkString(encoded, 63)...)
	return labels, nil
}

func DecodeFilenameLabels(labels []string) (string, error) {
	if len(labels) < 2 || labels[0] != FilenamePrefix {
		return "", errors.New("missing filename encoding prefix")
	}
	joined := strings.ToUpper(strings.Join(labels[1:], ""))
	raw, err := base32NoPadding.DecodeString(joined)
	if err != nil {
		return "", fmt.Errorf("decode filename: %w", err)
	}
	if !utf8.Valid(raw) {
		return "", errors.New("filename is not valid UTF-8")
	}
	return string(raw), nil
}

func ValidateFilename(filename string) error {
	if filename == "" || filename == "." || filename == ".." {
		return errors.New("empty filename")
	}
	if strings.ContainsAny(filename, "/\\") {
		return errors.New("path separators are not allowed")
	}
	for _, r := range filename {
		if unicode.IsControl(r) {
			return errors.New("control characters are not allowed")
		}
		// Block Unicode format characters (category Cf): bidirectional
		// overrides/isolates, zero-width spaces, soft hyphen and BOM. All of
		// these are invisible and can disguise the true filename in a terminal.
		if unicode.Is(unicode.Cf, r) {
			return errors.New("formatting control characters are not allowed in filenames")
		}
	}
	if filepath.Base(filename) != filename {
		return errors.New("filename must be a basename")
	}
	return nil
}

func ChunkString(value string, size int) []string {
	if size <= 0 {
		return nil
	}
	chunks := make([]string, 0, (len(value)+size-1)/size)
	for start := 0; start < len(value); start += size {
		end := start + size
		if end > len(value) {
			end = len(value)
		}
		chunks = append(chunks, value[start:end])
	}
	return chunks
}

func JoinName(domain, command string, args []string) string {
	labels := make([]string, 0, len(args)+2)
	labels = append(labels, args...)
	labels = append(labels, strings.ToLower(command), AuthDomain(domain))
	return strings.Join(labels, ".")
}
