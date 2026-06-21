package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestAuthVerifyCurrentAndPreviousMinute(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	args := []string{"sid12345", "0"}

	currentTS := CurrentTimestamp(now)
	currentToken := AuthToken("secret", "Example.TEST.", "D", currentTS, args)
	if !VerifyAuth("secret", "example.test", "d", args, currentTS, currentToken, now) {
		t.Fatal("current-minute token did not verify")
	}

	previousTS := CurrentTimestamp(now.Add(-time.Minute))
	previousToken := AuthToken("secret", "example.test", "d", previousTS, args)
	if !VerifyAuth("secret", "example.test", "d", args, previousTS, previousToken, now) {
		t.Fatal("previous-minute token did not verify")
	}

	// Within the ±VerifyAuthWindowMinutes (=15) NTP-drift tolerance: must verify.
	skewTS := CurrentTimestamp(now.Add(-14 * time.Minute))
	skewToken := AuthToken("secret", "example.test", "d", skewTS, args)
	if !VerifyAuth("secret", "example.test", "d", args, skewTS, skewToken, now) {
		t.Fatal("14-minute-old token did not verify (within ±15-minute window)")
	}

	// Beyond the window: must be rejected.
	oldTS := CurrentTimestamp(now.Add(-16 * time.Minute))
	oldToken := AuthToken("secret", "example.test", "d", oldTS, args)
	if VerifyAuth("secret", "example.test", "d", args, oldTS, oldToken, now) {
		t.Fatal("16-minute-old token verified (past ±15-minute window)")
	}

	futureTS := CurrentTimestamp(now.Add(time.Minute))
	futureToken := AuthToken("secret", "example.test", "d", futureTS, args)
	if !VerifyAuth("secret", "example.test", "d", args, futureTS, futureToken, now) {
		t.Fatal("next-minute token not verified (clock skew tolerance)")
	}

	tooFutureTS := CurrentTimestamp(now.Add(16 * time.Minute))
	tooFutureToken := AuthToken("secret", "example.test", "d", tooFutureTS, args)
	if VerifyAuth("secret", "example.test", "d", args, tooFutureTS, tooFutureToken, now) {
		t.Fatal("16-minute-future token should be rejected")
	}
}

func TestAuthRejectsWrongTokenAndArgs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	ts := CurrentTimestamp(now)
	args := []string{"sid12345", "0"}
	token := AuthToken("secret", "example.test", "d", ts, args)

	if VerifyAuth("wrong", "example.test", "d", args, ts, token, now) {
		t.Fatal("token verified with wrong secret")
	}
	if VerifyAuth("secret", "example.test", "d", []string{"sid12345", "1"}, ts, token, now) {
		t.Fatal("token verified with wrong args")
	}
	if VerifyAuth("secret", "example.test", "u", args, ts, token, now) {
		t.Fatal("token verified with wrong command")
	}
}

func TestFilenameLabelsRoundTrip(t *testing.T) {
	names := []string{
		"TestCase!3:256.exe.txt",
		"my_file.txt",
		"space name.txt",
		"unicode-\u041f\u0440\u0438\u0432\u0435\u0442.txt",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			labels, err := EncodeFilenameLabels(name)
			if err != nil {
				t.Fatalf("EncodeFilenameLabels: %v", err)
			}
			got, err := DecodeFilenameLabels(labels)
			if err != nil {
				t.Fatalf("DecodeFilenameLabels: %v", err)
			}
			if got != name {
				t.Fatalf("got %q, want %q", got, name)
			}
			if err := ValidateFilename(got); err != nil {
				t.Fatalf("ValidateFilename: %v", err)
			}
		})
	}
}

func TestValidateFilenameRejectsPathsAndControlCharacters(t *testing.T) {
	invalid := []string{
		"", ".", "..", "../x", "x/y", `x\y`,
		"bad\x00name",  // NUL (C0)
		"bad\nname",    // LF (C0)
		"bad\u0085name", // NEL (C1, U+0085)
		"bad\u009fname", // APC (C1, U+009F)
		"bad\u202ename", // RIGHT-TO-LEFT OVERRIDE (Cf)
		"bad\u2066name", // LEFT-TO-RIGHT ISOLATE  (Cf)
		"bad\u200bname", // ZERO WIDTH SPACE        (Cf)
		"bad\ufeffname", // BOM / ZWNBSP            (Cf)
	}
	for _, name := range invalid {
		if err := ValidateFilename(name); err == nil {
			t.Fatalf("ValidateFilename(%q) succeeded, want error", name)
		}
	}
}

func TestNewSID(t *testing.T) {
	sid, err := NewSID()
	if err != nil {
		t.Fatalf("NewSID: %v", err)
	}
	if len(sid) != 16 {
		t.Fatalf("NewSID length=%d, want 16", len(sid))
	}
	for _, r := range sid {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("NewSID contains non-hex char %q in %q", r, sid)
		}
	}
	sid2, err := NewSID()
	if err != nil {
		t.Fatalf("NewSID second call: %v", err)
	}
	if sid == sid2 {
		t.Fatalf("NewSID returned identical values: %q", sid)
	}
}

func TestValidSID(t *testing.T) {
	if ValidSID("") {
		t.Fatal("empty string should be invalid")
	}
	if ValidSID("abc") {
		t.Fatal("3-char SID should be invalid (< 8)")
	}
	if ValidSID(strings.Repeat("a", 65)) {
		t.Fatal("65-char SID should be invalid (> 64)")
	}
	if !ValidSID("abc12345") {
		t.Fatal("8-char lowercase alphanum SID should be valid")
	}
	if !ValidSID("hello-world1") {
		t.Fatal("SID with dash should be valid")
	}
	if ValidSID("UPPER12345") {
		t.Fatal("uppercase SID should be invalid")
	}
	if ValidSID("has space1") {
		t.Fatal("SID with space should be invalid")
	}
}

func TestJoinName(t *testing.T) {
	got := JoinName("example.test.", "d", []string{"sid12345", "0"})
	want := "sid12345.0.d.example.test"
	if got != want {
		t.Fatalf("JoinName=%q, want %q", got, want)
	}
}

func TestEncodeFilenameLabelsEmpty(t *testing.T) {
	if _, err := EncodeFilenameLabels(""); err == nil {
		t.Fatal("expected error for empty filename")
	}
}

func TestDecodeFilenameLabelsErrors(t *testing.T) {
	if _, err := DecodeFilenameLabels([]string{}); err == nil {
		t.Fatal("expected error for empty labels")
	}
	if _, err := DecodeFilenameLabels([]string{"wrong"}); err == nil {
		t.Fatal("expected error for missing prefix")
	}
	if _, err := DecodeFilenameLabels([]string{"f1", "!!notbase32!!"}); err == nil {
		t.Fatal("expected error for invalid base32 data")
	}
}

func TestCurrentTimestamp(t *testing.T) {
	now := time.Now().UTC()
	ts1 := CurrentTimestamp(now)
	ts2 := CurrentTimestamp(now)
	if ts1 != ts2 {
		t.Fatalf("same second should produce same timestamp: %q vs %q", ts1, ts2)
	}
	later := now.Add(61 * time.Second)
	ts3 := CurrentTimestamp(later)
	if ts1 == ts3 {
		t.Fatalf("timestamps 61 seconds apart should differ: both %q", ts1)
	}
}

func TestChunkStringSizesProtocol(t *testing.T) {
	got := ChunkString("abcdef", 2)
	want := []string{"ab", "cd", "ef"}
	if len(got) != len(want) {
		t.Fatalf("ChunkString(abcdef,2) len=%d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chunk %d: got %q, want %q", i, got[i], want[i])
		}
	}
	if got := ChunkString("abc", 0); got != nil {
		t.Fatalf("ChunkString with size 0 should return nil, got %v", got)
	}
	if got := ChunkString("", 5); len(got) != 0 {
		t.Fatalf("ChunkString of empty string should return empty, got %v", got)
	}
}
