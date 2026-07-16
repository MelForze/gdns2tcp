package clihelp

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintFormatsGroupsLongFlagsMultilineAndNotes(t *testing.T) {
	var out bytes.Buffer
	Print(&out, "tool", "-domain <zone>", []string{"tool -domain example.test"}, []Group{
		{Title: "Empty"},
		{Title: "Options", Flags: []Flag{
			{Names: "-short", Description: "one line"},
			{Names: "-this-option-name-is-deliberately-longer-than-thirty-four", Description: "first\nsecond"},
		}},
	}, []string{"a note"})
	text := out.String()
	for _, want := range []string{"Usage:", "tool -domain <zone>", "Examples:", "Options:", "-short", "first", "second", "Notes:", "a note"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Empty:") {
		t.Fatalf("empty group was printed:\n%s", text)
	}
}

func TestPrintMinimalPage(t *testing.T) {
	var out bytes.Buffer
	Print(&out, "tool", "command", nil, nil, nil)
	if got := out.String(); got != "Usage:\n  tool command\n" {
		t.Fatalf("minimal output=%q", got)
	}
}
