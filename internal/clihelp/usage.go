// Package clihelp contains tiny formatting helpers for command usage output.
package clihelp

import (
	"fmt"
	"io"
	"strings"
)

// Flag describes one visible CLI option in grouped help output.
type Flag struct {
	Names       string
	Description string
}

// Group is a named collection of related CLI options.
type Group struct {
	Title string
	Flags []Flag
}

// Print writes a compact, scenario-oriented usage page.
func Print(w io.Writer, program, usage string, examples []string, groups []Group, notes []string) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s %s\n", program, usage)

	if len(examples) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Examples:")
		for _, example := range examples {
			fmt.Fprintf(w, "  %s\n", example)
		}
	}

	maxNames := 0
	for _, group := range groups {
		for _, flag := range group.Flags {
			if n := len(flag.Names); n > maxNames {
				maxNames = n
			}
		}
	}
	if maxNames > 34 {
		maxNames = 34
	}

	for _, group := range groups {
		if len(group.Flags) == 0 {
			continue
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s:\n", group.Title)
		for _, flag := range group.Flags {
			writeFlag(w, flag, maxNames)
		}
	}

	if len(notes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Notes:")
		for _, note := range notes {
			fmt.Fprintf(w, "  - %s\n", note)
		}
	}
}

func writeFlag(w io.Writer, flag Flag, width int) {
	lines := strings.Split(flag.Description, "\n")
	if len(flag.Names) > width {
		fmt.Fprintf(w, "  %s\n", flag.Names)
		for _, line := range lines {
			prefix := strings.Repeat(" ", width+4)
			fmt.Fprintf(w, "%s%s\n", prefix, line)
		}
		return
	}
	fmt.Fprintf(w, "  %-*s  %s\n", width, flag.Names, lines[0])
	for _, line := range lines[1:] {
		fmt.Fprintf(w, "  %-*s  %s\n", width, "", line)
	}
}
