//go:build !race

package main

// raceEnabled lets tests skip themselves under `go test -race`. The 2 MB
// bulk-echo tests below are CPU-bound through a 96-worker axchg pipeline;
// the race detector adds ~10x overhead and combines badly with the known
// cross-test goroutine residue from earlier tests in the package,
// producing flaky timeouts even with very generous deadlines.
const raceEnabled = false
