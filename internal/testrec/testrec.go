// Package testrec records what a test HTTP fixture was asked for, safely.
//
// net/http serves each connection on its own goroutine, and this scanner
// probes with bounded concurrency by design, so a fixture that records
// requests into a captured slice is racing whenever the stage under test does
// its job. That is not hypothetical: the first eval for Neon table
// enumeration appended to a bare slice, passed under `go test`, and failed
// under `go test -race` — but only because the scheduler happened to overlap
// two appends on that run. A racy recorder that gets lucky reports nothing
// and silently drops entries, so the assertions built on it end up describing
// evidence that was never collected.
//
// Log is deliberately a log rather than a counter or a flag. A bool says that
// something happened; a log says what happened, which is the difference
// between a test that can only confirm its own expectation and one that can
// show you the request it objected to when it fails.
package testrec

import (
	"strings"
	"sync"
)

// Log is a concurrency-safe record of fixture observations. The zero value is
// ready to use, so a fixture declares `var asked testrec.Log` and is correct.
type Log struct {
	mu      sync.Mutex
	entries []string
}

// Add records one observation.
func (l *Log) Add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, s)
}

// Entries returns a copy, in the order observed. A copy because the caller is
// usually a test assertion running while the server may still be handling a
// request, and handing out the live slice would reintroduce the race this
// package exists to remove.
func (l *Log) Entries() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.entries))
	copy(out, l.entries)
	return out
}

// Len is the number of observations.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Last is the most recent observation, or "" if there is none.
func (l *Log) Last() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		return ""
	}
	return l.entries[len(l.entries)-1]
}

// Has reports whether any observation contains sub.
func (l *Log) Has(sub string) bool {
	for _, e := range l.Entries() {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}

// Count returns how many observations contain sub.
func (l *Log) Count(sub string) int {
	n := 0
	for _, e := range l.Entries() {
		if strings.Contains(e, sub) {
			n++
		}
	}
	return n
}
