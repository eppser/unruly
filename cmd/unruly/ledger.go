package main

import (
	"fmt"
	"sort"
	"strings"
)

// Where the requests went.
//
// A scan of a 21-relation fixture spends 18,300 requests, and until now the
// report said only that. An operator who thinks that is too much traffic
// against their project has no way to know which stage to cap, and neither did
// this project: the first attempt at tuning it capped -max-seeds and changed
// the total by zero, because seeds were not what was spending it.
//
// Every stage already returns its own count. They were being added into one
// scalar, which threw away the only information that makes the number
// actionable.
type ledger struct {
	n map[string]int
}

func newLedger() *ledger { return &ledger{n: map[string]int{}} }

// add records a stage's spend. A stage that ran and made no requests is still
// recorded, so "0" and "did not run" stay distinguishable.
func (l *ledger) add(stage string, n int) {
	if l == nil {
		return
	}
	l.n[stage] += n
}

func (l *ledger) total() int {
	t := 0
	for _, v := range l.n {
		t += v
	}
	return t
}

// summary lists the stages that actually cost something, largest first, so the
// line names the flag worth reaching for. Ties break by name: reports get
// diffed between runs.
func (l *ledger) summary(top int) string {
	type kv struct {
		k string
		v int
	}
	var all []kv
	for k, v := range l.n {
		if v > 0 {
			all = append(all, kv{k, v})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	if len(all) > top {
		all = all[:top]
	}
	parts := make([]string, 0, len(all))
	for _, e := range all {
		parts = append(parts, fmt.Sprintf("%s %d", e.k, e.v))
	}
	return strings.Join(parts, ", ")
}
