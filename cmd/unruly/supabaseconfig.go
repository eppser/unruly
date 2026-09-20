package main

import (
	"strings"
)

// splitHosts turns a comma-separated flag into a list.
//
// Shared with the pre-flight plan check, which builds the same stage list from
// the flags alone: two copies of this would let the shape that is CHECKED
// differ from the shape that RUNS, which is the one thing a pre-flight check
// must not permit.
func splitHosts(csv string) []string {
	var out []string
	for _, h := range strings.Split(csv, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// stringList is a repeatable string flag.
//
// Repeatable rather than comma-separated because the values are arbitrary --
// an identifier may legitimately contain a comma, and splitting one would
// send a request for a resource nobody named.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
