package scan

import "sort"

// StageSpend is how many requests one stage accounted for.
type StageSpend struct {
	Stage    string
	Requests int
}

// Attribute records requests a stage spent.
//
// This is ATTRIBUTION, not the authoritative request total, and the
// distinction is load-bearing. The stored report once said 1,827 requests for
// a scan that actually sent 88: it was counting what the stages asked for,
// including the seventeen hundred the circuit breaker declined to make. A
// report that overstates its own traffic is the same class of error as one
// that overstates its coverage, because the reader cannot tell effort from
// intent.
//
// The authoritative total therefore comes from the transport's own counter --
// what was actually sent. What this gives is the breakdown: where the traffic
// went, which the transport counter cannot say.
func (s *State) Attribute(stage string, n int) {
	if s.spend == nil {
		s.spend = map[string]int{}
	}
	// Accumulating rather than assigning: schema scans re-run the same stage
	// once per exposed schema, and reporting only the last would understate
	// traffic that really left.
	s.spend[stage] += n
}

// Attributed is the sum of everything stages accounted for. See Attribute for
// why this is not the number a report should print as its request count.
func (s *State) Attributed() int {
	var n int
	for _, v := range s.spend {
		n += v
	}
	return n
}

// Spending is the per-stage breakdown, sorted by stage name.
//
// Sorted by name and not by execution order, because execution order is not
// stable across a pipeline whose stages can be skipped or reordered by flags,
// and two scans of an unchanged project have to produce identical bytes.
func (s *State) Spending() []StageSpend {
	out := make([]StageSpend, 0, len(s.spend))
	for k, v := range s.spend {
		out = append(out, StageSpend{Stage: k, Requests: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Stage < out[j].Stage })
	return out
}
