package classify_test

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/eppser/unruly/internal/classify"
)

// Precision at volume, against the value distributions real tables actually
// hold.
//
// The held-out eval carries three negatives, which is enough to catch a rule
// that fires on everything and useless for measuring a rate. A checksum rule
// has an arithmetic false-positive rate whether anyone measures it or not:
// Luhn alone passes one string in ten, and the reason the card rule also wants
// an issuer prefix AND a length is to multiply that down. Any rule added
// without the same arithmetic is a claim nobody checked.
//
// Seeded, so a failure is reproducible rather than a story about one run.
func TestPrecisionAtVolume(t *testing.T) {
	r := rand.New(rand.NewSource(20260921))

	digits := func(n int) string {
		s := make([]byte, n)
		for i := range s {
			s[i] = byte('0' + r.Intn(10))
		}
		return string(s)
	}

	// A slice, not a map. The first draft ranged over a map, and Go randomises
	// map order, so each run fed the seeded RNG to the generators in a
	// different sequence and produced different counts. A seeded test whose
	// numbers move between runs measures nothing.
	gens := []struct {
		name string
		gen  func() string
	}{
		{"order number, 8 digits", func() string { return digits(8) }},
		{"order number, 11 digits", func() string { return digits(11) }},
		{"order number, 16 digits", func() string { return digits(16) }},
		{"order number, 18 digits", func() string { return digits(18) }},
		{"unix timestamp", func() string { return fmt.Sprintf("%d", 1600000000+r.Intn(200000000)) }},
		{"uuid", func() string {
			return fmt.Sprintf("%08x-%04x-4%03x-%04x-%012x",
				r.Uint32(), r.Intn(1<<16), r.Intn(1<<12), r.Intn(1<<16), r.Uint64()&0xffffffffffff)
		}},
		{"sku", func() string {
			return fmt.Sprintf("SKU-%s-%c%c", digits(4), 'A'+byte(r.Intn(26)), 'A'+byte(r.Intn(26)))
		}},
		{"price", func() string { return fmt.Sprintf("%d.%02d", r.Intn(100000), r.Intn(100)) }},
		{"hex id", func() string { return fmt.Sprintf("%016x", r.Uint64()) }},
		{"version", func() string { return fmt.Sprintf("v%d.%d.%d", r.Intn(20), r.Intn(40), r.Intn(99)) }},
		{"ipv4", func() string {
			return fmt.Sprintf("%d.%d.%d.%d", r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(256))
		}},
		{"national digits, no plus", func() string { return digits(11) }},
		{"prose", func() string { return fmt.Sprintf("Order %s shipped on schedule", digits(6)) }},
	}

	// Measured ceilings, not aspirations. Zero is the right number for any rule
	// that can demand a second independent constraint, and two here cannot:
	//
	//   financial     2.15% of random sixteen-digit strings. Luhn passes one in
	//                 ten and about 24% of sixteen-digit strings carry an
	//                 accepted issuer prefix, so 0.24 x 0.1 is the floor this
	//                 rule can reach. A bare card number offers nothing else to
	//                 check. PRE-EXISTING, and the package header used to imply
	//                 the issuer prefix removed it rather than reducing it.
	//   government-id 0.10% of random eighteen-digit strings, after the check
	//                 character, the embedded birth date and the province code.
	//
	// Everything else must be zero. A ceiling that rises is a rule that got
	// looser, and this fails rather than tracking it.
	ceiling := map[string]float64{"financial": 2.5, "government-id": 0.2}

	const perGen = 2000
	total, bad := 0, 0
	// A slice, not a map. The first draft ranged over a map, and Go randomises
	// map order, so each run fed the seeded RNG to the generators in a
	// different sequence and produced different counts. A seeded test whose
	// numbers move between runs measures nothing.
	for _, g := range gens {
		name, gen := g.name, g.gen
		hits := map[string]int{}
		for i := 0; i < perGen; i++ {
			v := gen()
			total++
			for _, k := range classify.Kinds([]map[string]any{{"c": v}}) {
				hits[k]++
				bad++
				if hits[k] <= 2 {
					t.Logf("FALSE POSITIVE  %-24s %-14s %q", name, k, v)
				}
			}
		}
		for k, n := range hits {
			rate := 100 * float64(n) / float64(perGen)
			if rate > ceiling[k] {
				t.Errorf("%s: %d/%d tagged %s (%.2f%%), ceiling %.2f%%. A rule with an "+
					"arithmetic false-positive rate needs a second independent "+
					"constraint, the way CPF gained punctuation and the Chinese "+
					"identity number gained its province code",
					name, n, perGen, k, rate, ceiling[k])
			}
		}
	}
	t.Logf("%d values across %d distributions, %d false positives", total, len(gens), bad)
}
