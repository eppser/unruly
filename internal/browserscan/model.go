package browserscan

import (
	"fmt"
	"sort"
	"strings"
)

// Class is one answer the model may give.
type Class struct {
	Slot        string // the single token the model emits
	Name        string // the kind reported, matching the rules' vocabulary
	Description string // what the model is asked to recognise
}

// modelClasses is FOUR, and the number is set by the runtime rather than by
// taste.
//
// It was five. The fifth was "sensitive": health, biometrics, religion,
// politics, criminal record. Against a real application it fired on almost
// every text column, filling the report with "sensitive / the model's opinion,
// not proof" beside ordinary content. A category that broad gives the model
// nowhere to put an uncertain answer except into it, and a class that is
// almost always chosen carries no information. The three that remain each name
// something specific enough to be wrong about.
//
// The CLI declares sixteen classes and renormalises the model's probability
// across all of them. WebLLM enforces top_logprobs <= 5: config.ts throws a
// RangeError above that. Scoring sixteen declared slots on five returned ones
// would divide by a short denominator, inflate every surviving class, and
// loosen the 0.80 gate that holds the model's false positives down.
//
// So the browser asks a coarser question it can answer correctly, rather than
// the CLI's question answered approximately. Names stay in the rules'
// vocabulary so the page can show model and rule findings side by side without
// translating between two dialects.
var modelClasses = []Class{
	{"A", "credential", "secret material: password, password hash, API key, access token, private key"},
	{"B", "financial", "payment instrument or bank account: card number, IBAN, account number, salary"},
	{"C", "contact", "a way to reach or name a person: full name, email address, phone number, postal address"},
	{"Z", "none", "ordinary application data with nothing personal or secret in it: product text, order references, prices, status values, timestamps, identifiers, logs"},
}

// ModelClasses returns the classes the browser model chooses between.
func ModelClasses() []Class { return append([]Class(nil), modelClasses...) }

// ModelPrompt renders the question for one column.
//
// The shared block comes FIRST and the column LAST, which is a performance
// contract, not a layout preference: everything before the column is identical
// on every request, so a runtime that caches a prefix re-reads only the tail.
// Reordering this reads better and silently costs an order of magnitude.
func ModelPrompt(column string, values []string) string {
	var b strings.Builder
	// "One letter and nothing else" is load bearing. Measured on the CLI:
	// without it the top token for a column called national_id was "The", the
	// correct class ranked second, and renormalised to 0.649 against a 0.80
	// gate. That sentence was most of a twenty point recall gap.
	b.WriteString("A column was read from a database table. Given its name and the " +
		"values sampled from it, choose the single class of sensitive data it holds.\n" +
		"Reply with exactly one letter from the list and nothing else.\n\n")
	for _, c := range modelClasses {
		fmt.Fprintf(&b, "%s. %s\n", c.Slot, c.Description)
	}
	fmt.Fprintf(&b, "\ncolumn name: %s\nsampled values: %s\n\nAnswer:",
		column, strings.Join(trim(values), " | "))
	return b.String()
}

// maxValueChars is how much of one sampled value reaches the model.
//
// Eighty. A browser run failed with "number of prompt tokens: 5080; context
// window size: 4096" because values were passed through whole, and a single
// long bio column is enough to overflow a 4k window. The classifier is
// deciding what KIND of thing a value is, and the opening of an address says
// that as well as the whole of it.
const maxValueChars = 80

// trim shortens each value so the prompt fits, and shortens them EVENLY so a
// long first value cannot spend the budget a later one needed.
func trim(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		r := []rune(v)
		if len(r) > maxValueChars {
			r = r[:maxValueChars]
			out = append(out, string(r)+"…")
			continue
		}
		out = append(out, v)
	}
	return out
}

// PickClass renormalises over the DECLARED slots and applies the gate.
//
// Renormalising over the answer slots rather than the whole vocabulary is the
// point: it asks what the model would choose among these options, not how much
// of its probability went to unrelated tokens. Slots the runtime did not
// return are absent rather than zero, which keeps the comparison between the
// ones it did return honest.
//
// Returns an empty name for "no opinion": below the gate, no declared slot
// present, or the model choosing "none". A quiet guess is worse than silence,
// because the page presents anything returned here as a finding.
func PickClass(weights map[string]float64, threshold float64) (string, float64) {
	kept := make(map[string]float64, len(modelClasses))
	sum := 0.0
	for _, c := range modelClasses {
		w, ok := weights[c.Slot]
		if !ok {
			// Some tokenizers carry the leading space into the token.
			if w, ok = weights[" "+c.Slot]; !ok {
				continue
			}
		}
		kept[c.Name] = w
		sum += w
	}
	if sum == 0 {
		return "", 0
	}
	names := make([]string, 0, len(kept))
	for n := range kept {
		names = append(names, n)
	}
	// Sorted, so a tie resolves the same way on every run and every machine.
	sort.Strings(names)
	best, bestP := "", 0.0
	for _, n := range names {
		if p := kept[n] / sum; p > bestP {
			best, bestP = n, p
		}
	}
	if best == "none" || bestP < threshold {
		return "", bestP
	}
	return best, bestP
}
