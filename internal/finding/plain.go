package finding

import (
	"sort"
	"strconv"
	"strings"
)

// Plain renders the report for somebody who does not run databases.
//
// The default rendering answers "what is wrong with this project" in the
// vocabulary of the thing being scanned: relations, policies, SQLSTATEs. That
// is right for the person fixing it and useless to the person deciding whether
// it matters. This answers a different question -- WHO can do WHAT to WHICH
// data -- and answers it in words that survive being read aloud in a meeting.
//
// It is a rendering, not a second analysis. Every line comes from findings the
// scan already produced, so it cannot claim more than the report behind it.

// actor is who can do the thing. Ordered by how little it costs an attacker to
// become them, because that is the order the reader cares about.
type actor int

const (
	anyone   actor = iota // no account, just the public key
	signedUp              // anyone who completes the signup form
)

func (a actor) heading() string {
	switch a {
	case anyone:
		return "Anyone on the internet, with no account and no password, can:"
	case signedUp:
		return "Anyone who signs up for an account can also:"
	}
	return ""
}

// verb is what they can do, worst first: destruction outranks alteration,
// alteration outranks creation, and reading is the floor.
type verb int

const (
	runAnything verb = iota
	readSecret
	deleteRows
	changeRows
	createRows
	watchChanges
	readRows
	// lastVerb bounds the render loop. Keep it last.
	lastVerb = readRows
)

func (v verb) phrase() string {
	switch v {
	case runAnything:
		return "run ANY command on the database, including deleting all of it"
	case readSecret:
		return "read a password or key that this app hands to every visitor"
	case deleteRows:
		return "permanently delete rows from"
	case changeRows:
		return "change the contents of"
	case createRows:
		return "add new rows to"
	case watchChanges:
		return "watch every change as it happens in"
	case readRows:
		return "read everything in"
	}
	return ""
}

// capability maps a finding id onto who and what. Ids absent from this table
// are not rendered: this view is deliberately about data an actor can reach,
// not about every fact the scan recorded.
var capability = map[string]struct {
	who  actor
	what verb
}{
	"pocketbase-anon-read-exposed":        {anyone, readRows},
	"pocketbase-authenticated-escalation": {signedUp, readRows},
	"supabase-anon-read-exposed":          {anyone, readRows},
	"supabase-anon-insert-allowed":        {anyone, createRows},
	"supabase-anon-update-allowed":        {anyone, changeRows},
	"supabase-anon-delete-allowed":        {anyone, deleteRows},
	"supabase-anon-arbitrary-sql":         {anyone, runAnything},
	"supabase-rpc-returns-data":           {anyone, readRows},
	"supabase-authenticated-escalation":   {signedUp, readRows},
	"supabase-storage-anon-write":         {anyone, createRows},
	"supabase-public-storage-bucket":      {anyone, readRows},
	"supabase-realtime-anon-delivery":     {anyone, watchChanges},
	"supabase-realtime-anon-subscription": {anyone, watchChanges},

	// The other backend.
	//
	// This table held only supabase- ids, so a Firebase project rendered NO
	// plain-language section at all -- measured on the lab, where a critical
	// finding (a Stripe-shaped key served to every client) was present and the
	// plain report was empty. A reader who was given this mode precisely
	// because they cannot read the technical one saw silence, which is the
	// clean result this tool exists to stop reporting by accident.
	//
	// Firebase's escalation finding is the same shape as Supabase's and belongs
	// in the same tier: a rule reading `if request.auth != null` is satisfied by
	// anybody where signup is open.
	"firebase-firestore-anon-read":          {anyone, readRows},
	"firebase-rtdb-anon-read":               {anyone, readRows},
	"firebase-firestore-authenticated-read": {signedUp, readRows},
	"firebase-remote-config-secret":         {anyone, readSecret},
	"firebase-storage-anon-read":            {anyone, readRows},
	"firebase-function-public":              {anyone, runAnything},
	"firebase-firestore-anon-write":         {anyone, createRows},
	"firebase-rtdb-anon-write":              {anyone, createRows},

	// Neon. signedUp rather than anyone, and the distinction is the whole
	// finding: an unauthenticated request to a Neon Data API is refused
	// before the table is consulted, so nobody reaches this data without an
	// account. Sign-up being open is what makes "an account" mean anyone who
	// wants one, which the finding says in its own words rather than by
	// overstating the tier here.
	"neon-authenticated-read-unrestricted": {signedUp, readRows},
	"neon-authenticated-write-allowed":     {signedUp, createRows},
}

// A policy mismatch can describe any subject and operation, so it cannot be
// forced into the fixed actor/verb table above without misrepresenting it.
var policyFinding = map[string]bool{"unruly-intent-violation": true}

// plainData turns column names into what a reader recognises. The classifier
// already tags columns; this is the last translation step, from a label to a
// noun somebody would use.
var plainData = []struct {
	tag, phrase string
}{
	{"credential", "passwords or access tokens"},
	{"financial", "card or payment details"},
	{"government-id", "government identifiers like passport, tax or social security numbers"},
	{"health", "health information"},
	{"pii", "personal names and dates of birth"},
	{"contact", "email addresses or phone numbers"},
	{"location", "postal addresses or coordinates"},
}

// Plain builds the whole report. Empty when nothing reachable was found, so a
// caller can print a clean-result line instead.
func Plain(fs []Finding) string {
	type row struct {
		resource string
		rows     int
		kinds    []string
	}
	grouped := map[actor]map[verb][]row{}
	var policyRows []string
	for _, f := range fs {
		if policyFinding[f.ID] {
			policyRows = append(policyRows, f.Resource)
			continue
		}
		cap, ok := capability[f.ID]
		if !ok {
			continue
		}
		if grouped[cap.who] == nil {
			grouped[cap.who] = map[verb][]row{}
		}
		grouped[cap.who][cap.what] = append(grouped[cap.who][cap.what], row{
			resource: f.Resource,
			rows:     f.Evidence.Rows,
			kinds:    kindsOf(f),
		})
	}
	if len(grouped) == 0 && len(policyRows) == 0 {
		return ""
	}

	var b strings.Builder
	for _, who := range []actor{anyone, signedUp} {
		byVerb, ok := grouped[who]
		if !ok {
			continue
		}
		b.WriteString(who.heading())
		b.WriteString("\n")
		// Every verb, derived from the enum rather than listed again here.
		//
		// This was a second hardcoded list, and adding a verb to the enum did
		// not add it to the report: the heading printed with nothing under it,
		// which reads as "anyone can do nothing" on a project where somebody
		// can read a live credential. One list, so the two cannot disagree.
		for what := verb(0); what <= lastVerb; what++ {
			rows, ok := byVerb[what]
			if !ok {
				continue
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].resource < rows[j].resource })
			b.WriteString("\n  " + what.phrase() + "\n")
			for _, r := range rows {
				b.WriteString("    " + r.resource)
				if r.rows > 0 {
					b.WriteString("  (" + strconv.Itoa(r.rows) + " " +
						plural(r.rows, "row", "rows") + ")")
				}
				if len(r.kinds) > 0 {
					b.WriteString("\n      holds " + strings.Join(r.kinds, ", "))
				}
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}
	if len(policyRows) > 0 {
		sort.Strings(policyRows)
		b.WriteString("The deployed access policy contradicts the declared intent for:\n")
		for _, resource := range policyRows {
			b.WriteString("  - ")
			b.WriteString(strings.TrimPrefix(resource, "intent:"))
			b.WriteString("\n")
		}
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

// kindsOf translates the classifier's tags into plain nouns, in a fixed order
// so the same finding always reads the same way.
func kindsOf(f Finding) []string {
	seen := map[string]bool{}
	// Evidence.Classes first: it is the machine-readable union of both
	// classifiers. sensitiveTags is a fallback for findings that carry only
	// prose -- it recovers "column:kind" pairs and nothing else, which is why
	// everything the VALUE classifier found used to be invisible here.
	for _, c := range f.Evidence.Classes {
		seen[c] = true
	}
	for _, s := range sensitiveTags(f) {
		seen[s] = true
	}
	var out []string
	for _, p := range plainData {
		if seen[p.tag] {
			out = append(out, p.phrase)
		}
	}
	return out
}

// sensitiveTags extracts the classification labels a finding carries, from the
// "column:tag" pairs the reason records.
func sensitiveTags(f Finding) []string {
	var out []string
	for _, part := range strings.Split(f.Evidence.Reason, ",") {
		if i := strings.LastIndex(strings.TrimSpace(part), ":"); i > 0 {
			out = append(out, strings.TrimSpace(strings.TrimSpace(part)[i+1:]))
		}
	}
	return out
}
