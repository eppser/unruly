// Package wordlist serves unruly's pinned name lists.
//
// The lists are embedded in the binary, so a scan depends on nothing outside
// the executable and two runs of the same version always probe the same names.
// They are generated combinatorially by data/gen_wordlists.py rather than
// curated by hand: a list assembled from observed targets would quietly encode
// those targets' answers, which is how a scanner comes to look accurate on the
// projects it was developed against and blind everywhere else.
//
// Wordlists complement the hint oracle, they do not replace it. Conventional
// names (users, sessions, admin_delete) are what a list can cover; a schema
// like zero_day_series or signatory_submissions is only reachable by seeding
// the oracle with the application's own vocabulary.
package wordlist

import (
	_ "embed"
	"sort"

	"github.com/eppser/unruly/internal/sample"
	"strings"
)

//go:embed collections.txt
var collectionsRaw string

//go:embed relations.txt
var relationsRaw string

//go:embed routines.txt
var routinesRaw string

//go:embed pages.txt
var pagesRaw string

//go:embed functions.txt
var functionsRaw string

//go:embed subdomains.txt
var subdomainsRaw string

var (
	collections = parse(collectionsRaw)
	relations   = parse(relationsRaw)
	routines    = parse(routinesRaw)
	pages       = parse(pagesRaw)
	functions   = parse(functionsRaw)
	subdomains  = parse(subdomainsRaw)
)

// Functions returns the pinned Edge Function name list.
func Functions() []string { return clone(functions) }

// Pages returns the pinned page-path list used to seed route discovery.
func Pages() []string { return clone(pages) }

// Relations returns the pinned relation-name list, sorted and deduplicated.
func Relations() []string { return clone(relations) }

// Collections is the Firebase list: Firestore collection names and Realtime
// Database top-level paths, which are the same kind of name and are probed the
// same way.
func Collections() []string { return clone(collections) }

// Subdomains are the labels a second deployment of the same application is
// most often published under.
//
// Pinned and small on purpose. This list decides how many hostnames get a DNS
// lookup and, for those that resolve, one HTTP request -- traffic to somebody's
// infrastructure, so it is a list that has to justify every entry rather than a
// dictionary that happens to be lying around. The entries are the ones that
// name an ENVIRONMENT (staging, preprod, uat) or a SURFACE (api, admin,
// dashboard), because those are where a forgotten deployment of the same
// backend lives.
func Subdomains() []string { return clone(subdomains) }

// Routines returns the pinned routine-name list, sorted and deduplicated.
func Routines() []string { return clone(routines) }

// fold lower-cases a name only where Postgres would.
//
// An unquoted ASCII identifier is folded by the server, so `Customers` in a
// bundle is `customers` in the catalogue and probing both would double the
// work for one relation. Postgres does NOT fold non-ASCII without a collation,
// and the benchmark corpus holds Ünïcödé and ünïcödé as two separate relations
// to pin that down. Folding here lost one of them: supplying all fourteen
// names of that project recovered thirteen, and the missing one was the
// upper-case twin, discarded as a duplicate before the oracle ever saw it.
func fold(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return s // not ours to fold
		}
	}
	return strings.ToLower(s)
}

// Merge combines harvested vocabulary with a pinned list, returning a sorted,
// deduplicated set. Order is total so enumeration stays deterministic
// regardless of which source contributed a name.
// MergeKeepingCase is Merge without the case fold.
//
// It exists for one consumer and the distinction is not cosmetic. Merge folds
// ASCII names to lower case because a Postgres identifier is case-insensitive
// unless it was quoted into existence, so `Users` and `users` are one name and
// counting them twice would spend two probes to ask one question.
//
// A Cloud Function name is not an identifier. It is a path segment, and the
// server compares it byte for byte: .../publicEcho answers 200 where
// .../publicecho answers 404. Folding therefore does not merge two spellings
// of one name, it invents a name that does not exist -- and since the function
// check reports a 404 as nothing at all, the result was silence rather than an
// error anybody could see.
func MergeKeepingCase(harvested, pinned []string) []string {
	seen := make(map[string]struct{}, len(harvested)+len(pinned))
	out := make([]string, 0, len(harvested)+len(pinned))
	for _, src := range [][]string{harvested, pinned} {
		for _, s := range src {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out) // total order: enumeration stays deterministic
	return out
}

func Merge(harvested, pinned []string) []string {
	seen := make(map[string]struct{}, len(harvested)+len(pinned))
	out := make([]string, 0, len(harvested)+len(pinned))
	for _, src := range [][]string{harvested, pinned} {
		for _, s := range src {
			s = fold(strings.TrimSpace(s))
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Contributions reports how many names in the merged set came from each
// source, in the order the sources are given.
//
// WHY THIS IS NOT len(source): Merge deduplicates, folds and drops empties, so
// the raw source sizes double-count every name that appears in two of them.
// That is not a corner case -- "users" and "profiles" are on the pinned list
// AND are exactly the names an application references, so the pinned/harvested
// overlap is the common case. The scan summary renders these counts as a
// sentence a reader will add up, and the total has to be a number the scan
// actually probed.
//
// First source to contribute a surviving name owns it, which is Merge's own
// precedence, so the counts sum to exactly len(Merge(...)) over the same
// inputs.
//
// It lives beside Merge because it has to fold identically to it. fold()
// deliberately leaves non-ASCII alone ("not ours to fold"); a second copy
// elsewhere would disagree on exactly the NFC/NFD identifiers this project
// went to trouble to get right.
func Contributions(sources ...[]string) []int {
	seen := make(map[string]struct{})
	counts := make([]int, len(sources))
	for i, src := range sources {
		for _, s := range src {
			s = fold(strings.TrimSpace(s))
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			counts[i]++
		}
	}
	return counts
}

func parse(raw string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, line)
	}
	sort.Strings(out)
	return out
}

func clone(xs []string) []string {
	out := make([]string, len(xs))
	copy(out, xs)
	return out
}

// routinePrefixes are the verbs that begin a privileged database routine.
//
// Pinned rather than harvested: they are a property of how people name
// functions, not of any one application, and pinning them keeps discovery
// deterministic.
var routinePrefixes = []string{
	"admin", "get", "list", "fetch", "read", "create", "insert", "update",
	"delete", "remove", "purge", "reset", "set", "sync", "export", "import",
	"approve", "reject", "review", "grant", "revoke", "refresh", "recalculate",
	"internal", "private", "sudo", "su",
}

// Compose builds compound routine candidates by joining a pinned verb to each
// harvested token.
//
// PostgREST's hint oracle matches on similarity, and a compound name is not
// similar enough to either of its parts. Measured against a routine named
// admin_read_audit_log on a real project:
//
//	audit_log        no hint       admin            no hint
//	admin_read       no hint       read_audit_log   no hint
//	admin_audit_log  HINT -> "Perhaps you meant ... public.admin_read_audit_log"
//
// Only the compound clears the threshold. Vocabulary harvesting yields single
// tokens, so every routine whose name joins a verb to a domain noun was out of
// reach — which is most of the privileged ones worth finding.
//
// The result is verb-major and sorted, so truncation under a probe cap drops
// the least likely candidates rather than an arbitrary slice, and two runs
// against the same site always probe the same names.
func Compose(harvested []string, max int) []string {
	if len(harvested) == 0 || max <= 0 {
		return nil
	}
	// Only domain-looking tokens are worth joining: a verb glued to another
	// verb ("admin_get") names almost nothing, and doubles the probe budget.
	verbs := make(map[string]bool, len(routinePrefixes))
	for _, v := range routinePrefixes {
		verbs[v] = true
	}
	nouns := make([]string, 0, len(harvested))
	for _, h := range harvested {
		h = strings.TrimSpace(strings.ToLower(h))
		if len(h) < 3 || verbs[h] {
			continue
		}
		nouns = append(nouns, h)
	}
	sort.Strings(nouns)
	nouns = dedup(nouns)

	out := make([]string, 0, len(routinePrefixes)*len(nouns))
	for _, v := range routinePrefixes {
		for _, n := range nouns {
			out = append(out, v+"_"+n)
		}
	}
	sort.Strings(out)
	out = dedup(out)
	// Sampled across the list: cutting at the front keeps only the
	// alphabetically first prefixes, so a binding cap made whole families of
	// names (update_*, verify_*, write_*) unreachable.
	out = sample.Take(out, max)
	sort.Strings(out)
	return out
}

func dedup(xs []string) []string {
	if len(xs) == 0 {
		return xs
	}
	out := xs[:1]
	for _, x := range xs[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// bucketWords are the nouns Supabase storage buckets are named after, and the
// modifiers that get glued to them.
//
// Pinned because a bucket cannot be enumerated: GET /storage/v1/bucket returns
// [] to the anonymous role even when a public bucket exists, so the only way
// to reach one is to know or guess its name. That makes the quality of this
// list the entire recall of the storage check.
var bucketNouns = []string{
	"assets", "attachments", "audio", "avatars", "backups", "banners", "docs",
	"documents", "downloads", "exports", "files", "icons", "images", "imports",
	"invoices", "logos", "media", "photos", "pictures", "receipts", "reports",
	"resources", "static", "storage", "thumbnails", "uploads", "videos",
}

var bucketModifiers = []string{
	"public", "private", "user", "users", "profile", "product", "temp", "tmp",
	"shared", "internal", "customer", "admin",
}

// Buckets returns candidate bucket names: the pinned nouns, the pinned
// modifiers, and each modifier joined to each noun with a hyphen and with an
// underscore, since both conventions are common and Supabase permits both.
//
// Harvested vocabulary is folded in by the caller through Merge. The lab's own
// bucket is public-uploads, which no single-token list contains and which the
// modifier-noun join produces.
func Buckets(harvested []string) []string {
	out := make([]string, 0, len(bucketNouns)+len(bucketModifiers)+
		len(bucketModifiers)*len(bucketNouns)*2)
	out = append(out, bucketNouns...)
	out = append(out, bucketModifiers...)
	for _, m := range bucketModifiers {
		for _, n := range bucketNouns {
			out = append(out, m+"-"+n, m+"_"+n)
		}
	}
	for _, h := range harvested {
		h = strings.TrimSpace(strings.ToLower(h))
		// Bucket names are short and word-like; a long harvested token is
		// almost always a sentence fragment or an identifier from a bundle.
		if len(h) < 3 || len(h) > 24 {
			continue
		}
		out = append(out, h)
	}
	sort.Strings(out)
	return dedup(out)
}

// relationModifiers are the words that commonly prefix a table name.
//
// Pinned, like the routine verbs, because they are a property of how people
// name tables rather than of any one application.
var relationModifiers = []string{
	"account", "admin", "api", "audit", "billing", "customer", "employee",
	"feedback", "internal", "invoice", "member", "order", "org", "payment",
	"private", "product", "profile", "project", "public", "user", "workspace",
}

// RelationCandidates expands a seed list into near-misses the PostgREST hint
// oracle can act on.
//
// The oracle answers a near miss with the real name, so recall is decided by
// whether any seed lands close enough to something real. With a site to
// harvest, the application's own vocabulary supplies those seeds and recall is
// high. WITHOUT one — a bare -p ref -k key scan — the pinned list has to do it
// alone, and measured against a second project it managed 2 of 7 while the
// oracle would have answered for all 7. The seeds were the limit, not the
// oracle.
//
// Measured on that project's seven relations:
//
//	seeds as they are      0/7
//	n-1 stems              1/7   (audit_log, from audit_lo)
//	modifier + singular    4/7   (customer_records, api_tokens, …)
//
// So both are generated. A compound is singularised because that is what makes
// it a near miss rather than an exact one: customer_record hints
// customer_records, while customer_records IS customer_records and hints
// nothing.
//
// Sorted and capped, so truncation drops the tail rather than an arbitrary
// slice and two runs probe the same names.
//
// SAMPLING WAS MEASURED AND REJECTED. The obvious saving is to probe a subset
// and let the oracle's iterative rounds find the neighbours, since it does
// expand from a foothold. It does not compensate here — each relation needs
// its own near miss, and recall falls almost linearly with the sample:
//
//	every 8th candidate   1,718 probes   3 of 7 relations
//	every 4th             3,435          4 of 7
//	every 2nd             6,870          5 of 7
//	all                  13,740          7 of 7
//
// So the cost is not slack to be trimmed; it is what full recall costs. This
// is written down because the number looks like an obvious optimisation
// target, and taking it would quietly trade away the recall the expansion
// exists to provide.
//
// The two generators are also measured, not assumed. Against the same project:
// stems alone are 658 probes for 1 relation, compounds alone are 13,083 for
// all 7. Stems are kept anyway — they are 5% of the cost, and they reach a
// name whose plural differs by one character, which no modifier pairing does.
// RelationCandidatesFrom is RelationCandidates, led by the families the scan
// has already found.
//
// A name observed on THIS target is evidence; a pinned noun is a guess about
// schemas in general. Measured on the reference target: the first pass
// recovers v3_cves, v3_exploits, v3_tte and v3_nvd_references, and the one
// relation it misses is v3_fetch_progress -- a fifth member of a family whose
// prefix is sitting in the results. The expansion then spent 15,180 requests
// on combinations of an English list to reach it, and -max-relation-probes
// binds at 15,000, so the order candidates are produced in decides which ones
// are ever sent.
//
// Only prefixes seen at least twice count. One relation called orders is not a
// family, and crossing every discovered name with every noun would bury the
// evidence in combinations nothing supports.
func RelationCandidatesFrom(seeds, discovered []string, max int) []string {
	if max <= 0 {
		return nil
	}
	fams := families(discovered)
	if len(fams) == 0 {
		return RelationCandidates(seeds, max)
	}
	seen := map[string]bool{}
	out := make([]string, 0, max)
	add := func(s string) bool {
		if len(s) < 4 || len(s) > 48 || seen[s] || len(out) >= max {
			return len(out) < max
		}
		seen[s] = true
		out = append(out, s)
		return true
	}
	// Observed prefix crossed with the seeds, then with the pinned modifiers.
	for _, f := range fams {
		for _, sd := range seeds {
			add(f + "_" + sd)
		}
		for _, m := range relationModifiers {
			add(f + "_" + m)
		}
	}
	// Then everything the generic expansion would have produced, minus what is
	// already here. Nothing is lost: this reorders, it does not replace.
	for _, c := range RelationCandidates(seeds, max) {
		if len(out) >= max {
			break
		}
		add(c)
	}
	return out
}

// families are the prefixes that appear in two or more discovered names.
func families(discovered []string) []string {
	count := map[string]int{}
	for _, d := range discovered {
		if i := strings.IndexByte(d, '_'); i > 1 {
			count[d[:i]]++
		}
	}
	var out []string
	for p, n := range count {
		if n >= 2 {
			out = append(out, p)
		}
	}
	sort.Strings(out) // determinism: the request order is not an input
	return out
}

func RelationCandidates(seeds []string, max int) []string {
	if max <= 0 {
		return nil
	}
	// Capacity is bounded by what can actually be produced, not by the
	// caller's cap. -max-relation-probes flows straight into max, and the
	// internal "give me everything" call passed 0x7fffffff — a request for a
	// 34 GB slice that survives only because most allocators are lazy. It
	// would fail under a cgroup memory limit.
	ceiling := len(seeds) * (len(relationModifiers) + 1)
	if max < ceiling {
		ceiling = max
	}
	out := make([]string, 0, ceiling)
	seen := map[string]bool{}
	add := func(s string) {
		if len(s) < 4 || len(s) > 48 || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	// n-1 stems: cheap, and the only thing that reaches a name whose plural
	// differs by one character.
	for _, s := range seeds {
		if len(s) > 5 {
			add(s[:len(s)-1])
		}
	}
	// modifier + singular noun.
	for _, m := range relationModifiers {
		for _, s := range seeds {
			if len(s) < 4 || len(s) > 20 {
				continue
			}
			add(m + "_" + strings.TrimSuffix(s, "s"))
		}
	}
	sort.Strings(out)
	out = dedup(out)
	// Sampled across the list: cutting at the front keeps only the
	// alphabetically first prefixes, so a binding cap made whole families of
	// names (update_*, verify_*, write_*) unreachable.
	out = sample.Take(out, max)
	sort.Strings(out)
	if len(out) == 0 {
		// nil rather than an empty slice, matching Compose. This codebase
		// treats the two as different everywhere else — nil is "nothing was
		// produced", empty is "something ran and produced none" — and a
		// generator that disagrees with its neighbour invites the caller to
		// guess which convention applies.
		return nil
	}
	return out
}

// RelationModifierCount reports how many modifiers RelationCandidates pairs
// with each seed, so a caller can size the untruncated candidate list without
// asking for an absurd allocation.
func RelationModifierCount() int { return len(relationModifiers) }
