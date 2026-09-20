// Package classify names the KINDS of sensitive data in sampled values.
//
// The scanner already classified sensitivity by COLUMN NAME: a column called
// password is a credential, one called iban is financial. That works well and
// has one systematic blind spot -- every pattern is English. A schema written
// in German (passwort, kreditkarte), or one that simply uses generic names
// (notes, payload, data, value), yields no tags at all, so a readable relation
// full of card numbers is rated "data with nothing recognised in it" rather
// than critical. For a tool whose first requirement is that it work against ANY
// project, that is not a missing nicety; it is a severity that is systematically
// too low outside the anglophone web.
//
// This package looks at what the scan already retrieved. It sends no requests,
// stores nothing, and returns kinds -- never values. A finding that says "this
// table contains card numbers" is evidence; one that quotes the number is a
// second copy of the leak.
//
// PRECISION IS THE WHOLE DESIGN. A false "financial" tag on a table of order
// IDs teaches an operator to distrust the severity column, and a severity
// nobody trusts is worse than none. So every rule here is structural rather
// than statistical: a card number must pass Luhn AND carry a real issuer
// prefix, an IBAN must satisfy mod-97, a JWT's header must actually decode to
// JSON naming an algorithm. Rules that cannot be checked that way are not
// included, however tempting.
package classify

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/eppser/unruly/internal/creds"
)

// Kinds returns the sorted, deduplicated kinds found anywhere in rows.
//
// The kinds match the vocabulary the column-name classifier already uses --
// credential, financial, pii -- so the two can be merged without translation.
func Kinds(rows []map[string]any) []string {
	seen := map[string]bool{}
	for _, row := range rows {
		for _, v := range row {
			for _, k := range kindsOf(stringify(v)) {
				seen[k] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stringify renders a sampled value for inspection.
//
// Nested objects and arrays are flattened to their JSON text rather than
// skipped: a JSONB column holding {"card": "4111..."} is exactly the shape this
// package exists to catch, and it is also the shape a column-name rule can
// never see, because the sensitive name is inside the value.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case map[string]any, []any:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	default:
		return fmt.Sprint(t)
	}
}

func kindsOf(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	if isCredential(s) {
		out = append(out, "credential")
	}
	if isFinancial(s) {
		out = append(out, "financial")
	}
	if isContact(s) {
		// An email address is contact data. It was labelled "pii", which is
		// true but less useful: under the refined vocabulary pii means the
		// identity attributes a name rule finds, and putting an email under
		// both would make the two classifiers disagree about the same value.
		out = append(out, "contact")
	}
	return out
}

// Credential shapes are NOT defined here. They live in internal/creds, which
// exists so a shape added for one channel reaches every channel that looks for
// credentials -- the live site, its bundles, public archives, preview
// deployments, and now sampled database rows. The audit enforces that, and it
// caught this file trying to keep a second copy.
//
// The rule earns its place immediately: a service_role key sitting in a
// database ROW is now recognised by exactly the patterns that recognise one in
// a JS bundle, rather than by whatever this file happened to remember.

func isCredential(s string) bool {
	for _, re := range creds.SecretMaterial {
		if re.MatchString(s) {
			return true
		}
	}
	// The JWT shape needs its header decoded before it means anything, which
	// creds.IsJWT does: dotted base64 is common in sampled rows.
	for _, m := range creds.JWT.FindAllString(s, -1) {
		if creds.IsJWT(m) {
			return true
		}
	}
	return false
}

var (
	reCardish = regexp.MustCompile(`\b(?:[0-9][ -]?){12,18}[0-9]\b`)
	reIBAN    = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b`)
)

func isFinancial(s string) bool {
	for _, m := range reCardish.FindAllString(s, -1) {
		if isCardNumber(strings.NewReplacer(" ", "", "-", "").Replace(m)) {
			return true
		}
	}
	for _, m := range reIBAN.FindAllString(s, -1) {
		if isIBAN(m) {
			return true
		}
	}
	return false
}

// isCardNumber requires BOTH a real issuer prefix and a valid Luhn check.
//
// Luhn alone is not enough and the arithmetic says why: one in ten random digit
// strings passes it. A table of sixteen-digit order numbers would report as
// financial roughly every tenth row, which is precisely the false positive that
// makes a severity column worthless.
func isCardNumber(d string) bool {
	if len(d) < 13 || len(d) > 19 || !issuerPrefix(d) {
		return false
	}
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if n < 0 || n > 9 {
			return false
		}
		if alt {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// issuerPrefix reports whether d begins with a range an issuer actually uses.
func issuerPrefix(d string) bool {
	two := d[:2]
	switch {
	case d[0] == '4': // Visa
		return true
	case two >= "51" && two <= "55": // Mastercard
		return true
	case two == "34" || two == "37": // American Express
		return true
	case strings.HasPrefix(d, "6011") || two == "65": // Discover
		return true
	case two == "36" || two == "38": // Diners
		return true
	case strings.HasPrefix(d, "35"): // JCB
		return true
	}
	// Mastercard's 2-series, which is a numeric RANGE rather than a prefix.
	if len(d) >= 4 {
		if n := d[:4]; n >= "2221" && n <= "2720" {
			return true
		}
	}
	return false
}

// isIBAN applies the mod-97 check the standard defines.
func isIBAN(s string) bool {
	r := s[4:] + s[:4]
	rem := 0
	for _, ch := range r {
		var v int
		switch {
		case ch >= '0' && ch <= '9':
			v = int(ch - '0')
		case ch >= 'A' && ch <= 'Z':
			v = int(ch-'A') + 10
		default:
			return false
		}
		if v > 9 {
			rem = (rem*100 + v) % 97
		} else {
			rem = (rem*10 + v) % 97
		}
	}
	return rem == 1
}

// reEmail is deliberately anchored: the WHOLE value must be an address.
//
// That anchoring is the discrimination this package was hardest to get right.
// An address inside prose -- "questions? write to hello@acme.example" -- is a
// website's contact copy, and a scanner that calls that a personal-data leak
// will report one on almost every marketing page it meets. An address that IS
// the value of a field is a record about a person.
var reEmail = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)

// documentation domains reserved by RFC 2606 and RFC 6761. Seed and demo data
// use them precisely because they can never belong to a real person.
var reservedDomains = []string{
	".example", "example.com", "example.org", "example.net",
	".invalid", ".test", ".localhost", "@localhost",
}

func isContact(s string) bool {
	v := strings.TrimSpace(s)
	if !reEmail.MatchString(v) {
		return false
	}
	low := strings.ToLower(v)
	for _, d := range reservedDomains {
		if strings.HasSuffix(low, d) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Classification by NAME.
//
// The counterpart to Kinds, which classifies by value. Names are cheaper --
// they need no rows retrieved, which matters where retrieving them would mean
// copying somebody's data to prove a point the key names already prove -- and
// they are language-bound, which is why both exist.

var sensitivePatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	// ORDER MATTERS: the first match wins, so the more specific rule comes
	// first. "email_address" must be contact and not location; a passport
	// number must be a government identifier and not a generic identity
	// attribute.

	// --- credential ---
	//
	// Any column whose name ENDS in _token, plus a bare "token". The rule was
	// a fixed prefix list (access|refresh|api|auth|bearer|session|csrf), which
	// missed every token Supabase's own auth schema uses --
	// confirmation_token, recovery_token, email_change_token -- along with
	// reset_token, verification_token, invite_token and magic_token. A
	// relation exposing those was reported high rather than critical, which
	// understates a credential leak.
	//
	// Anchored on the SUFFIX on purpose. Plural and prefixed forms are counts,
	// not secrets, and they are everywhere in LLM-adjacent schemas:
	// max_tokens, total_tokens, prompt_tokens, token_count, tokens_used. This
	// project's own reference target is in that domain, so flagging them would
	// be a false positive on the first real database it met.
	{regexp.MustCompile(`(?i)(^|_)token$`), "credential"},
	{regexp.MustCompile(`(?i)^jwt$|_jwt$|jwt_`), "credential"},
	{regexp.MustCompile(`(?i)(signing|encryption|secret|master)[_-]?key`), "credential"},
	{regexp.MustCompile(`(?i)(otp|totp|mfa|2fa)([_-]?(code|secret))?$`), "credential"},
	{regexp.MustCompile(`(?i)(recovery|backup)[_-]?code`), "credential"},
	{regexp.MustCompile(`(?i)(password|passwd|pwd|secret|private[_-]?key|api[_-]?key)`), "credential"},
	{regexp.MustCompile(`(?i)(hash|salt)$`), "credential"},

	// --- financial ---
	{regexp.MustCompile(`(?i)(credit[_-]?card|card[_-]?number|iban|cvv)`), "financial"},
	{regexp.MustCompile(`(?i)(bank[_-]?account|routing[_-]?number|sort[_-]?code|swift[_-]?code)`), "financial"},

	// --- government-id ---
	//
	// Split out of "pii", where these used to sit, because the consequence is
	// different in kind rather than in degree: a leaked email address is a
	// nuisance and a leaked passport number is an identity-theft primitive.
	// Several are separately regulated. A report that calls both "personal
	// details" makes the operator work out which one they have.
	{regexp.MustCompile(`(?i)(ssn|social[_-]?security)`), "government-id"},
	{regexp.MustCompile(`(?i)(tax[_-]?id|passport)`), "government-id"},
	{regexp.MustCompile(`(?i)(national[_-]?id|driver[s]?[_-]?licen[cs]e)`), "government-id"},

	// --- health ---
	//
	// Previously impossible to report at all: the renderer had a phrase for
	// health data and no rule has ever produced the label, so the phrase was
	// decoration. Deliberately narrow -- "condition", "treatment" and "status"
	// are ordinary business words and are not here, whatever they sometimes
	// hold.
	{regexp.MustCompile(`(?i)(^|_)(diagnos[ei]s|icd[_-]?(9|10|11))(_|$)`), "health"},
	{regexp.MustCompile(`(?i)(^|_)(medication|prescription|allerg(y|ies))(_|$)`), "health"},
	{regexp.MustCompile(`(?i)(^|_)(blood[_-]?type|blood[_-]?group)(_|$)`), "health"},
	{regexp.MustCompile(`(?i)(^|_)medical[_-]?record`), "health"},

	// --- contact ---
	//
	// Before location, so "email_address" is an email rather than an address.
	{regexp.MustCompile(`(?i)(^|_)(e[_-]?mail|email)([_-]?address)?$`), "contact"},
	{regexp.MustCompile(`(?i)(^|_)(phone|mobile|msisdn)([_-]?(number|no))?$`), "contact"},

	// --- location ---
	{regexp.MustCompile(`(?i)(^|_)address$|(^|_)address_`), "location"},
	{regexp.MustCompile(`(?i)(post[_-]?code|zip[_-]?code|postal[_-]?code)`), "location"},
	{regexp.MustCompile(`(?i)(^|_)(latitude|longitude|lat|lng|lon)$`), "location"},

	// --- pii ---
	//
	// Personal identity attributes not covered above. The name rules are new:
	// the report's own phrase promised "names" and no rule detected one.
	//
	// Anchored to a QUALIFIED name. A bare "name" is a product, a file, a
	// table, a column, a branch -- matching it would fire on very nearly every
	// schema in existence, and a classifier that fires everywhere says
	// nothing.
	{regexp.MustCompile(`(?i)(^|_)(first|last|full|sur|given|family|middle|maiden)[_-]?name$`), "pii"},
	{regexp.MustCompile(`(?i)^surname$`), "pii"},
	{regexp.MustCompile(`(?i)(date[_-]?of[_-]?birth|birth[_-]?date|^dob$)`), "pii"},
}

// notPersonal names things that end in a sensitive-looking word while
// identifying a machine, a mailbox or a blockchain account rather than a
// person.
//
// ip_address, mac_address, wallet_address and contract_address were all
// classified as personal data, which is a false positive in the column an
// operator uses to decide what to worry about first. RE2 has no lookbehind,
// so the exclusion is a separate expression rather than a negative assertion
// inside the address rule.
var notPersonal = regexp.MustCompile(`(?i)(^|_)(ip|ipv4|ipv6|mac|email|e[_-]?mail|wallet|contract|host|server|network|onion|bitcoin|btc|eth)[_-]?address$`)

// valueKinds are the classes the VALUE classifier can produce. Listed rather
// than inferred, because kindsOf is a chain of ifs and a class added there
// without being added here would go unrendered.
var valueKinds = []string{"contact", "credential", "financial"}

// Vocabulary returns every class either classifier can emit, sorted.
//
// The authoritative answer to "what kinds of data does this tool report". It
// exists so the renderer can be checked AGAINST the classifiers rather than
// maintained alongside them: internal/finding offered phrases for three
// classes -- contact, location, health -- that nothing had ever produced, and
// nothing could see that because the two lists were written in different
// packages and compared by nobody.
func Vocabulary() []string {
	seen := map[string]bool{}
	for _, p := range sensitivePatterns {
		seen[p.label] = true
	}
	for _, k := range valueKinds {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Names returns "name:kind" for each name matching a rule.
//
// Used for database columns, for Realtime Database key names, and for
// Firestore collection names: all four are a caller telling you what a thing
// holds, and none of them require reading what it holds.
func Names(names []string) []string {
	var out []string
	for _, c := range names {
		// Match on the LEAF, report the PATH. Every pattern here is anchored on
		// the start or end of a name -- (^|_)token$, ^jwt$|_jwt$ -- so matching
		// them against a dotted path silently stops working: "profile.jwt" has
		// neither ^jwt nor _jwt. Classifying the last segment keeps the anchors
		// meaning what they were written to mean, while the operator still gets
		// the full path and can find the value.
		leaf := c
		if i := strings.LastIndexAny(leaf, "."); i >= 0 {
			leaf = leaf[i+1:]
		}
		// Checked before the contact rule, which would otherwise claim
		// "email_address" for itself and hide the exclusion from every other
		// rule that needs it.
		if notPersonal.MatchString(leaf) && !strings.HasPrefix(strings.ToLower(leaf), "email") &&
			!strings.HasPrefix(strings.ToLower(leaf), "e_mail") {
			continue
		}
		for _, p := range sensitivePatterns {
			if p.re.MatchString(leaf) {
				out = append(out, c+":"+p.label)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
