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
	"strconv"
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
	if isGovernmentID(s) {
		out = append(out, "government-id")
	}
	if isContact(s) || isPhone(s) {
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

// issuerPrefix reports whether d begins with a range an issuer actually uses
// AND is a length that issuer actually issues.
//
// The length is part of the check, and leaving it out cost precision. A
// validly-formed Chinese resident identity number -- eighteen digits, opening
// with 4 -- passed Luhn and was reported as a card. Visa issues 13, 16 and 19
// digits and has never issued 18, so the prefix had already seen enough to
// refuse it and was not being asked.
//
// Where an issuer's range is genuinely wide the range stays wide: UnionPay and
// Maestro do run 16 to 19, and narrowing those to flatter a test would trade a
// false positive for a false negative.
func issuerPrefix(d string) bool {
	n := len(d)
	ok := func(lengths ...int) bool {
		for _, l := range lengths {
			if n == l {
				return true
			}
		}
		return false
	}
	two := d[:2]
	switch {
	case d[0] == '4': // Visa
		return ok(13, 16, 19)
	case two >= "51" && two <= "55": // Mastercard
		return ok(16)
	case two == "34" || two == "37": // American Express
		return ok(15)
	case strings.HasPrefix(d, "6011") || two == "65": // Discover
		return ok(16, 19)
	case two == "36": // Diners, international
		return ok(14, 16, 19)
	case two == "38": // Diners, carte blanche
		return ok(14)
	case strings.HasPrefix(d, "35"): // JCB
		return n >= 16 && n <= 19
	case strings.HasPrefix(d, "62"): // UnionPay
		return n >= 16 && n <= 19
	}
	// Mastercard's 2-series, which is a numeric RANGE rather than a prefix.
	if len(d) >= 4 {
		if r := d[:4]; r >= "2221" && r <= "2720" {
			return ok(16)
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

// --- national identifiers, recovered from the value ---
//
// Only schemes whose digits can be CHECKED. The held-out eval showed why the
// value has to carry the proof: a column called 身份证 teaches the name table
// nothing, and there is no finite list of words for "national identity number"
// across the languages a schema can be written in. A check character does not
// need translating.
//
// Two schemes were considered and rejected, and the reasons are the rule:
//
//   US SSN      no checksum at all, so nine digits anywhere would tag as a
//               government identifier and a table of order numbers would go
//               critical.
//   Polish PESEL a single mod-10 check digit, satisfied by roughly one in ten
//               arbitrary eleven-digit strings. CPF is kept because it carries
//               two check digits -- about one in a hundred and twenty -- and
//               rejects repeated-digit sequences.

var (
	// \b works inside JSON text too, which is where a JSONB column puts it.
	reChinaID = regexp.MustCompile(`\b\d{17}[\dXx]\b`)
	reCPF     = regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b\d{11}\b`)
)

func isGovernmentID(s string) bool {
	for _, m := range reChinaID.FindAllString(s, -1) {
		if validChinaResidentID(m) {
			return true
		}
	}
	for _, m := range reCPF.FindAllString(s, -1) {
		if validCPF(m) {
			return true
		}
	}
	return false
}

// validChinaResidentID checks the ISO 7064 MOD 11-2 character AND the birth
// date the number embeds.
//
// The check character alone leaves about a one-in-eleven collision rate, which
// is not a precision claim. Requiring positions 7..14 to be a real date closes
// most of the rest: an arbitrary eighteen-digit run has to satisfy both.
func validChinaResidentID(v string) bool {
	if len(v) != 18 {
		return false
	}
	weights := [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i := 0; i < 17; i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
		sum += int(v[i]-'0') * weights[i]
	}
	if "10X98765432"[sum%11] != strings.ToUpper(v[17:])[0] {
		return false
	}
	year, _ := strconv.Atoi(v[6:10])
	month, _ := strconv.Atoi(v[10:12])
	day, _ := strconv.Atoi(v[12:14])
	if year < 1900 || month < 1 || month > 12 || day < 1 || day > 31 {
		return false
	}
	return true
}

// validCPF checks both mod-11 digits and rejects the repeated-digit sequences
// that satisfy them arithmetically -- 111.111.111-11 passes the arithmetic and
// is not a CPF.
func validCPF(v string) bool {
	var d []int
	for _, r := range v {
		if r >= '0' && r <= '9' {
			d = append(d, int(r-'0'))
		}
	}
	if len(d) != 11 {
		return false
	}
	same := true
	for _, x := range d[1:] {
		if x != d[0] {
			same = false
			break
		}
	}
	if same {
		return false
	}
	for _, pos := range []int{9, 10} {
		sum := 0
		for i := 0; i < pos; i++ {
			sum += d[i] * (pos + 1 - i)
		}
		check := 11 - sum%11
		if check >= 10 {
			check = 0
		}
		if d[pos] != check {
			return false
		}
	}
	return true
}

// --- phone numbers ---
//
// The one shape here with no checksum, so the structure has to carry the
// weight instead: a leading +, an ITU-assigned country calling code, and a
// digit count inside what E.164 permits.
//
// Bare national digits are NOT matched. "5511987654321" is indistinguishable
// from an identifier, and a rule that guesses there would put contact data on
// every table of large integers. The same reason the card rule wants Luhn and
// an issuer prefix rather than sixteen digits.
//
// Matched against the whole value rather than searched for inside it, for the
// same reason: a bare + and a number inside free text is far more often a
// price, a diff or a version than a phone number.

// callingCodes are the assigned ITU-T E.164 country codes, longest first at
// match time. Unassigned ranges are absent on purpose: +999 must not match, or
// the "assigned code" half of the check does nothing.
var callingCodes = map[string]bool{
	"1": true, "7": true,
	"20": true, "27": true, "30": true, "31": true, "32": true, "33": true,
	"34": true, "36": true, "39": true, "40": true, "41": true, "43": true,
	"44": true, "45": true, "46": true, "47": true, "48": true, "49": true,
	"51": true, "52": true, "53": true, "54": true, "55": true, "56": true,
	"57": true, "58": true, "60": true, "61": true, "62": true, "63": true,
	"64": true, "65": true, "66": true, "81": true, "82": true, "84": true,
	"86": true, "90": true, "91": true, "92": true, "93": true, "94": true,
	"95": true, "98": true,
	"211": true, "212": true, "213": true, "216": true, "218": true,
	"220": true, "221": true, "222": true, "223": true, "224": true,
	"225": true, "226": true, "227": true, "228": true, "229": true,
	"230": true, "231": true, "232": true, "233": true, "234": true,
	"235": true, "236": true, "237": true, "238": true, "239": true,
	"240": true, "241": true, "242": true, "243": true, "244": true,
	"245": true, "248": true, "249": true, "250": true, "251": true,
	"252": true, "253": true, "254": true, "255": true, "256": true,
	"257": true, "258": true, "260": true, "261": true, "262": true,
	"263": true, "264": true, "265": true, "266": true, "267": true,
	"268": true, "269": true, "290": true, "291": true, "297": true,
	"298": true, "299": true, "350": true, "351": true, "352": true,
	"353": true, "354": true, "355": true, "356": true, "357": true,
	"358": true, "359": true, "370": true, "371": true, "372": true,
	"373": true, "374": true, "375": true, "376": true, "377": true,
	"378": true, "380": true, "381": true, "382": true, "383": true,
	"385": true, "386": true, "387": true, "389": true, "420": true,
	"421": true, "423": true, "500": true, "501": true, "502": true,
	"503": true, "504": true, "505": true, "506": true, "507": true,
	"508": true, "509": true, "590": true, "591": true, "592": true,
	"593": true, "595": true, "597": true, "598": true, "599": true,
	"670": true, "672": true, "673": true, "674": true, "675": true,
	"676": true, "677": true, "678": true, "679": true, "680": true,
	"681": true, "682": true, "683": true, "685": true, "686": true,
	"687": true, "688": true, "689": true, "690": true, "691": true,
	"692": true, "850": true, "852": true, "853": true, "855": true,
	"856": true, "880": true, "886": true, "960": true, "961": true,
	"962": true, "963": true, "964": true, "965": true, "966": true,
	"967": true, "968": true, "970": true, "971": true, "972": true,
	"973": true, "974": true, "975": true, "976": true, "977": true,
	"992": true, "993": true, "994": true, "995": true, "996": true,
	"998": true,
}

var rePhoneShape = regexp.MustCompile(`^\+[0-9][0-9 ()./-]{6,22}$`)

func isPhone(s string) bool {
	v := strings.TrimSpace(s)
	if !rePhoneShape.MatchString(v) {
		return false
	}
	var digits strings.Builder
	for _, r := range v {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	d := digits.String()
	// E.164 caps the whole number at 15 digits. The floor is 8: shorter runs
	// are service codes and abbreviations, not the subscriber numbers this is
	// looking for.
	if len(d) < 8 || len(d) > 15 {
		return false
	}
	// The phone equivalent of reservedDomains. NANP reserves the 555 central
	// office code for fiction, and seed data uses it for exactly the reason
	// seed data uses example.com: nobody owns it. Four corpus fixtures are
	// seeded with +1-555 numbers, and reporting one as a person's contact
	// details is the same false positive the reserved-domain list already
	// refuses on the email side. It costs nothing real -- a leaked customer
	// table does not contain 555 numbers.
	if strings.HasPrefix(d, "1555") {
		return false
	}
	for n := 3; n >= 1; n-- {
		if len(d) > n && callingCodes[d[:n]] {
			return true
		}
	}
	return false
}
