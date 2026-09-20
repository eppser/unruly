package classify

import (
	"reflect"
	"strings"
	"testing"
)

// The class a column name is given, in both directions.
//
// Every entry here is a decision about what a report will SAY, and the
// negative half is the more important one: a false "health" or "financial" tag
// teaches an operator to distrust the whole column, and a severity nobody
// trusts is worse than none.
func TestColumnNamesAreClassified(t *testing.T) {
	for _, c := range []struct {
		column string
		want   string // "" means: must not be classified at all
	}{
		// Credentials.
		{"password", "credential"},
		{"password_hash", "credential"},
		{"access_token", "credential"},
		{"recovery_token", "credential"},
		{"totp_secret", "credential"},
		{"backup_code", "credential"},
		// Counts that merely contain "token" are not secrets, and this
		// project's own reference target is full of them.
		{"max_tokens", ""},
		{"prompt_tokens", ""},
		{"token_count", ""},

		// Financial.
		{"credit_card", "financial"},
		{"iban", "financial"},
		{"routing_number", "financial"},
		{"cvv", "financial"},

		// Government identifiers, separated from ordinary personal data
		// because the consequence is different: these are the ones that
		// enable identity theft, and several are separately regulated.
		{"ssn", "government-id"},
		{"social_security_number", "government-id"},
		{"passport_number", "government-id"},
		{"tax_id", "government-id"},
		{"drivers_license", "government-id"},
		{"national_id", "government-id"},

		// Contact.
		{"email", "contact"},
		{"email_address", "contact"},
		{"phone", "contact"},
		{"mobile", "contact"},
		{"msisdn", "contact"},

		// Location.
		{"address", "location"},
		{"home_address", "location"},
		{"postcode", "location"},
		{"zip_code", "location"},
		{"latitude", "location"},
		{"longitude", "location"},
		// Things that end in "address" and identify a machine, a mailbox or a
		// blockchain account rather than where a person lives. Every one of
		// these was classified as personal data before.
		{"ip_address", ""},
		{"mac_address", ""},
		{"wallet_address", ""},
		{"contract_address", ""},

		// Health. Regulated separately nearly everywhere, and previously
		// impossible to report at all: the phrase existed and no rule did.
		{"diagnosis", "health"},
		{"medication", "health"},
		{"prescription", "health"},
		{"blood_type", "health"},
		{"allergies", "health"},
		{"medical_record_number", "health"},
		// Generic business words that a health rule must not swallow.
		{"condition", ""},
		{"treatment_cost", ""},
		{"status", ""},

		// Identity attributes. "names" were promised in the report's own
		// phrasing and NO rule detected them.
		{"first_name", "pii"},
		{"last_name", "pii"},
		{"full_name", "pii"},
		{"surname", "pii"},
		{"maiden_name", "pii"},
		{"date_of_birth", "pii"},
		{"dob", "pii"},
		// A bare "name" is a product, a file, a table, a column. Matching it
		// would fire on nearly every schema in existence.
		{"name", ""},
		{"file_name", ""},
		{"display_name", ""},
	} {
		t.Run(c.column, func(t *testing.T) {
			got := Names([]string{c.column})
			if c.want == "" {
				if len(got) != 0 {
					t.Errorf("Names([%q]) = %v, want nothing: this name does not identify a person",
						c.column, got)
				}
				return
			}
			want := c.column + ":" + c.want
			if !reflect.DeepEqual(got, []string{want}) {
				t.Errorf("Names([%q]) = %v, want [%q]", c.column, got, want)
			}
		})
	}
}

// Every label a pattern produces is in the published vocabulary.
//
// A pattern carrying a label Vocabulary() does not list would be found by the
// scanner and dropped by the renderer, which has no phrase for it.
func TestEveryPatternLabelIsInTheVocabulary(t *testing.T) {
	vocab := map[string]bool{}
	for _, v := range Vocabulary() {
		vocab[v] = true
	}
	for _, p := range sensitivePatterns {
		if !vocab[p.label] {
			t.Errorf("pattern %v produces label %q, absent from Vocabulary()", p.re, p.label)
		}
	}
	for _, k := range valueKinds {
		if !vocab[k] {
			t.Errorf("valueKinds names %q, absent from Vocabulary()", k)
		}
	}
}

// A class is never the matched text.
func TestVocabularyIsKindsNotValues(t *testing.T) {
	for _, v := range Vocabulary() {
		if strings.ContainsAny(v, " 0123456789") {
			t.Errorf("vocabulary entry %q looks like data rather than a kind", v)
		}
	}
}
