package classify

import (
	"reflect"
	"strings"
	"testing"
)

// The corpus is two lists, and the second one is the reason this package is
// hard. Recall against obvious secrets is easy; the difficulty is refusing the
// things that merely LOOK like them, because a severity column that cries wolf
// gets ignored, and an ignored severity column is worse than no severity column.
//
// Every negative below was chosen because a plausible implementation would get
// it wrong: Luhn without an issuer prefix flags order numbers, unanchored email
// matching flags marketing copy, shape-only JWT matching flags signed cookies.
func TestKindsRecognisesSecretsAndRefusesLookalikes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		want  []string
	}{
		// ---- credentials ------------------------------------------------
		// A full-length signature: creds.JWT requires 8+ characters in every
		// segment, and a real HS256 signature is 43. The first version of this
		// vector ended in "abc" and matched nothing, which is the shared
		// pattern being stricter than the one this file used to carry.
		{"real jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9." +
			"dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXkw", []string{"credential"}},
		{"pem private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==", []string{"credential"}},
		{"aws access key", "AKIAIOSFODNN7EXAMPLE", []string{"credential"}},
		{"bcrypt hash", "$2b$12$" + "abcdefghijklmnopqrstuv" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234", []string{"credential"}},
		{"argon2 hash", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", []string{"credential"}},
		{"stripe live key", "sk_live_abcdefghijklmnopqrstuvwx", []string{"credential"}},

		// A base64 blob with dots, which is what a signed cookie or a cache key
		// looks like. Shape-only matching calls this a token.
		{"dotted base64 that is not a jwt", "eyJub3RhandzIjoi.YWJjZGVmZw.xxxx", nil},
		// Valid base64 JSON header without an alg: not a JWT.
		{"json header without alg", "eyJ0eXAiOiJKV1QifQxx.eyJhIjoxfQxxxx." +
			"c2lnbmF0dXJlc2lnbmF0dXJl", nil},

		// ---- financial --------------------------------------------------
		{"visa", "4111111111111111", []string{"financial"}},
		{"visa spaced", "4111 1111 1111 1111", []string{"financial"}},
		{"mastercard 2-series", "2221000000000009", []string{"financial"}},
		{"amex", "378282246310005", []string{"financial"}},
		{"iban", "GB82WEST12345698765432", []string{"financial"}},

		// Sixteen digits that pass Luhn but begin with no issuer range. This is
		// the order-number case: one in ten such IDs passes Luhn by chance.
		{"luhn-valid order number", "1234567812345670", nil},
		// Still a control against the card rule -- a phone number must never be
		// financial -- but no longer "nothing". The name table has classified a
		// column called phone as contact all along, so a phone VALUE reading as
		// nothing meant the two classifiers disagreed about the same fact. This
		// expectation was written before contact was split out of pii.
		{"phone number", "+1 415 555 0132", []string{"contact"}},
		{"timestamp run", "20260819013000", nil},
		{"iban-shaped but failing mod-97", "GB82WEST12345698765433", nil},

		// ---- pii ---------------------------------------------------------
		{"email as the value", "ada@lovelace.org", []string{"contact"}},
		{"email with subaddress", "ada+news@lovelace.co.uk", []string{"contact"}},

		// Site copy. The address is real-looking but the field is prose, and
		// this is the single most common false positive available.
		{"email inside marketing copy", "Questions? Write to hello@acme.io any time.", nil},
		{"email in a support paragraph", "Contact support@vendor.com for help with billing.", nil},
		// Seed data uses reserved domains precisely because nobody owns them.
		{"documentation domain", "user@example.com", nil},
		{"invalid tld", "probe@unruly.invalid", nil},

		// ---- neither -------------------------------------------------------
		{"marketing headline", "The fastest way to ship your app", nil},
		{"uuid", "6f1c2b7e-6f7a-4a1e-9a2a-1b0d5f9c3e21", nil},
		{"empty", "", nil},
		{"number", 42, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Kinds([]map[string]any{{"col": tc.value}})
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Kinds(%v) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

// A JSONB column is where a column-name rule is blindest: the sensitive name is
// INSIDE the value, so no amount of reading the schema finds it.
func TestKindsLooksInsideNestedValues(t *testing.T) {
	rows := []map[string]any{{
		"payload": map[string]any{
			"billing": map[string]any{"number": "4111111111111111"},
		},
	}}
	if got := Kinds(rows); !reflect.DeepEqual(got, []string{"financial"}) {
		t.Errorf("nested card number not found: got %v", got)
	}
}

// The kinds are a description, never a copy. This package exists inside a
// scanner whose report is handed around in tickets and chat, and a finding that
// quotes the card number it found has published it a second time.
func TestKindsNeverReturnsTheValue(t *testing.T) {
	const card = "4111111111111111"
	for _, k := range Kinds([]map[string]any{{"c": card}}) {
		if strings.Contains(k, card) || strings.Contains(k, "4111") {
			t.Fatalf("the kind %q carries the value it describes", k)
		}
	}
}

// Deterministic and order-independent: the same rows must yield the same kinds
// in the same order, whichever order Go's map iteration hands them over in.
func TestKindsIsStable(t *testing.T) {
	rows := []map[string]any{{
		"a": "ada@lovelace.org",
		"b": "4111111111111111",
		"c": "-----BEGIN PRIVATE KEY-----",
	}}
	want := []string{"contact", "credential", "financial"}
	for i := 0; i < 50; i++ {
		if got := Kinds(rows); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d returned %v, want %v", i, got, want)
		}
	}
}
