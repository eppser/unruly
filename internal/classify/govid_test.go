package classify_test

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/classify"
)

// National identifiers, recovered from the VALUE, and only where the value can
// be proven rather than guessed.
//
// The held-out set showed the gap this closes: a column called 身份证 teaches
// the name table nothing, so an 18-digit Chinese resident-identity number read
// as "data with nothing recognised in it". The fix is not to learn the word --
// there are a hundred languages and the next schema uses a different one -- it
// is that the number carries an ISO 7064 mod 11-2 check character, so it can be
// VERIFIED without knowing what any column is called.
//
// Every scheme here was chosen for that property. A US SSN is deliberately
// absent: it has no checksum, so any nine digits would tag as a government
// identifier and a table of order numbers would go critical. That is the same
// line the card rule already draws with Luhn.
func TestGovernmentIDsAreRecoveredFromTheValue(t *testing.T) {
	for _, tc := range []struct {
		name, val string
		want      bool
	}{
		// Chinese resident identity, ISO 7064 mod 11-2. The last character is
		// the check, and X stands for a remainder of 10.
		{"chinese resident id", "11010519491231002X", true},
		{"chinese resident id, numeric check", "440524199001010018", true},
		{"chinese resident id, check character wrong", "11010519491231002Y", false},
		{"chinese resident id, one digit altered", "11010519491231003X", false},
		{"chinese resident id, impossible birth month", "110105194913310028", false},

		// Brazilian CPF, two check digits mod 11.
		{"cpf", "529.982.247-25", true},
		{"cpf unpunctuated", "52998224725", true},
		{"cpf with a bad check digit", "52998224726", false},
		{"cpf of repeated digits", "11111111111", false},

		// Polish PESEL is deliberately NOT implemented, and this is the case
		// that decided it: its check is a single mod-10 digit, so roughly one
		// in ten arbitrary eleven-digit strings satisfies it. On a column of
		// order numbers that is a false critical every tenth row. CPF survives
		// the same test because it carries TWO check digits -- about one in a
		// hundred and twenty -- and rejects repeated-digit sequences outright.
		{"pesel, valid but not claimed", "44051401359", false},

		// Negative controls. These are the strings a scanner meets constantly,
		// and tagging any of them would make the severity column untrustworthy.
		{"order number", "10010519491231002", false},
		{"unix timestamp", "1758312000", false},
		{"phone digits", "+55 11 98765-4321", false},
		{"product code", "SKU-0001-AA", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kinds := classify.Kinds([]map[string]any{{"c": tc.val}})
			got := false
			for _, k := range kinds {
				if k == "government-id" {
					got = true
				}
			}
			if got != tc.want {
				t.Errorf("%q -> %v, want government-id=%v", tc.val, kinds, tc.want)
			}
		})
	}
}

// A phone number is contact data, and it is the one shape here with no
// checksum to lean on. The rule is therefore structural in a different way: a
// leading +, a real country calling code, and a digit count inside what E.164
// permits. Bare national digits are NOT matched -- "5511987654321" with no plus
// is indistinguishable from an identifier, and guessing there is how a
// precision claim dies.
func TestPhoneNumbersAreRecoveredOnlyInE164Form(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"+55 11 98765-4321", true},
		{"+442071838750", true},
		{"+1 (415) 555-2671", true},
		{"+49 30 901820", true},
		{"5511987654321", false}, // no plus: could be anything
		{"+999123456789", false}, // not an assigned calling code
		{"+1", false},            // too short to be a number
		{"+123456789012345678", false},
		{"order +1 more", false},
	} {
		t.Run(tc.val, func(t *testing.T) {
			kinds := classify.Kinds([]map[string]any{{"c": tc.val}})
			got := strings.Contains(strings.Join(kinds, ","), "contact")
			if got != tc.want {
				t.Errorf("%q -> %v, want contact=%v", tc.val, kinds, tc.want)
			}
		})
	}
}

// An issuer's length is part of its prefix, and leaving it out costs precision.
//
// Found by collision: 440524188001010014 is a validly-formed Chinese resident
// identity number that also passes Luhn and starts with 4, so it was reported
// as financial. Visa numbers are 13, 16 or 19 digits and never 18, so the
// prefix check had already seen enough to refuse it and did not ask.
func TestCardLengthIsCheckedAgainstTheIssuer(t *testing.T) {
	for _, tc := range []struct {
		name, val string
		want      bool
	}{
		{"visa, 16", "4111111111111111", true},
		{"visa, 13", "4222222222222", true},
		{"mastercard, 16", "5500005555555559", true},
		{"amex, 15", "374245455400126", true},

		// Luhn-valid and prefixed like an issuer, at a length that issuer does
		// not use. Every one of these is a false financial tag today.
		{"18 digits behind a visa prefix", "440524188001010014", false},
		{"14 digits behind a visa prefix", "42222222222226", false},
		{"16 digits behind an amex prefix", "3742454554001264", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kinds := classify.Kinds([]map[string]any{{"c": tc.val}})
			got := false
			for _, k := range kinds {
				if k == "financial" {
					got = true
				}
			}
			if got != tc.want {
				t.Errorf("%q -> %v, want financial=%v", tc.val, kinds, tc.want)
			}
		})
	}
}
