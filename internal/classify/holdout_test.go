package classify_test

import (
	"testing"

	"github.com/eppser/unruly/internal/classify"
)

// A held-out set, written without the rule table open.
//
// The scored corpus measures data classification at n=9, which is too small a
// denominator to notice a systematic blind spot. This set is deliberately
// hostile in the way the real web is: column names in German, French, Spanish,
// Portuguese, Japanese and Chinese, and generic English names -- payload,
// notes, value, data -- that carry anything at all.
//
// It exists to answer one question with a number: when the NAME teaches
// nothing, how often does the VALUE still give the class away? Every name here
// is unrecognised by design -- Names() scores zero on all of them -- so the
// figure is the value rules alone.
//
// The first draft of this file reported 47%, and it was wrong: a bcrypt hash
// one character short of the 53 the format requires, and a JWT whose signature
// segment was the literal "sig". Both were my fixtures, not the rules. A
// held-out set whose own data is malformed measures the person who wrote it.
var holdout = []struct {
	col, val, want string
}{
	// German
	{"passwort", "$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", "credential"},
	{"kreditkarte", "4111111111111111", "financial"},
	{"bankverbindung", "DE89370400440532013000", "financial"},
	{"diagnose", "Typ-2-Diabetes, Metformin 500mg", "health"},
	{"anschrift", "Hauptstrasse 14, 10115 Berlin", "pii"},
	// French
	{"mot_de_passe", "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG", "credential"},
	{"numero_carte", "5500005555555559", "financial"},
	{"adresse_postale", "12 rue de Rivoli, 75001 Paris", "pii"},
	// Spanish / Portuguese
	{"contrasena", "$2y$10$3euPcmQFCiblsZeEu5s7p.9OVHgeHWFwrjHoo6SbxLdCF7dmtGrWO", "credential"},
	{"tarjeta", "4012888888881881", "financial"},
	{"telefone", "+55 11 98765-4321", "pii"},
	// Japanese / Chinese romanised and native
	{"パスワード", "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", "credential"},
	{"身份证", "11010519491231002X", "gov-id"},
	// Generic names carrying anything
	{"payload", `{"api_key":"sb_secret_abcdef123456"}`, "credential"},
	{"notes", "IBAN GB82WEST12345698765432 for the refund", "financial"},
	{"value", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.QUJDREVGR0hJSktMTU5PUA", "credential"},
	{"data", "4242424242424242", "financial"},
	{"meta", "no sensitive content at all", ""},
	{"col_a", "ordinary product description text", ""},
	{"col_b", "12345", ""},
}

func TestHeldOutNamesAndValues(t *testing.T) {
	var nameHits, valueHits, either, total, negatives, falsePos int
	for _, tc := range holdout {
		if tc.want == "" {
			negatives++
			if len(classify.Kinds([]map[string]any{{tc.col: tc.val}})) > 0 ||
				len(classify.Names([]string{tc.col})) > 0 {
				falsePos++
				t.Logf("FALSE POSITIVE  %-16s -> %v / %v", tc.col,
					classify.Names([]string{tc.col}), classify.Kinds([]map[string]any{{tc.col: tc.val}}))
			}
			continue
		}
		total++
		byName := len(classify.Names([]string{tc.col})) > 0
		byValue := len(classify.Kinds([]map[string]any{{tc.col: tc.val}})) > 0
		if byName {
			nameHits++
		}
		if byValue {
			valueHits++
		}
		if byName || byValue {
			either++
		} else {
			t.Logf("MISS  %-16s want %-10s val=%.40q", tc.col, tc.want, tc.val)
		}
	}
	recall := 100 * float64(either) / float64(total)
	t.Logf("held-out positives=%d  by-name=%d  by-value=%d  either=%d (%.0f%%)",
		total, nameHits, valueHits, either, recall)
	t.Logf("negatives=%d  false-positives=%d", negatives, falsePos)

	// A floor, not a target. Measured at 71%: twelve of seventeen recovered
	// from the value alone with every column name unrecognised. It is asserted
	// so a rule that stops firing is caught here rather than in a report.
	if recall < 70 {
		t.Errorf("held-out recall %.0f%%, floor 70%%: a value rule stopped firing", recall)
	}
	// Precision is the whole design of this package, so the negatives are not
	// decoration. One false tag on a held-out negative fails this outright.
	if falsePos > 0 {
		t.Errorf("%d false positive(s) on held-out negatives; precision is the claim "+
			"this package is built on", falsePos)
	}
	if nameHits > 0 {
		t.Errorf("%d held-out name(s) matched the name table, so the recall above is "+
			"not measuring the value rules alone", nameHits)
	}
}
