package wordlist

import (
	"strings"
	"testing"
	"unicode"
)

// The pinned list is not only English.
//
// Measured on the benchmark corpus: 10-nonlatin-names scored 7% relation
// recall, one of fourteen, against 100% precision everywhere. That project
// ships no application, so nothing can be harvested and the pinned list is the
// entire recall -- and every name in it was English, so a schema whose tables
// are called пользователи or 顧客 was invisible by construction.
//
// This does not assert the corpus's own names. Fitting a wordlist to a
// benchmark measures agreement with the benchmark; what is asserted is that
// the ordinary word for an ordinary thing exists in several alphabets, and
// what that buys is then measured rather than claimed.
func TestRelationsCoverMoreThanEnglish(t *testing.T) {
	rel := Relations()
	var nonASCII int
	scripts := map[string]bool{}
	for _, r := range rel {
		if isASCIIWord(r) {
			continue
		}
		nonASCII++
		for _, c := range r {
			switch {
			case unicode.Is(unicode.Han, c):
				scripts["han"] = true
			case unicode.Is(unicode.Hiragana, c), unicode.Is(unicode.Katakana, c):
				scripts["kana"] = true
			case unicode.Is(unicode.Cyrillic, c):
				scripts["cyrillic"] = true
			case unicode.Is(unicode.Latin, c) && c > 127:
				scripts["latin-accented"] = true
			}
		}
	}
	if nonASCII == 0 {
		t.Fatal("every pinned relation name is ASCII, so a schema in any other " +
			"alphabet is unreachable whenever there is no application to harvest")
	}
	for _, want := range []string{"han", "cyrillic", "latin-accented"} {
		if !scripts[want] {
			t.Errorf("no %s name in the pinned list", want)
		}
	}
	// Bounded on purpose: every name is a request against somebody's project.
	if share := float64(nonASCII) / float64(len(rel)); share > 0.35 {
		t.Errorf("%.0f%% of the list is non-ASCII (%d of %d); this is a supplement "+
			"for schemas that are not in English, not a translation of the whole "+
			"list, and every entry costs a request on every scan",
			share*100, nonASCII, len(rel))
	}
	t.Logf("%d of %d pinned names are not ASCII, across %d scripts",
		nonASCII, len(rel), len(scripts))
}

func isASCIIWord(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return !strings.HasPrefix(s, "#")
}
