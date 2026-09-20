package postgrest

import "testing"

// A hint the target volunteered must not be thrown away for its alphabet.
//
// The hint oracle is the mechanism that recovers domain-specific names no
// wordlist can hold: ask for a near miss, and PostgREST answers "Perhaps you
// meant the table 'public.X'". Measured against the benchmark corpus, that
// works perfectly well for non-Latin schemas -- bestellungen draws
// bestellübersicht, benutzer draws benutzer_顧客_данные -- and every one of
// those answers was then discarded, because the guard on the extracted name
// was [A-Za-z0-9_$].
//
// So the target named its own tables, in a response this scanner asked for,
// and the scanner dropped them. That is the single most expensive line in the
// non-Latin gap: the wordlist can be extended forever and the oracle is what
// reaches the compounds.
func TestHintedRelationAcceptsEveryAlphabet(t *testing.T) {
	for _, tc := range []struct{ hint, want string }{
		{"Perhaps you meant the table 'public.bestellübersicht'", "bestellübersicht"},
		{"Perhaps you meant the table 'public.benutzer_顧客_данные'", "benutzer_顧客_данные"},
		{"Perhaps you meant the table 'public.información_personal'", "información_personal"},
		{"Perhaps you meant the table 'public.пользователи'", "пользователи"},
		{"Perhaps you meant the table 'public.𝕂𝕒𝕣𝕥𝕖'", "𝕂𝕒𝕣𝕥𝕖"},
		{"Perhaps you meant the table 'public.Ünïcödé'", "Ünïcödé"},
	} {
		got, ok := HintedRelation(tc.hint)
		if !ok || got != tc.want {
			t.Errorf("HintedRelation(%q) = %q,%v; the target volunteered this name and "+
				"the scan discarded it", tc.hint, got, ok)
		}
	}
}

// And the guard still refuses what it was built to refuse.
//
// The set is narrow because a scanned host controls this string. Two real
// attempts got through an earlier version: a name carrying
// ?select=*&limit=999999, and one using ../ to escape the PostgREST path onto
// other endpoints. Widening the alphabet must not widen the punctuation.
func TestHintedRelationStillRefusesWhatAHostileHostSends(t *testing.T) {
	for _, hint := range []string{
		"Perhaps you meant the table 'public.orders?select=*&limit=999999'",
		"Perhaps you meant the table 'public.../../../etc/passwd'",
		"Perhaps you meant the table 'public.my table'",
		"Perhaps you meant the table 'public.orders;drop'",
		"Perhaps you meant the table 'public.'",
	} {
		if got, ok := HintedRelation(hint); ok {
			t.Errorf("HintedRelation(%q) = %q; this string goes into a URL path and "+
				"the host chose it", hint, got)
		}
	}
	// Postgres stores at most 63 BYTES, so a name longer than that cannot be
	// one and asking for it spends a request on an impossibility.
	long := "Perhaps you meant the table 'public." + string(make([]byte, 0)) + ""
	for i := 0; i < 30; i++ {
		long += "客"
	}
	long += "'"
	if _, ok := HintedRelation(long); ok {
		t.Error("a 90-byte name was accepted; Postgres cannot store one")
	}
}
