package main

import "testing"

// The corpus grader must read Firebase findings, not only Supabase ones.
//
// observe switches on finding ids: supabase-anon-read-exposed and its
// siblings. A Firebase scan emits firebase-firestore-anon-read and
// firebase-rtdb-anon-read, which nothing matched, so ReadExposed came back
// empty whatever the scanner found -- and 14-firebase scored 100% recall on a
// denominator of zero until the runner learned to refuse it.
//
// Refusing was the right immediate answer: a project that cannot be graded
// must not appear graded. But the refusal is a statement about this runner,
// not about the corpus, and it leaves the only Firebase project in the corpus
// contributing nothing to the accuracy claim while the mission's first line is
// "not just Supabase".
//
// The dimensions transfer unchanged. A Firestore collection is a relation for
// grading purposes: a name the scan either recovered or missed, either read or
// stayed silent about. Only the finding ids differ.
func TestObserveReadsFirebaseFindings(t *testing.T) {
	report := `{"id":"firebase-firestore-anon-read","resource":"user_profiles","evidence":{"rows":5}}
{"id":"firebase-firestore-anon-read","resource":"public_announcements","evidence":{"rows":2}}
{"id":"firebase-rtdb-anon-read","resource":"/telemetry","evidence":{"rows":1}}
{"id":"firebase-firestore-anon-write","resource":"user_profiles"}
`
	o := observe([]byte(report))

	has := func(set []string, want string) bool {
		for _, s := range set {
			if s == want {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"user_profiles", "public_announcements", "/telemetry"} {
		if !has(o.ReadExposed, want) {
			t.Errorf("%q was reported anonymously readable and is not in ReadExposed %v; "+
				"the grader reads Supabase ids only, so a Firebase scan grades as though "+
				"it found nothing", want, o.ReadExposed)
		}
	}
	if !has(o.InsertReachable, "user_profiles") {
		t.Errorf("an anonymous Firestore write was reported and is not in InsertReachable "+
			"%v", o.InsertReachable)
	}
	if o.Rows["user_profiles"] != 5 {
		t.Errorf("row count for user_profiles = %d, want 5: the sampled evidence is what "+
			"separates a relation that returned data from one that answered 200 empty",
			o.Rows["user_profiles"])
	}
}
