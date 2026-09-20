package provider

import (
	"testing"

	"github.com/eppser/unruly/internal/finding"
)

// The same question must get the same answer whichever backend asked it.
//
// A Supabase relation with a column called password is critical. A Realtime
// Database path whose keys are api_key and password was high, and a Firestore
// collection was high whatever it was called -- not because anyone decided
// Firebase data matters less, but because the classifier lived in the Supabase
// package and the provider could not reach it. An operator running one tool
// across two backends would have read that difference as a judgement.
//
// Neither surface retrieves values to do this, and neither should: RTDB is
// probed with ?shallow=true and Firestore keeps only document IDs, so the key
// names are already in hand. Proving a path is readable does not require
// copying what is inside it.
func TestFirebaseSeverityUsesKeyNamesLikeSupabaseUsesColumnNames(t *testing.T) {
	const host = "https://lab-default-rtdb.europe-west1.firebasedatabase.app"

	t.Run("sensitive keys lift the severity", func(t *testing.T) {
		f := rtdbFinding(host, "/config", []string{"api_key", "region", "signing_key"}, false)
		if f.Severity != finding.Critical {
			t.Errorf("a readable path whose keys are api_key and signing_key was rated "+
				"%v: the same names in a Supabase column list are critical", f.Severity)
		}
		if f.Evidence.Reason == "" {
			t.Error("the finding does not say which key names earned the rating")
		}
	})

	t.Run("ordinary keys do not", func(t *testing.T) {
		f := rtdbFinding(host, "/posts", []string{"title", "slug", "published"}, false)
		if f.Severity != finding.High {
			t.Errorf("a readable path of presentation keys was rated %v, not high: "+
				"promoting everything would make the rating meaningless", f.Severity)
		}
	})

	t.Run("a readable root stays critical regardless", func(t *testing.T) {
		f := rtdbFinding(host, "/", []string{"posts"}, true)
		if f.Severity != finding.Critical {
			t.Errorf("a readable root was rated %v: the whole database is exposed "+
				"whatever the keys are called", f.Severity)
		}
	})
}

// The same rule for Firestore, where the collection NAME is the signal.
//
// Document identifiers are deliberately not classified: they are generated,
// and a UUID says nothing about what it points at. Rating a collection by its
// document IDs would be rating it by noise.
func TestFirestoreSeverityUsesTheCollectionName(t *testing.T) {
	d := Detection{Provider: "firebase", Project: "lab"}
	const base = "https://firestore.googleapis.com/v1/projects/lab/databases/(default)/documents"

	f := firestoreReadFinding(d, base, "k", "user_passwords", []string{"doc1"}, ScanOptions{})
	if f.Severity != finding.Critical {
		t.Errorf("a readable collection called user_passwords was rated %v", f.Severity)
	}
	f = firestoreReadFinding(d, base, "k", "blog_posts", []string{"doc1"}, ScanOptions{})
	if f.Severity != finding.High {
		t.Errorf("a readable collection called blog_posts was rated %v, not high", f.Severity)
	}
	// A generated document id must not decide anything.
	f = firestoreReadFinding(d, base, "k", "posts",
		[]string{"6f1c2b7e-6f7a-4a1e-9a2a-1b0d5f9c3e21", "password"}, ScanOptions{})
	if f.Severity != finding.High {
		t.Errorf("a document IDENTIFIER changed the rating (%v): identifiers are "+
			"generated and say nothing about what they point at", f.Severity)
	}
}
