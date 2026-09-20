package eval_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// The commands the Firebase backend publishes must reproduce against the lab.
//
// The fixture replay in replay_test.go covers the local Supabase lab only.
// Firebase findings address Google's endpoints, so that check skips them and
// nothing else read them -- and the three evidence drifts found
// were all in code the fixture replay DOES cover, which says nothing reassuring
// about the code it does not. One of those three was the Firestore evidence
// dropping the __name__ projection, so replaying it would have retrieved the
// field values the finding says were never taken.
//
// Firestore commands are NOT replayed and the omission is counted: every one is
// a metered read on this project's own quota, the free tier is 50,000 a day,
// and a check that quietly spends somebody's budget to prove a point about
// tidiness is the wrong trade. -vocab-only keeps this scan off the pinned
// wordlist for the same reason.
func TestFirebaseExploitsPublishedRequestsReplay(t *testing.T) {
	key := os.Getenv("FIREBASE_LAB_API_KEY")
	if key == "" {
		t.Skip("set FIREBASE_LAB_API_KEY (see the Makefile target)")
	}
	rtdb := "https://firebase-lab-000000-default-rtdb.europe-west1.firebasedatabase.app"
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `<!doctype html><html><body><script>
const firebaseConfig = {
  apiKey: %q, authDomain: "firebase-lab-000000.firebaseapp.com",
  databaseURL: %q, projectId: "firebase-lab-000000",
  storageBucket: "unruly-lab-fixture-505809",
  messagingSenderId: %q, appId: %q
};
</script></body></html>`, key, rtdb,
			os.Getenv("FIREBASE_LAB_PROJECT_NUMBER"), os.Getenv("FIREBASE_LAB_APP_ID"))
	}))
	defer site.Close()

	dir := t.TempDir()
	vocab := dir + "/vocab.json"
	// Only names that cost nothing to probe: the lab's functions and its open
	// RTDB path. No collection names, so Firestore is not swept.
	seeds, _ := json.Marshal(map[string]any{
		"schema_version": 1, "stage": "vocabulary",
		// public_notes is the lab's open collection. It is here so a Firestore
		// finding EXISTS to replay: with only function and RTDB names the
		// Firestore branch was unreachable and the check reported "0 Firestore
		// commands seen", which is a category covered by arithmetic rather than
		// by measurement. -vocab-only keeps the cost to these four names.
		"seeds": []string{"publicEcho", "privateControl", "public", "public_notes"},
	})
	if err := os.WriteFile(vocab, seeds, 0o644); err != nil {
		t.Fatal(err)
	}
	report := firebaseScan(t, site.URL, []string{
		"-vocab", vocab, "-vocab-only", "-invoke", "-write", "-yes-i-own-this"})

	type ev struct {
		Request   string `json:"request"`
		Status    int    `json:"status"`
		Suggested bool   `json:"suggested"`
	}
	type line struct {
		ID       string `json:"id"`
		Evidence ev     `json:"evidence"`
	}
	var replayed, metered, templates, offers int
	var firestoreReplayed bool
	for _, raw := range strings.Split(report, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var f line
		if json.Unmarshal([]byte(raw), &f) != nil {
			continue
		}
		if !strings.HasPrefix(f.ID, "firebase-") {
			continue
		}
		req, want := f.Evidence.Request, f.Evidence.Status
		if req == "" {
			continue
		}
		if f.Evidence.Suggested {
			offers++
			continue
		}
		if strings.Contains(req, "<") || strings.Contains(req, `"..."`) {
			templates++
			continue
		}
		if strings.Contains(req, "firestore.googleapis.com") {
			// Metered: every Firestore probe is a billed read on this project's
			// own quota. One is replayed and the rest are counted, which buys
			// the end-to-end check for a single read rather than skipping the
			// category entirely -- and this is the category whose evidence
			// dropped the __name__ projection, so replaying it is exactly how
			// you find out the published command retrieves field values the
			// finding says were never taken.
			metered++
			if firestoreReplayed {
				continue
			}
			firestoreReplayed = true
		}
		if want == 0 {
			t.Errorf("%s publishes a command and not the status it answered, so nothing "+
				"can check whether it still reproduces:\n  %s", f.ID, req)
			continue
		}
		got, err := replayFirebase(t, req, key)
		if err != nil {
			t.Errorf("%s: its own published command does not run: %v\n  %s", f.ID, err, req)
			continue
		}
		replayed++
		if got != want {
			t.Errorf("%s: the report says HTTP %d and its own command returns HTTP %d.\n  %s",
				f.ID, want, got, req)
		}
	}
	t.Logf("replayed %d command(s), one of them a metered Firestore read; %d Firestore "+
		"command(s) seen in total and the rest not run; %d templates; %d offers",
		replayed, metered, templates, offers)
	if replayed == 0 {
		t.Error("no Firebase command was replayed, so this check graded nothing")
	}
}

func replayFirebase(t *testing.T, req, key string) (int, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", req+` -o /dev/null -w '%{http_code}'`)
	cmd.Env = append(os.Environ(),
		"FIREBASE_API_KEY="+key, "FIREBASE_LAB_API_KEY="+key,
		"FIREBASE_APP_ID="+os.Getenv("FIREBASE_LAB_APP_ID"))
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}
