package neon

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eppser/unruly/internal/neonauth"
)

// The commands this backend publishes must reproduce against the real lab.
//
// internal/eval replays every command a scan of the local Supabase fixture
// prints, and it found a drift within a minute of working. Neon's findings were
// outside that check entirely: they address a live endpoint, so the fixture
// replay skips them, and nothing else read them.
//
// Read commands only, and the omission is counted rather than quiet. This
// target is documented read-only -- "the fixture's seed row counts are
// untouched" -- and replaying the write command would insert a row, which is a
// promise this test does not get to break for its own convenience. The write
// command's fidelity is covered offline instead, by
// TestAcceptedWriteQuotesTheRowItCreated and by the transcript provenance
// guard.
//
//	set -a && . .secrets/neon.env && set +a
//	UNRULY_LIVE=1 go test ./backend/neon -run CrossCheckPublished -v
func TestCrossCheckPublishedRequestsReplay(t *testing.T) {
	if os.Getenv("UNRULY_LIVE") != "1" {
		t.Skip("set UNRULY_LIVE=1")
	}
	api, auth := os.Getenv("NEON_DATA_API"), os.Getenv("NEON_AUTH_URL")
	if api == "" || auth == "" {
		t.Fatal("NEON_DATA_API and NEON_AUTH_URL must be set; source .secrets/neon.env")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tok, err := neonauth.New(auth, "http://localhost:3000").
		Token(ctx, "unruly-replay@example.com", "Correct-Horse-9271")
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	dir := t.TempDir()
	vocab := filepath.Join(dir, "vocab.json")
	seeds, _ := json.Marshal(map[string]any{
		"schema_version": 1, "stage": "vocabulary", "seeds": allTables,
	})
	if err := os.WriteFile(vocab, seeds, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "f.jsonl")
	bin := filepath.Join(dir, "unruly")
	if b, err := exec.Command("go", "build", "-o", bin, "../../cmd/unruly").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	// No -write: this target does not mutate the fixture.
	cmd := exec.CommandContext(ctx, bin, "-u", api, "-user-jwt", tok,
		"-vocab", vocab, "-j", "-o", out, "-nc", "-timeout", "25")
	_, _ = cmd.CombinedOutput() // non-zero exit means findings

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report: %v", err)
	}
	var replayed, notRun int
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f map[string]any
		if json.Unmarshal([]byte(line), &f) != nil {
			continue
		}
		id, _ := f["id"].(string)
		if !strings.HasPrefix(id, "neon-") {
			continue
		}
		ev, _ := f["evidence"].(map[string]any)
		req, _ := ev["request"].(string)
		want := 0
		switch v := ev["status"].(type) {
		case float64:
			want = int(v)
		}
		if req == "" || want == 0 {
			t.Errorf("%s publishes no command or no status; on this backend every finding "+
				"is a claim the scan measured, so both are evidence", id)
			continue
		}
		if strings.Contains(req, "-X POST") {
			// Deliberately not run: it would insert a row.
			notRun++
			continue
		}
		got, err := replayNeon(t, req, tok)
		if err != nil {
			t.Errorf("%s: its own published command does not run: %v\n  %s", id, err, req)
			continue
		}
		replayed++
		if got != want {
			t.Errorf("%s: the report says HTTP %d and its own command returns HTTP %d.\n  %s",
				id, want, got, req)
		}
	}
	t.Logf("replayed %d read command(s); %d write command(s) not run, because this "+
		"target is read-only", replayed, notRun)
	if replayed == 0 {
		t.Error("no Neon command was replayed, so this check graded nothing")
	}
}

func replayNeon(t *testing.T, req, tok string) (int, error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", req+` -o /dev/null -w '%{http_code}'`)
	cmd.Env = append(os.Environ(), "NEON_TOKEN="+tok)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}
