package provider

import (
	"context"
	"os"
	"testing"

	"github.com/eppser/unruly/scan"
)

// End-to-end against the real lab: detection -> stages -> findings.
func TestEndToEndAgainstTheRealPocketBaseLab(t *testing.T) {
	if os.Getenv("UNRULY_PB_LAB") == "" {
		t.Skip("set UNRULY_PB_LAB=1 with the pocketbase lab serving")
	}
	seeds := []string{"public_notes", "locked_notes", "open_create", "open_write",
		"view_only", "open_files", "locked_files"}

	for _, tc := range []struct {
		label, base string
		wantLeaks   []string
	}{
		{"vulnerable", "http://127.0.0.1:8090",
			[]string{"open_files", "open_write", "public_notes"}},
		{"hardened", "http://127.0.0.1:8091", nil},
	} {
		t.Run(tc.label, func(t *testing.T) {
			d := Detection{Provider: "pocketbase", Project: tc.base}
			st := &scan.State{Target: tc.base}
			stages := StagesFor(d, scan.Inputs{Seeds: seeds})
			if _, err := scan.Pipeline(stages).Run(context.Background(), st); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, f := range st.Findings() {
				if f.ID == "pocketbase-anon-read-exposed" {
					got = append(got, f.Resource)
				}
			}
			if len(got) != len(tc.wantLeaks) {
				t.Fatalf("reported %v, want %v", got, tc.wantLeaks)
			}
			for i := range got {
				if got[i] != tc.wantLeaks[i] {
					t.Errorf("position %d: got %q want %q (order must be stable)",
						i, got[i], tc.wantLeaks[i])
				}
			}
		})
	}
}
