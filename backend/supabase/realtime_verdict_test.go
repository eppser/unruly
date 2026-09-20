package supabase

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/realtime"
)

// The realtime pass has four distinct verdicts and they must stay distinct.
//
// This is the project's central claim applied to one surface: not looking, and
// looking and finding nothing, and looking with an instrument that cannot see,
// are three different results. Collapsing any of them into "clean" is the lie
// the tool exists to refuse -- and until this test they were narration nobody
// checked, so deleting the inconclusive branch SURVIVED its mutation.
func TestTheRealtimeVerdictsStayDistinct(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result realtime.Result
		want   string
		reject string
	}{
		{
			name:   "unreachable",
			result: realtime.Result{Reachable: false},
			want:   "not reachable",
		},
		{
			// Proof: a payload for a real change arrived at an anonymous
			// listener. Nothing else on this surface is proof.
			name: "delivered",
			result: realtime.Result{
				Reachable:      true,
				Delivered:      []realtime.Delivery{{Relation: "orders"}},
				DeliveryTested: []string{"orders", "invoices"},
			},
			want: "delivered change payloads for 1 of 2",
		},
		{
			// THE ONE THAT MATTERS. A change was caused and nothing arrived.
			// That is not evidence of safety: with no delivery anywhere the
			// probe itself is unproven.
			name: "tested and nothing arrived",
			result: realtime.Result{
				Reachable:      true,
				DeliveryTested: []string{"orders"},
			},
			want:   "inconclusive, not clean",
			reject: "stream to anon",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, got := realtimeVerdict(tc.result, 3)
			if !strings.Contains(got, tc.want) {
				t.Errorf("verdict = %q, want it to contain %q", got, tc.want)
			}
			if tc.reject != "" && strings.Contains(got, tc.reject) {
				t.Errorf("verdict = %q, which reads as the %q case: a surface that was "+
					"probed and stayed silent is not a surface known to be quiet",
					got, tc.reject)
			}
		})
	}
}
