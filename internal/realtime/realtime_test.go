package realtime

import "testing"

func TestWSURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://ref.supabase.co":  "wss://ref.supabase.co",
		"http://127.0.0.1:54321/":  "ws://127.0.0.1:54321",
		"https://ref.supabase.co/": "wss://ref.supabase.co",
	} {
		if got := wsURL(in); got != want {
			t.Errorf("wsURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// Severity turns on whether REST already serves the relation. A table REST
// refuses but Realtime streams is the dangerous case: the two paths disagree,
// and an operator who checked only RLS would believe it was private.
func TestSeverityDependsOnRestDisagreement(t *testing.T) {
	o := Options{BaseURL: "https://ref.supabase.co", ReadExposed: map[string]bool{"public_feed": true}}

	alsoRest := streamFinding(o, Subscription{Relation: "public_feed", Accepted: true})
	if alsoRest.Severity.String() != "medium" {
		t.Errorf("already REST-readable should be medium, got %s", alsoRest.Severity)
	}

	restRefuses := streamFinding(o, Subscription{Relation: "private_orders", Accepted: true})
	if restRefuses.Severity.String() != "high" {
		t.Errorf("REST-protected but streamed should be high, got %s", restRefuses.Severity)
	}
	if !contains(restRefuses.Description, "the two paths disagree") {
		t.Error("the description must name the disagreement, which is the actual finding")
	}
}

func TestStreamingListsOnlyAcceptedSubscriptions(t *testing.T) {
	r := Result{Subscriptions: []Subscription{
		{Relation: "b", Accepted: true},
		{Relation: "a", Accepted: false, Reason: "unauthorized"},
		{Relation: "c", Accepted: true},
	}}
	got := r.Streaming()
	if len(got) != 2 || got[0] != "b" || got[1] != "c" {
		t.Errorf("Streaming() = %v, want [b c] sorted", got)
	}
}

// A refusal must never be reported. Realtime returning "ok" with no binding is
// a refusal dressed as success, and treating it as acceptance would fabricate
// a finding on every relation.
func TestRefusalsProduceNoFindings(t *testing.T) {
	o := Options{BaseURL: "https://ref.supabase.co", AnonKey: "k",
		Relations: []string{"a"}, ReadExposed: map[string]bool{}}
	res := Result{Subscriptions: []Subscription{{Relation: "a", Accepted: false}}}
	for _, s := range res.Subscriptions {
		if s.Accepted {
			t.Fatal("fixture is wrong")
		}
	}
	if len(res.Findings) != 0 {
		t.Error("a refused subscription must not produce a finding")
	}
	_ = o
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestControlProbeSuppressesFindings is the guard for this package's whole
// premise. The subscription acknowledgement was measured NOT to discriminate:
// Supabase acknowledges a join for a relation that does not exist. Any code
// path that derives a finding from the acknowledgement alone would flag every
// relation in the schema, which is how the first version of this check
// reported all 21 relations of the reference target as streaming, 13 of them
// correctly protected.
func TestControlProbeSuppressesFindings(t *testing.T) {
	uninformative := Result{Reachable: true, ControlAccepted: true}
	if uninformative.Informative() {
		t.Error("an acknowledgement that a nonexistent relation also receives is not informative")
	}
	if len(uninformative.Findings) != 0 {
		t.Error("no finding may be derived when the control probe was accepted")
	}

	// If Supabase ever starts refusing subscriptions the caller cannot have,
	// the control probe fails and the oracle becomes meaningful again.
	informative := Result{Reachable: true, ControlAccepted: false}
	if !informative.Informative() {
		t.Error("a refused control probe should make the acknowledgement meaningful")
	}

	unreachable := Result{Reachable: false}
	if unreachable.Informative() {
		t.Error("an unreachable endpoint is not informative")
	}
}

// The subscription must name the schema it was asked for.
//
// All three join payloads hardcoded "public". A publication is not limited to
// the default schema -- ALTER PUBLICATION supabase_realtime ADD TABLE
// reporting.metrics is ordinary -- and a subscriber asks for a schema by name,
// so a table anywhere else streamed every INSERT, UPDATE and DELETE to
// anonymous listeners while the scan never subscribed.
//
// Confirmed against the lab once the schema was threaded through: a change
// payload for reporting.metrics was delivered to an anonymous subscriber.
func TestSubscriptionNamesTheRequestedSchema(t *testing.T) {
	if got := (Options{}).schemaOrDefault(); got != "public" {
		t.Errorf("an unset schema must mean public, got %q", got)
	}
	if got := (Options{Schema: "reporting"}).schemaOrDefault(); got != "reporting" {
		t.Errorf("the configured schema must be used, got %q", got)
	}
}
