package realtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// A check that can only ever answer "inconclusive" is indistinguishable from a
// check that is broken, and against the reference target that is exactly what
// the delivery probe answers — its Realtime publication appears to be empty,
// which is the common case and the correct result. So the positive control
// cannot come from that target. It comes from a server that replays the wire
// shape observed live: phx_reply with a populated postgres_changes binding,
// then a postgres_changes frame carrying the row.
//
// These tests exist to fail if the probe stops being able to see a delivery it
// is actually shown, which no live scan of a well-configured project can prove.

// fakeRealtime speaks enough of the phoenix protocol to answer joins and, when
// asked, to deliver a change payload for a named table.
type fakeRealtime struct {
	publish map[string]bool // tables whose changes it will deliver
	// refuse names relations whose join is rejected, so a test can make the
	// acknowledgement oracle informative.
	refuse map[string]bool
	emit   chan string
	srv    *httptest.Server
}

func newFakeRealtime(t *testing.T, publish ...string) *fakeRealtime {
	t.Helper()
	f := &fakeRealtime{publish: map[string]bool{}, emit: make(chan string, 16)}
	for _, p := range publish {
		f.publish[p] = true
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close(websocket.StatusNormalClosure, "")
		ctx := r.Context()
		topicOf := map[string]string{} // table -> topic
		done := make(chan struct{})

		// One writer goroutine: coder/websocket permits concurrent read and
		// write, and the payload must be able to arrive while the reader is
		// still handling joins.
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-done:
					return
				case table := <-f.emit:
					topic, ok := topicOf[table]
					if !ok || !f.publish[table] {
						continue
					}
					frame, _ := json.Marshal(map[string]any{
						"topic": topic,
						"event": "postgres_changes",
						"payload": map[string]any{"data": map[string]any{
							"schema": "public", "table": table, "type": "INSERT",
							"record": map[string]any{"id": 1, "email": "a@b.c", "secret": "x"},
						}},
					})
					_ = c.Write(ctx, websocket.MessageText, frame)
				}
			}
		}()

		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				close(done)
				return
			}
			var m struct {
				Topic   string `json:"topic"`
				Event   string `json:"event"`
				Ref     string `json:"ref"`
				Payload struct {
					Config struct {
						PostgresChanges []struct {
							Table string `json:"table"`
						} `json:"postgres_changes"`
					} `json:"config"`
				} `json:"payload"`
			}
			if json.Unmarshal(data, &m) != nil || m.Event != "phx_join" {
				continue
			}
			var table string
			if len(m.Payload.Config.PostgresChanges) > 0 {
				table = m.Payload.Config.PostgresChanges[0].Table
			}
			topicOf[table] = m.Topic
			if f.refuse[table] {
				bad, _ := json.Marshal(map[string]any{
					"topic": m.Topic, "event": "phx_reply", "ref": m.Ref,
					"payload": map[string]any{"status": "error",
						"response": map[string]any{"reason": "no such relation"}},
				})
				_ = c.Write(ctx, websocket.MessageText, bad)
				continue
			}
			reply, _ := json.Marshal(map[string]any{
				"topic": m.Topic, "event": "phx_reply", "ref": m.Ref,
				"payload": map[string]any{"status": "ok", "response": map[string]any{
					"postgres_changes": []map[string]any{{"id": 42}},
				}},
			})
			_ = c.Write(ctx, websocket.MessageText, reply)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRealtime) dial(t *testing.T, ctx context.Context) *websocket.Conn {
	t.Helper()
	u := "ws" + strings.TrimPrefix(f.srv.URL, "http")
	conn, _, err := websocket.Dial(ctx, u, nil)
	if err != nil {
		t.Fatalf("dial fake realtime: %v", err)
	}
	t.Cleanup(func() { conn.Close(websocket.StatusNormalClosure, "") })
	return conn
}

// trigger returns a Trigger func that reports the write landed and asks the
// fake server to deliver, mirroring what an INSERT through PostgREST causes.
func (f *fakeRealtime) trigger(landed map[string]bool) func(context.Context, string) bool {
	return func(_ context.Context, rel string) bool {
		if landed != nil && !landed[rel] {
			return false
		}
		f.emit <- rel
		return true
	}
}

func run(t *testing.T, f *fakeRealtime, o Options) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if o.DeliveryWindow == 0 {
		// The real window covers WAL propagation across a network. The fake
		// server answers from memory, so paying it six times over would make
		// the suite slow for no added confidence.
		o.DeliveryWindow = 750 * time.Millisecond
	}
	res := Result{}
	runDelivery(ctx, f.dial(t, ctx), o, &res)
	return res
}

// The control that matters: a delivery the probe is actually shown must be
// reported. Without this the live "inconclusive" result proves nothing.
func TestDeliveryReportsAnObservedPayload(t *testing.T) {
	f := newFakeRealtime(t, "leaky")
	res := run(t, f, Options{
		BaseURL: "http://x", Writable: []string{"leaky"}, Trigger: f.trigger(nil),
	})
	if !res.DeliveryObserved {
		t.Fatalf("payload was delivered but DeliveryObserved is false")
	}
	if len(res.Delivered) != 1 || res.Delivered[0].Relation != "leaky" {
		t.Fatalf("want leaky delivered, got %+v", res.Delivered)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(res.Findings))
	}
	// The columns are the evidence: they show what a listener receives for
	// every real change, not just for the probe's throwaway row.
	if got := strings.Join(res.Delivered[0].Columns, ","); got != "email,id,secret" {
		t.Fatalf("columns not carried as evidence: %q", got)
	}
	if res.Findings[0].Evidence.Reason == "" {
		t.Fatalf("finding carries no reason")
	}
	if res.Findings[0].ID != "supabase-realtime-anon-delivery" {
		t.Errorf("ID changed to %q; consumers filter on it", res.Findings[0].ID)
	}
}

// A relation REST refuses but Realtime publishes is the case the whole probe
// exists for: the two paths disagree and only one of them gets audited.
func TestDeliverySeverityRisesWhenRESTRefusesTheRelation(t *testing.T) {
	f := newFakeRealtime(t, "private")
	quiet := run(t, f, Options{
		BaseURL: "http://x", Writable: []string{"private"}, Trigger: f.trigger(nil),
		ReadExposed: map[string]bool{"private": true},
	})
	f2 := newFakeRealtime(t, "private")
	loud := run(t, f2, Options{
		BaseURL: "http://x", Writable: []string{"private"}, Trigger: f2.trigger(nil),
	})
	if len(quiet.Findings) != 1 || len(loud.Findings) != 1 {
		t.Fatalf("want one finding each, got %d and %d", len(quiet.Findings), len(loud.Findings))
	}
	if !(loud.Findings[0].Severity > quiet.Findings[0].Severity) {
		t.Fatalf("a relation REST refuses must outrank one it already serves: %v vs %v",
			loud.Findings[0].Severity, quiet.Findings[0].Severity)
	}
}

// Mixed is the case that proves negatives are real rather than incidental: one
// relation delivers, so the connection demonstrably works, so the silence of
// the other is a measurement and not a failure.
func TestDeliveryDistinguishesSilentRelationsOnceOneDelivers(t *testing.T) {
	f := newFakeRealtime(t, "leaky") // "quiet" is writable but not published
	res := run(t, f, Options{
		BaseURL: "http://x", Writable: []string{"quiet", "leaky"}, Trigger: f.trigger(nil),
	})
	if !res.DeliveryObserved {
		t.Fatalf("one relation delivered; the positive control should hold")
	}
	if len(res.Delivered) != 1 || res.Delivered[0].Relation != "leaky" {
		t.Fatalf("want only leaky delivered, got %+v", res.Delivered)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("a published and an unpublished relation must not read alike: %d findings",
			len(res.Findings))
	}
	if strings.Contains(res.Findings[0].Resource, "quiet") {
		t.Fatalf("flagged a relation that never delivered")
	}
}

// The soundness rule. No delivery anywhere means the probe cannot tell a
// project that publishes nothing from a probe that did not work, so it must
// produce neither a finding nor a clean bill of health.
func TestDeliverySilenceEverywhereIsInconclusiveNotClean(t *testing.T) {
	f := newFakeRealtime(t) // publishes nothing
	res := run(t, f, Options{
		BaseURL: "http://x", Writable: []string{"a", "b"}, Trigger: f.trigger(nil),
	})
	if res.DeliveryObserved {
		t.Fatalf("nothing was delivered; the positive control must not hold")
	}
	if len(res.Findings) != 0 {
		t.Fatalf("want no findings from an unproven channel, got %d", len(res.Findings))
	}
	if len(res.DeliveryTested) != 2 {
		t.Fatalf("both relations were written to and must be recorded as measured: %v",
			res.DeliveryTested)
	}
}

// A relation the write never landed on was not measured, and must not be
// counted as one that stayed silent.
func TestDeliverySkipsRelationsWhereTheWriteDidNotLand(t *testing.T) {
	f := newFakeRealtime(t, "leaky")
	res := run(t, f, Options{
		BaseURL: "http://x", Writable: []string{"blocked", "leaky"},
		Trigger: f.trigger(map[string]bool{"leaky": true}),
	})
	if len(res.DeliveryTested) != 1 || res.DeliveryTested[0] != "leaky" {
		t.Fatalf("only leaky was written to, got %v", res.DeliveryTested)
	}
}

// Without -write there is no Trigger, and the probe must stay out entirely
// rather than subscribe and report silence as absence.
func TestDeliveryDoesNothingWithoutATrigger(t *testing.T) {
	f := newFakeRealtime(t, "leaky")
	res := run(t, f, Options{BaseURL: "http://x", Writable: []string{"leaky"}})
	if res.DeliveryObserved || len(res.Findings) != 0 || len(res.DeliveryTested) != 0 {
		t.Fatalf("no consent to write means no probe: %+v", res)
	}
}

// streamFinding is the acknowledgement-based finding. It is unreachable
// against Supabase today, because the control probe shows every join is
// acknowledged and Run returns before building it. It stays in the tree
// deliberately: should the platform start refusing subscriptions the caller
// may not have, the oracle becomes meaningful and this path resumes with no
// code change. An unreachable path with no test is how that resumption would
// come back broken.
func TestSubscriptionFindingIDAndSeverity(t *testing.T) {
	o := Options{BaseURL: "http://x", ReadExposed: map[string]bool{"public_data": true}}
	served := streamFinding(o, Subscription{Relation: "public_data", Accepted: true})
	refused := streamFinding(o, Subscription{Relation: "private_data", Accepted: true})

	if served.ID != "supabase-realtime-anon-subscription" {
		t.Errorf("ID changed to %q; consumers filter on it", served.ID)
	}
	if !(refused.Severity > served.Severity) {
		t.Errorf("a relation REST refuses must outrank one it already serves: %v vs %v",
			refused.Severity, served.Severity)
	}
}

// Delivery must run on BOTH paths. It was reachable only from the branch taken
// when the acknowledgement control probe is ACCEPTED — i.e. only when the weak
// oracle is broken — so a deployment that correctly refuses the control probe
// got no payload-based evidence at all. The package doc claimed the opposite
// throughout.
func TestDeliveryRunsWhenTheAcknowledgementOracleWorks(t *testing.T) {
	f := newFakeRealtime(t, "leaky")
	// Refuse the control relation, which is what a correctly behaving server
	// would do and what makes the acknowledgement oracle informative.
	f.refuse = map[string]bool{"unruly_control_relation_does_not_exist": true}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := Run(ctx, Options{
		BaseURL:        "http://" + strings.TrimPrefix(f.srv.URL, "http://"),
		AnonKey:        "k",
		Relations:      []string{"leaky"},
		Writable:       []string{"leaky"},
		Trigger:        f.trigger(nil),
		DeliveryWindow: 750 * time.Millisecond,
	})
	if res.ControlAccepted {
		t.Fatal("the fake refuses the control relation; the oracle should be informative")
	}
	if !res.DeliveryObserved {
		t.Error("delivery must be probed on the informative path too, or the sound " +
			"evidence is skipped exactly where the weak evidence starts working")
	}
}
