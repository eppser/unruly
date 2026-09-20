// Package realtime checks whether change streams are readable anonymously.
//
// Supabase Realtime broadcasts row changes over a WebSocket. Two things have
// to be true for a relation's changes to reach an anonymous listener: the
// relation must be in the `supabase_realtime` publication, and the anon role
// must satisfy the relation's RLS SELECT policy. Operators routinely add a
// table to the publication and forget the second half — or add it before RLS
// is tightened and never revisit.
//
// This is a real gap in the rest of the scan rather than a bonus check. A
// PostgREST probe answers "can anon SELECT this now"; Realtime answers "does
// anon receive every future INSERT, UPDATE and DELETE as it happens". A
// relation can look quiet to a REST probe and still stream its contents.
//
// MEASURED NEGATIVE RESULT: the subscription acknowledgement is not a
// discriminator, and cannot be used to report exposure.
//
// The obvious probe is to join a postgres_changes channel and read the reply.
// It looked sound and it is not. Against a live project, Realtime answers
// status=ok with a populated postgres_changes binding for a table that does
// not exist at all:
//
//	zzz_definitely_not_a_table  {"status":"ok","response":{"postgres_changes":[{"id":21942019,...}]}}
//	cves (RLS-protected)        {"status":"ok","response":{"postgres_changes":[{"id":46914639,...}]}}
//	sessions (anon-readable)    {"status":"ok","response":{"postgres_changes":[{"id":124901999,...}]}}
//
// The server accepts the subscription and applies RLS at DELIVERY time, so the
// acknowledgement says nothing about whether rows will ever arrive. Reporting
// on it flagged all 21 relations of the reference target, including the 13 that
// are correctly protected — the same false-positive shape as a zero-match
// DELETE write probe.
//
// Proving exposure from the acknowledgement is therefore impossible, and this
// package deliberately reports NO findings from it.
//
// Exposure IS provable a different way. An earlier version of this comment
// concluded that proof "would mean waiting for a real change event, which
// depends on whatever the application happens to be doing and is therefore not
// deterministic". That holds only while the scanner is a passive observer, and
// under -write it is not: it already INSERTs into relations shown to accept
// anonymous writes, and cleans up after itself. Subscribing FIRST and then
// performing that INSERT makes the change event caused rather than awaited, so
// a delivered payload becomes a deterministic result. See the delivery probe
// at the foot of this file. It runs a control probe against a relation that cannot
// exist, and if that is accepted too — which is the current behaviour — it
// records that the acknowledgement oracle is uninformative on this deployment
// and stays quiet, while the delivery probe runs regardless.
// Should Supabase ever start refusing subscriptions the caller may not have,
// the control probe fails, the oracle becomes meaningful, and findings resume
// with no code change.
package realtime

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/eppser/unruly/internal/finding"
)

// Subscription is the outcome for one relation.
type Subscription struct {
	Relation string
	// Accepted is true when the server confirmed a postgres_changes
	// subscription for this relation.
	Accepted bool
	// Reason carries the server's own words when it refused.
	Reason string
}

// Result is the outcome of the Realtime check.
// schemaOrDefault is the schema to subscribe to.
func (o Options) schemaOrDefault() string {
	if o.Schema == "" {
		return "public"
	}
	return o.Schema
}

type Result struct {
	// Reachable is false when the endpoint could not be spoken to at all.
	Reachable bool
	// ControlAccepted records whether a relation that cannot exist was also
	// acknowledged. When true the acknowledgement carries no information and
	// no finding may be derived from it.
	ControlAccepted bool
	// DeliveryTested lists relations a change was successfully CAUSED on, so
	// a payload had something to be triggered by. A relation absent from this
	// list was not measured.
	DeliveryTested []string
	// Delivered lists relations whose change payload actually arrived.
	Delivered []Delivery
	// DeliveryObserved is the in-band positive control: true once any payload
	// arrives, which is what makes the absence of the others meaningful.
	DeliveryObserved bool
	Subscriptions    []Subscription
	Findings         []finding.Finding
	Requests         int
}

// Informative reports whether the acknowledgement discriminates on this
// deployment. Currently false against Supabase; kept as a runtime check rather
// than a hardcoded assumption so the tool adapts if the platform changes.
func (r Result) Informative() bool { return r.Reachable && !r.ControlAccepted }

// Streaming lists relations whose changes reach an anonymous listener.
func (r Result) Streaming() []string {
	var out []string
	for _, s := range r.Subscriptions {
		if s.Accepted {
			out = append(out, s.Relation)
		}
	}
	sort.Strings(out)
	return out
}

// Options configures the check.
type Options struct {
	BaseURL string
	AnonKey string
	// Schema is the Postgres schema whose changes are subscribed to. Empty
	// means public.
	//
	// A publication is not limited to the default schema: ALTER PUBLICATION
	// supabase_realtime ADD TABLE reporting.x is ordinary, and a subscriber
	// asks for a schema by name. This was hardcoded to "public" in all three
	// join payloads, so changes to a table in any other exposed schema were
	// delivered to anonymous listeners and the scan never asked about them --
	// the last per-schema surface still blind after relations, routines and
	// the elevated pass had been covered.
	Schema string
	// Relations to test. Reusing the enumerated set keeps this cheap: one
	// connection, one join per relation.
	Relations []string
	// ReadExposed marks relations anon can already read via REST, so the
	// finding can distinguish "streams data anon could fetch anyway" from
	// "streams data REST refuses to serve".
	ReadExposed map[string]bool
	// Writable lists relations already shown to accept anonymous INSERT.
	// Triggering a change on anything else would either fail or need a write
	// the operator has not consented to.
	Writable []string
	// Trigger causes one row-level change on a relation and reports whether
	// the write actually landed. Supplied by the caller only under -write, and
	// nil otherwise, which disables the delivery probe entirely.
	Trigger func(context.Context, string) bool
	// DeliveryWindow bounds the wait for triggered payloads. Zero means
	// deliveryWindow. Exposed so tests need not spend the real propagation
	// budget, and so a slow project can be given more.
	DeliveryWindow time.Duration
	Timeout        time.Duration
}

// deliveryWindow bounds how long the probe waits for triggered payloads. Every
// change is caused by this process, so the wait is for propagation through the
// WAL and the Realtime server, not for application traffic.
const deliveryWindow = 8 * time.Second

// phoenix message envelope used by Realtime.
type message struct {
	Topic   string          `json:"topic"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	Ref     string          `json:"ref"`
}

// Run opens one WebSocket and attempts a postgres_changes join per relation.
func Run(ctx context.Context, o Options) Result {
	res := Result{}
	if o.AnonKey == "" || len(o.Relations) == 0 {
		return res
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	endpoint := wsURL(o.BaseURL) + "/realtime/v1/websocket?vsn=1.0.0&apikey=" + o.AnonKey
	conn, _, err := websocket.Dial(ctx, endpoint, nil)
	if err != nil {
		return res
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	res.Reachable = true
	res.Requests++

	// Control probe first. A relation that cannot exist must be REFUSED for
	// the acknowledgement to mean anything.
	const control = "unruly_control_relation_does_not_exist"
	accepted, _ := joinAndAwait(ctx, conn, "0", control, o.schemaOrDefault())
	res.ControlAccepted = accepted
	res.Requests++
	if accepted {
		// The oracle is uninformative here: every join is acknowledged. Report
		// nothing from IT rather than flagging every relation in the schema.
		// Delivery does not depend on the acknowledgement and is still sound,
		// so it runs below like it does on any other deployment.
		runDelivery(ctx, conn, o, &res)
		return res
	}

	relations := append([]string{}, o.Relations...)
	sort.Strings(relations)

	for i, rel := range relations {
		ref := fmt.Sprintf("%d", i+1)
		sub := Subscription{Relation: rel}
		sub.Accepted, sub.Reason = joinAndAwait(ctx, conn, ref, rel, o.schemaOrDefault())
		res.Requests++
		res.Subscriptions = append(res.Subscriptions, sub)
	}

	for _, s := range res.Subscriptions {
		if s.Accepted {
			res.Findings = append(res.Findings, streamFinding(o, s))
		}
	}

	// Delivery runs here too.
	//
	// The package doc has always claimed the delivery probe "runs regardless",
	// and it did not: it was reachable only from the branch above, the one
	// taken when the acknowledgement control is ACCEPTED — that is, only when
	// the weak oracle is broken. On a deployment where the control is properly
	// refused, which the doc frames as the desirable future state, the sound
	// payload-based evidence was skipped and only acknowledgements were
	// reported. The stronger evidence was abandoned exactly where the weaker
	// evidence started working. An audit found it; the doc was right and the
	// code was not.
	runDelivery(ctx, conn, o, &res)

	finding.Sort(res.Findings)
	res.Findings = finding.Dedup(res.Findings)
	return res
}

// joinAndAwait sends one postgres_changes join and reads its reply.
func joinAndAwait(ctx context.Context, conn *websocket.Conn, ref, table, schema string) (bool, string) {
	join := map[string]any{
		"topic": "realtime:unruly-" + ref,
		"event": "phx_join",
		"ref":   ref,
		"payload": map[string]any{
			"config": map[string]any{
				"postgres_changes": []map[string]any{
					{"event": "*", "schema": schema, "table": table},
				},
			},
		},
	}
	body, err := json.Marshal(join)
	if err != nil {
		return false, err.Error()
	}
	if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
		return false, err.Error()
	}
	return awaitReply(ctx, conn, ref)
}

// awaitReply reads until the reply carrying our ref arrives. Realtime
// interleaves heartbeats and system events, so matching on ref rather than
// taking the next frame is what makes this reliable.
func awaitReply(ctx context.Context, conn *websocket.Conn, ref string) (bool, string) {
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return false, "no reply: " + err.Error()
		}
		if typ != websocket.MessageText {
			continue
		}
		var m message
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if m.Ref != ref || m.Event != "phx_reply" {
			continue
		}
		var p struct {
			Status   string `json:"status"`
			Response struct {
				PostgresChanges []struct {
					ID int `json:"id"`
				} `json:"postgres_changes"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			} `json:"response"`
		}
		if json.Unmarshal(m.Payload, &p) != nil {
			return false, "unparseable reply"
		}
		if p.Status != "ok" {
			reason := p.Response.Reason
			if reason == "" {
				reason = p.Response.Message
			}
			if reason == "" {
				reason = "status=" + p.Status
			}
			return false, reason
		}
		// An "ok" with no confirmed postgres_changes binding means the join
		// succeeded but the subscription did not, which is a refusal.
		if len(p.Response.PostgresChanges) == 0 {
			return false, "joined without a postgres_changes binding"
		}
		return true, ""
	}
}

func streamFinding(o Options, s Subscription) finding.Finding {
	// A relation REST already serves to anon is a smaller surprise than one
	// REST refuses; the latter means the two paths disagree about who may read
	// it, and the operator almost certainly only checked the REST side.
	sev := finding.Medium
	extra := " The same rows are already readable over REST, so this widens the " +
		"exposure to live updates rather than creating it."
	if !o.ReadExposed[s.Relation] {
		sev = finding.High
		extra = " REST does NOT serve this relation to the anonymous role, so the two " +
			"paths disagree: the table is protected when queried and streamed when watched. " +
			"An operator who checked only RLS would reasonably believe it was private."
	}
	return finding.Finding{
		ID:       "supabase-realtime-anon-subscription",
		Name:     "Relation changes stream to anonymous listeners",
		Severity: sev,
		Protocol: "realtime",
		Matched:  strings.TrimSuffix(o.BaseURL, "/") + "/realtime/v1/websocket",
		Resource: s.Relation,
		Description: fmt.Sprintf(
			"Realtime accepted an anonymous postgres_changes subscription for %q, so every "+
				"INSERT, UPDATE and DELETE on that relation is delivered to any listener holding "+
				"the public anon key.%s", s.Relation, extra),
		Remediation: Remediation(s.Relation),
		Evidence: finding.Evidence{
			Request: fmt.Sprintf("wscat -c '%s/realtime/v1/websocket?vsn=1.0.0&apikey=$ANON_KEY' "+
				`# then: {"topic":"realtime:probe","event":"phx_join","ref":"1",`+
				`"payload":{"config":{"postgres_changes":[{"event":"*","schema":"%s","table":"%s"}]}}}`,
				strings.TrimSuffix(o.BaseURL, "/"), o.schemaOrDefault(), s.Relation),
			Reason: "subscription acknowledged with status=ok",
		},
	}
}

// wsURL converts an http(s) origin to its ws(s) equivalent.
func wsURL(base string) string {
	base = strings.TrimSuffix(base, "/")
	switch {
	case strings.HasPrefix(base, "https://"):
		return "wss://" + strings.TrimPrefix(base, "https://")
	case strings.HasPrefix(base, "http://"):
		return "ws://" + strings.TrimPrefix(base, "http://")
	}
	return base
}

// ---------------------------------------------------------------------------
// Delivery probe
//
// The acknowledgement oracle above is dead: Supabase accepts a subscription for
// a relation that does not exist. The package doc concluded that proving
// exposure "would mean waiting for a real change event, which depends on
// whatever the application happens to be doing and is therefore not
// deterministic".
//
// That is true only while the scanner is a passive observer. It does not have
// to be. Under -write the scanner already performs an INSERT against relations
// it has shown accept anonymous writes, and cleans up after itself. Subscribing
// FIRST and then performing that INSERT turns the change event from something
// waited for into something CAUSED, which makes it deterministic:
//
//	subscribe(rel)  ->  INSERT into rel  ->  payload arrives?  yes = delivered
//
// A payload is proof in the strongest sense available here. It is not an
// acknowledgement that a subscription was registered; it is the server handing
// an anonymous listener the contents of a row it just wrote, having applied RLS
// at delivery time and decided this listener may see it.
//
// Soundness: a relation that produces no payload is only meaningfully negative
// if delivery is known to work at all on this connection. So absence is
// reported ONLY when at least one other relation delivered, which serves as an
// in-band positive control. If nothing delivers anywhere, the result is
// inconclusive and no finding — and no clean bill of health — is produced.

// Delivery records a change event that actually reached an anonymous listener.
type Delivery struct {
	Relation string
	// Columns are the field names the server broadcast. The values belong to
	// the probe's own throwaway row, so the columns are the informative part:
	// they show what a listener receives for every real change too.
	Columns []string
	// Type is the change type reported by the server (INSERT).
	Type string
}

// runDelivery subscribes to each writable relation, triggers a change on each,
// and reports which ones delivered a payload to this anonymous listener.
func runDelivery(ctx context.Context, conn *websocket.Conn, o Options, res *Result) {
	rels := append([]string{}, o.Writable...)
	sort.Strings(rels)
	rels = dedup(rels)
	if len(rels) == 0 {
		return
	}

	// Subscribe to everything BEFORE triggering anything. A change fired
	// before its subscription exists is simply missed, and would read as a
	// negative — the exact ambiguity this probe is built to remove.
	topics := map[string]string{} // topic -> relation
	for i, rel := range rels {
		ref := fmt.Sprintf("d%d", i)
		topic := "realtime:unruly-deliver-" + ref
		if ok, _ := joinTopic(ctx, conn, topic, ref, rel, o.schemaOrDefault()); ok {
			topics[topic] = rel
		}
		res.Requests++
	}
	if len(topics) == 0 {
		return
	}

	for _, rel := range rels {
		if o.Trigger != nil && o.Trigger(ctx, rel) {
			res.DeliveryTested = append(res.DeliveryTested, rel)
		}
	}
	sort.Strings(res.DeliveryTested)
	if len(res.DeliveryTested) == 0 {
		// Nothing was written, so nothing could have been delivered. Silence
		// here means "not measured", not "not exposed".
		return
	}

	// Drain for a bounded window. Payloads for relations triggered early may
	// already be buffered; the window covers the rest.
	window := o.DeliveryWindow
	if window <= 0 {
		window = deliveryWindow
	}
	deadline := time.Now().Add(window)
	seen := map[string]Delivery{}
	for time.Now().Before(deadline) {
		rctx, cancel := context.WithDeadline(ctx, deadline)
		_, data, err := conn.Read(rctx)
		cancel()
		if err != nil {
			break
		}
		var m message
		if json.Unmarshal(data, &m) != nil || m.Event != "postgres_changes" {
			continue
		}
		rel, ok := topics[m.Topic]
		if !ok {
			continue
		}
		var p struct {
			Data struct {
				Table  string         `json:"table"`
				Type   string         `json:"type"`
				Record map[string]any `json:"record"`
			} `json:"data"`
		}
		if json.Unmarshal(m.Payload, &p) != nil || p.Data.Table != rel {
			continue
		}
		cols := make([]string, 0, len(p.Data.Record))
		for k := range p.Data.Record {
			cols = append(cols, k)
		}
		sort.Strings(cols)
		seen[rel] = Delivery{Relation: rel, Columns: cols, Type: p.Data.Type}
	}

	for _, rel := range rels {
		if d, ok := seen[rel]; ok {
			res.Delivered = append(res.Delivered, d)
		}
	}
	sort.Slice(res.Delivered, func(i, j int) bool {
		return res.Delivered[i].Relation < res.Delivered[j].Relation
	})

	// In-band positive control. Without a single delivery we cannot tell a
	// project that publishes nothing from a probe that did not work.
	if len(res.Delivered) == 0 {
		return
	}
	res.DeliveryObserved = true
	for _, d := range res.Delivered {
		res.Findings = append(res.Findings, deliveryFinding(o, d))
	}
	finding.Sort(res.Findings)
	res.Findings = finding.Dedup(res.Findings)
}

// joinTopic sends a postgres_changes join on an explicit topic.
func joinTopic(ctx context.Context, conn *websocket.Conn, topic, ref, table, schema string) (bool, string) {
	join := map[string]any{
		"topic": topic,
		"event": "phx_join",
		"ref":   ref,
		"payload": map[string]any{
			"config": map[string]any{
				"postgres_changes": []map[string]any{
					{"event": "INSERT", "schema": schema, "table": table},
				},
			},
		},
	}
	body, err := json.Marshal(join)
	if err != nil {
		return false, err.Error()
	}
	if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
		return false, err.Error()
	}
	return awaitReply(ctx, conn, ref)
}

func deliveryFinding(o Options, d Delivery) finding.Finding {
	sev := finding.High
	extra := " The same rows are readable over REST as well, so this extends a known " +
		"exposure to live updates rather than creating a new one."
	if !o.ReadExposed[d.Relation] {
		sev = finding.Critical
		extra = " REST does NOT serve this relation to the anonymous role. The two paths " +
			"disagree: the table is protected when queried and published when watched. An " +
			"operator who verified their RLS policies with a SELECT would reasonably believe " +
			"this data was private."
	}
	return finding.Finding{
		ID:       "supabase-realtime-anon-delivery",
		Name:     "Row changes are delivered to anonymous listeners",
		Severity: sev,
		Protocol: "realtime",
		Matched:  strings.TrimSuffix(o.BaseURL, "/") + "/realtime/v1/websocket",
		Resource: d.Relation,
		Description: fmt.Sprintf(
			"An anonymous listener holding only the public anon key subscribed to %q and "+
				"received the payload for a %s on it. This is delivery, not merely an accepted "+
				"subscription: Realtime evaluated RLS for this listener at delivery time and "+
				"decided it may see the row. Every future change to this relation reaches "+
				"anyone with the key, in real time.%s", d.Relation, d.Type, extra),
		Remediation: Remediation(d.Relation),
		Evidence: finding.Evidence{
			Request: fmt.Sprintf("subscribe to postgres_changes INSERT on public.%s, then "+
				"POST %s/%s -- the payload for that row arrived on the socket",
				d.Relation, strings.TrimSuffix(o.BaseURL, "/"), d.Relation),
			Reason:  "change payload delivered to an anonymous subscriber",
			Columns: d.Columns,
		},
	}
}

func dedup(xs []string) []string {
	if len(xs) == 0 {
		return xs
	}
	out := xs[:1]
	for _, x := range xs[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

// Remediation is the fix for a relation whose changes reach anonymous
// listeners. Exported and shared by both findings in this package: the text
// was duplicated between them, and a fix that drifts between two copies is a
// fix one of its readers gets wrong.
//
// The commented policy is a worked example an operator uncomments, which makes
// it the line most likely to be run by hand against production. It is executed
// against a real Postgres by TestRemediationTemplatesAreValidSQL.
func Remediation(relation string) string {
	return fmt.Sprintf(`-- Remove the relation from the Realtime publication if live
-- updates are not meant to be public:
ALTER PUBLICATION supabase_realtime DROP TABLE %[1]s;

-- Realtime honours RLS, so the durable fix is a SELECT policy that scopes rows
-- to the owning user rather than granting the role blanket access:
-- CREATE POLICY "%[1]s_own_rows" ON %[1]s
--   FOR SELECT TO authenticated USING (user_id = (select auth.uid()));

-- Review what is currently published:
-- SELECT tablename FROM pg_publication_tables
-- WHERE pubname = 'supabase_realtime' ORDER BY tablename;`, relation)
}

// CoverageFinding reports that delivery could not be measured.
//
// Added after an audit found this project's central thesis failing inside its
// own evidence bundle. The console said:
//
//	realtime: caused a change on 3 relations and no payload was delivered;
//	with no delivery anywhere this is inconclusive, not clean
//
// and the JSONL report — the artifact a machine reads, and the one the exit
// code is derived from — said nothing about realtime at all. So a project
// whose realtime exposure could not be measured, with nothing else at high or
// above, exited 0: "scanned, nothing at or above high, every surface measured".
//
// The package was right to refuse a FINDING about the target. It was wrong to
// stay silent, because by this project's own rule — a scan that reports
// nothing is indistinguishable from one that looked and found nothing wrong —
// silence in the artifact IS a clean bill of health. The distinction held in
// the terminal and collapsed in the file.
func (r Result) CoverageFinding(baseURL string) (finding.Finding, bool) {
	if len(r.Delivered) > 0 {
		return finding.Finding{}, false
	}
	// Three ways to end up unable to say anything, and the first fix covered
	// only one of them. An audit found the other two:
	//
	//	delivery attempted, nothing arrived   -> inconclusive
	//	delivery never attempted (no -write)  -> UNMEASURED, and this was the
	//	                                         DEFAULT path, silent in the
	//	                                         artifact and exiting 0
	//	endpoint unreachable                  -> unmeasured, also silent
	//
	// The doc comment below was written about exactly this failure and then
	// applied to one branch of three. A default scan of a real project said
	// "not a reliable exposure signal" in the terminal and nothing at all in
	// the JSONL, which is where the exit code comes from.
	// A check the operator DECLINED is not a surface the scan could not see,
	// and conflating them makes the exit code meaningless. Without -write,
	// delivery is never attempted — that is the default, so reporting it as
	// blindness would put every ordinary scan at exit 3 and the code would
	// stop distinguishing anything. It is recorded as a skipped check
	// instead, which is the same treatment write probing already gets.
	//
	// This was got wrong first: an audit correctly found the default path
	// silent in the artifact, and the fix reported it as unmeasured, which
	// made exit 0 unreachable for anyone not passing -write.
	if r.Reachable && len(r.DeliveryTested) == 0 {
		return finding.Finding{}, false
	}
	var detail, why string
	switch {
	case !r.Reachable:
		detail = "the Realtime endpoint could not be reached"
		why = "0 relations tested, endpoint unreachable"
	default:
		detail = fmt.Sprintf("a change was caused on %d relation(s) and no payload arrived",
			len(r.DeliveryTested))
		why = fmt.Sprintf("%d relations changed, 0 payloads delivered", len(r.DeliveryTested))
	}
	return finding.Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "Realtime delivery could not be assessed",
		Severity: finding.Info,
		Protocol: "realtime",
		Matched:  strings.TrimSuffix(baseURL, "/") + "/realtime/v1/websocket",
		Resource: "realtime-delivery",
		Description: "Realtime exposure was not established: " + detail + ". A subscription " +
			"acknowledgement proves nothing — Supabase accepts one for a relation that does " +
			"not exist — so the only sound evidence is a delivered payload, and none was " +
			"observed. Realtime exposure here is UNMEASURED, not absent.",
		Remediation: "-- Confirm by hand: subscribe to postgres_changes for a relation you " +
			"believe is published and insert a row. Note that a relation added to the " +
			"publication may take a minute before the replication slot delivers, so an " +
			"immediate re-scan can report this same inconclusive result for a channel that " +
			"does work.",
		Evidence: finding.Evidence{
			Reason: why,
		},
	}, true
}
