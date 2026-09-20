// Package client is unruly's HTTP layer.
//
// Concurrency defaults come from measurement, not intuition. Sweeping a live
// PostgREST endpoint showed throughput peaking at 64 concurrent connections
// (701 req/s) and then collapsing: 128 gave 556 req/s, 256 gave 294, and 512
// gave 163 with p50 latency rising from 63ms to 2.2s. No 429s were ever
// returned, so this is server-side queueing rather than a rate-limit policy.
// Pushing past the knee makes a scan slower and noisier at the same time.
//
// Connection reuse mattered more than raw client speed: a process-per-request
// native client managed 251 req/s against Python-with-pooling at 323 req/s.
// Hence one shared transport with a generous idle pool.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	// maxBody caps how much of a response is kept. Findings quote samples, not
	// whole tables, so a megabyte is far more than any classification needs.
	maxBody = 1 << 20
	// drainLimit caps how much is read past maxBody purely to make the
	// connection reusable.
	drainLimit = 8 << 20
)

// DefaultConcurrency is a deliberate ceiling, not a saturation point.
//
// The name it carried -- "the measured saturation point of PostgREST" -- turned
// out to be wrong in both directions. Warm, this target does not saturate
// anywhere in the range worth probing: throughput was still climbing at 128,
// the highest level swept.
//
//	16  436 req/s    32  602 req/s    64  647 req/s
//	96  805 req/s   128 1047 req/s
//
// So 64 is not where the server gives up. It is a courtesy bound on how much
// load an unattended scanner should put on somebody else's database, chosen
// below the point where the curve would justify going further, and it is what
// -concurrency exists to override.
//
// It was carried for a hundred commits as "measured" with no measurement
// recorded and no test that would notice if it were wrong. Measuring it was
// nearly a mistake: a benchmark that read ONE relation repeatedly with
// count=exact reported 64 as far past the knee, and on that evidence the
// default was lowered to 16. End-to-end scans of the reference target said
// the opposite, decisively:
//
//	concurrency 16   49.1  50.7  36.8  41.9   median 45.5s
//	concurrency 64   25.9  27.3  17.5  39.0   median 26.6s
//
// The benchmark was unrepresentative. A scan is dominated by thousands of
// near-miss probes for names that do not exist -- cheap 404s where the cost is
// the round trip -- not by repeated expensive counted reads of one table,
// which contend on that table and saturate early.
//
// Fixing the request type was not enough: the corrected harness STILL reported
// 64 as past the knee. The cause was the harness itself. It built a fresh
// client per level, so 64 concurrent requests meant 64 simultaneous TLS
// handshakes from a cold pool, while a real scan reaches its bursty stages with
// connections already established. Warming the pool first, same target, same
// sweep:
//
//	concurrency 64, cold pool   118 req/s   493ms p50
//	concurrency 64, warm pool   487 req/s    66ms p50
//
// Four times the throughput from one line of setup. Throughput then keeps
// climbing through 64 and 96 instead of collapsing, which agrees with the
// end-to-end timings above and vindicates the original value.
//
// The lesson is kept because the failure mode was not a wrong number. It was a
// measurement that looked rigorous -- nine levels, three repeats, medians --
// and measured the harness instead of the target. Two independent projects
// agreed with each other and were both wrong about the thing being decided.
const DefaultConcurrency = 64

// Options configures a Client.
type Options struct {
	ProjectRef string
	// BaseURL overrides the derived https://<ref>.supabase.co origin. Needed
	// for self-hosted Supabase, and for the local eval fixture — a scanner
	// that can only reach the managed cloud is not generic.
	BaseURL string
	// RestPrefix is the path PostgREST is mounted under. The managed product
	// routes it through Kong at /rest/v1; a bare self-hosted PostgREST serves
	// at the root. Configurable so both are reachable.
	RestPrefix  string
	AnonKey     string
	Concurrency int
	Timeout     time.Duration
	Retries     int
	// Bearer overrides the Authorization token while apikey keeps naming the
	// project. Empty means "same as AnonKey", which is right for every
	// anonymous request.
	Bearer string
	// Schema selects a PostgREST schema other than the default.
	//
	// Supabase exposes more than one: every project serves public and
	// graphql_public, and projects add their own -- the reference target
	// exposes a third called staging. A scan that probes only the default
	// simply cannot see relations in the others, which is the same
	// false-negative shape as an enumerator that depends on the OpenAPI root:
	// it reports nothing and nothing is what a clean project looks like.
	//
	// Empty means the default schema, and no profile header is sent at all.
	Schema string
	// RefusalBudget is how many consecutive refusals -- 429, or a 5xx that
	// survived every retry -- this client will absorb from a host that has
	// never once given it a usable answer, before it stops issuing requests
	// altogether. Zero selects defaultRefusalBudget; negative disables it.
	RefusalBudget int
	// RateLimit caps requests per second. Zero means unlimited (still bounded
	// by Concurrency).
	RateLimit int
	// Limiter, when set, is shared with every other stage of the scan so the
	// rate the operator asked for is the rate the target receives.
	Limiter   *Limiter
	UserAgent string
	// MaxBody overrides how much of a response is kept. Zero selects maxBody.
	//
	// It exists because application fetches and API responses want different
	// numbers, and the difference is not a preference. A finding quotes rows,
	// so a megabyte is far more than any classification needs -- but a single
	// modern JS bundle routinely exceeds that, and a bundle truncated at a
	// megabyte silently loses the vocabulary, the project ref and the
	// credentials that happen to sit past the cut. The stages that read
	// applications asked for 8MB when they had their own clients, and moving
	// them onto this one must not quietly take that away.
	MaxBody int64
}

// Client issues bounded-concurrency requests against one Supabase project.
type Client struct {
	opts    Options
	http    *http.Client
	limiter *Limiter
	base    string
	// maxBody is this client's response cap; zero means the package default.
	maxBody int64

	// Request accounting. A scan that quietly lost requests may have quietly
	// lost findings, and a relation whose probe failed is indistinguishable
	// from one that does not exist — the same ambiguity that makes an
	// unsound probe unsound, arriving through the transport instead.
	// Shared by every client derived from this one. Requests sent under a
	// different bearer, key or schema still go to the same host, so "how much
	// did this scan send" and "is this host refusing" are properties of the
	// target, not of whichever credential a stage happened to hold.
	//
	// These were per-client. Nothing ever read the derived clients' totals, so
	// the schema and escalation passes were invisible in the request count the
	// report prints, and each derived client got a fresh refusal budget to
	// spend against a host that had already refused everything.
	*counters
}

// counters is the per-target accounting shared across derived clients.
type counters struct {
	sent   atomic.Int64
	failed atomic.Int64

	// The circuit breaker.
	//
	// Measured against a fixture that answers 429 to everything instantly: a
	// scan spent 2m6s and 1,827 requests and learned nothing -- 0 relations,
	// every surface unassessed. The plan runs to completion because no single
	// stage can see that the whole target is refusing; each one only sees its
	// own probes come back unusable, which is exactly what a well-protected
	// project looks like.
	//
	// Pouring seventeen hundred requests into a rate limiter is not thorough.
	// It is slow, it is rude, and on infrastructure that answers 429 because a
	// WAF is watching, it is how the operator running this ends up blocked.
	//
	// So: count consecutive refusals, and give up when the host has said
	// nothing useful at all. The "at all" is the safety catch -- a project
	// that serves five hundred good answers and then starts rate-limiting is
	// not refusing, it is throttling, and the right response there is the
	// backoff that already exists. Recall must never be traded for speed
	// against a target that was talking to us.
	refusals atomic.Int64
	useful   atomic.Int64
	gaveUp   atomic.Bool

	// A credential the project rejects.
	//
	// Distinct from a refusal, and far more common in the wild. Measured
	// against a fixture whose bundle carries a service_role key the project
	// will not accept: the scan adopted it, sent 18,755 requests, was answered
	// 401 every single time, and reported "0 relations ... cannot be
	// distinguished from a target with no relations". The reason was knowable
	// after the first answer -- this key does not work here -- and the report
	// instead described a project it had never once been allowed to look at.
	//
	// Keys are rejected for ordinary reasons: rotated since the bundle was
	// built, harvested from an archive, belonging to a different project, or a
	// service_role key that the gateway will not accept from a browser origin.
	//
	// 401 still counts as USEFUL for the refusal breaker above -- a 401 wall is
	// the target answering, and a host that answers is worth continuing with.
	// This is the narrower question of whether OUR credential is being taken,
	// and it needs its own counter because the two have opposite answers on the
	// same status code.
	authRejects atomic.Int64
	accepted    atomic.Int64
	keyRejected atomic.Bool
}

// defaultRefusalBudget is deliberately larger than any transient blip and far
// smaller than a scan plan. Twenty-five consecutive refusals with nothing
// usable in between is not a blip; it is a wall.
const defaultRefusalBudget = 25

// bodyLimit is how much of a response this client keeps.
func (c *Client) bodyLimit() int64 {
	if c.maxBody > 0 {
		return c.maxBody
	}
	return maxBody
}

// ErrRefused is returned, without sending anything, once the breaker is open.
// It is distinct from a timeout on purpose: callers must be able to tell "the
// target refused" from "we never asked".
var ErrRefused = errors.New("target refused every request; stopped asking")

// KeyRejected reports whether every answer so far has been an authentication
// rejection, which means nothing measured by this client is a statement about
// the project.
func (c *Client) KeyRejected() bool { return c.keyRejected.Load() }

// GaveUp reports whether the breaker opened. The scan reports this rather than
// presenting a target it never measured as one it found nothing wrong with.
func (c *Client) GaveUp() bool { return c.gaveUp.Load() }

// record classifies one completed request for the breaker.
//
// A refusal is 429, a 5xx that outlived its retries, or no answer at all.
// Anything else -- including a 401 or a 404 -- is useful: it is the target
// telling us something we can classify, which is all this needs to decide the
// host is worth continuing with.
func (c *Client) record(r Response) {
	refused := r.Err != nil || r.Status == 0 ||
		r.Status == http.StatusTooManyRequests || r.Status >= 500
	if !refused {
		c.useful.Add(1)
		c.refusals.Store(0)
		c.noteAuth(r)
		return
	}
	n := c.refusals.Add(1)
	if c.useful.Load() == 0 && n >= int64(c.refusalBudget()) {
		c.gaveUp.Store(true)
	}
}

// authRejectBudget is deliberately far higher than the refusal budget. Some
// endpoints answer 401 to a perfectly good anon key -- storage bucket listing
// and the auth admin routes among them -- so a handful of them proves nothing.
// Fifty answers with not one acceptance among them is a credential that does
// not work here.
const authRejectBudget = 50

// noteAuth separates "the target rejected our credential" from "the target
// answered". Called for every response that was not a refusal.
func (c *Client) noteAuth(r Response) {
	// 401 only, never 403.
	//
	// 401 is "I do not know who you are": the credential was not accepted.
	// 403 is "I know who you are and the answer is no", which is a RULES
	// decision and a perfectly normal answer to a well-formed request. Firestore
	// answers 403 to every collection that is protected OR does not exist --
	// the central ambiguity this scanner is built around -- so counting 403 here
	// read a healthy Firebase scan as a rejected credential and stopped it
	// before it ever reached the Realtime Database. Two evals caught it.
	if r.Status == http.StatusUnauthorized {
		if c.accepted.Load() == 0 && c.authRejects.Add(1) >= authRejectBudget {
			c.keyRejected.Store(true)
			c.gaveUp.Store(true)
		}
		return
	}
	c.accepted.Add(1)
}

func (c *Client) refusalBudget() int {
	switch {
	case c.opts.RefusalBudget < 0:
		return 1 << 30 // disabled
	case c.opts.RefusalBudget == 0:
		return defaultRefusalBudget
	default:
		return c.opts.RefusalBudget
	}
}

// Stats returns requests sent and requests that never produced a response.
func (c *Client) Stats() (sent, failed int64) {
	return c.sent.Load(), c.failed.Load()
}

// RestPrefix reports the configured PostgREST mount path. Providers use it in
// preparation findings when the target proves that path wrong; exposing the
// value avoids duplicating command-line state outside the client that actually
// sent the request.
func (c *Client) RestPrefix() string { return c.opts.RestPrefix }

// Retries reports the configured retry count so a provider can declare a
// preparation request bound in wire attempts rather than logical calls.
func (c *Client) Retries() int { return c.opts.Retries }

// Response is a captured HTTP exchange, kept whole so findings can quote it.
type Response struct {
	Status  int
	Header  http.Header
	Body    []byte
	Request string // replayable curl line
	Err     error
}

// ContentRange returns the raw Content-Range header.
func (r Response) ContentRange() string { return r.Header.Get("Content-Range") }

// DecodeError parses a PostgREST error envelope, if present.
func (r Response) DecodeError() (code, message, hint string) {
	var b struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Hint    string `json:"hint"`
	}
	if json.Unmarshal(r.Body, &b) == nil {
		return b.Code, b.Message, b.Hint
	}
	return "", "", ""
}

// DecodeRows parses a PostgREST array payload into rows.
func (r Response) DecodeRows() []map[string]any {
	var rows []map[string]any
	if json.Unmarshal(r.Body, &rows) == nil {
		return rows
	}
	return nil
}

// New builds a Client with a shared, pooled transport.
func New(o Options) *Client {
	if o.Concurrency <= 0 {
		o.Concurrency = DefaultConcurrency
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.UserAgent == "" {
		o.UserAgent = UserAgent()
	}
	tr := transportFor(o.Concurrency)
	o.RestPrefix = normalisePrefix(o.RestPrefix)
	o.BaseURL = trimDuplicatePrefix(o.BaseURL, o.RestPrefix)
	c := &Client{
		opts: o,
		http: &http.Client{
			Transport: tr,
			Timeout:   o.Timeout,
			// Never follow a redirect.
			//
			// This client sends the project's credentials on every request:
			// apikey, and Authorization when a key or user JWT is in play. Go
			// strips Authorization when a redirect crosses domains, but apikey
			// is a CUSTOM header and nothing strips it -- so a host that
			// answers 302 harvests the credential from any scanner that
			// follows. Measured before this was added: a redirect from the
			// target to a second origin delivered
			// apikey="SECRET-PROJECT-KEY" AND the bearer token to the second
			// origin.
			//
			// That matters because pointing this tool at a host you do not
			// control is its ENTIRE purpose. A scanner that hands the
			// operator's key to the thing it is scanning is a liability
			// whatever else it gets right.
			//
			// Nothing is lost. PostgREST, GoTrue, Storage and Realtime do not
			// redirect in normal operation; a 3xx from them is a
			// misconfiguration or a hostile host, and either way the redirect
			// itself is the interesting answer. internal/routes already
			// refused to follow for the same reason -- "redirects to a login
			// page are an auth decision" -- and this is the same argument
			// applied to the credential-bearing client.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		base:     baseURL(o),
		counters: &counters{},
		maxBody:  o.MaxBody,
	}
	c.limiter = o.Limiter
	if c.limiter == nil {
		c.limiter = NewLimiter(o.RateLimit)
	}
	return c
}

// WithKey returns a client for the same target using a different credential,
// sharing the underlying transport so connections are reused across roles.
// WithBearer returns a client that keeps the project's anon key in the apikey
// header and presents a different token as the bearer.
//
// This is the only correct shape for an elevated read against a managed
// project. Supabase's gateway authenticates the PROJECT from apikey and the
// CALLER from Authorization, so replacing both with a user JWT answers
// "Invalid API key" for every request:
//
//	apikey=JWT   Authorization=Bearer JWT   -> {"message":"Invalid API key"}
//	apikey=anon  Authorization=Bearer JWT   -> the authenticated role's rows
//
// The escalation stage used WithKey, which swaps both, so -user-jwt measured
// nothing against any real project and reported "0 relations that anon cannot
// read" — a clean-looking result produced entirely by rejected requests. The
// fixtures could not catch it: bare PostgREST ignores apikey altogether and
// reads the JWT from Authorization, so swapping both works there and only
// there.
func (c *Client) WithBearer(token string) *Client {
	o := c.opts
	o.Bearer = token
	return &Client{opts: o, http: c.http, limiter: c.limiter, base: c.base, counters: c.counters}
}

// WithKey returns a client authenticating as a different project credential.
// For a USER token use WithBearer: this replaces the apikey too, which a
// managed project rejects.
func (c *Client) WithKey(key string) *Client {
	o := c.opts
	o.AnonKey = key
	o.Bearer = ""
	return &Client{opts: o, http: c.http, limiter: c.limiter, base: c.base, counters: c.counters}
}

// WithRestPrefix returns a client addressing PostgREST under a different path,
// sharing this one's transport, limiter, credentials and counters.
//
// The managed product routes PostgREST through Kong at /rest/v1; a self-hosted
// or bare deployment serves it at the root. Getting that wrong is not a partial
// scan, it is a total one: every probe is answered PGRST125 by PostgREST itself
// and the report says "0 relations", which reads exactly like a project with
// nothing exposed.
// WithBase returns a client pointed at a different origin, keeping the HTTP
// client, the limiter and the counters.
//
// A stage that builds its own URLs does not need this; a stage that hands the
// client to a shared package which builds URLs from RestURL does, because that
// package cannot know the base the stage was configured with. backend/neon's
// enumerate stage is the case: internal/enumerate probes c.RestURL(name), and
// giving it the scan-wide client sent every probe to a path that does not exist
// -- 887 candidates, no hints, and a report saying the API volunteered nothing.
// The oracle was working the whole time; it was being asked the wrong URL.
func (c *Client) WithBase(base string) *Client {
	o := c.opts
	o.BaseURL = base
	return &Client{opts: o, http: c.http, limiter: c.limiter,
		base: strings.TrimSuffix(base, "/"), counters: c.counters}
}

func (c *Client) WithRestPrefix(prefix string) *Client {
	o := c.opts
	o.RestPrefix = normalisePrefix(prefix)
	return &Client{opts: o, http: c.http, limiter: c.limiter, base: c.base, counters: c.counters}
}

// transportFor returns the shared transport for a pool size.
//
// Shared, because a transport is a connection POOL and one per client means no
// reuse between them. That is invisible in a scan -- one target, one client --
// and expensive everywhere else: the eval suite builds a client per test, each
// dialling up to twice the concurrency cap, and around fifty of them exhausted
// this machine's ephemeral port range mid-audit. Measured while diagnosing it:
// 11,410 sockets in TIME_WAIT to one fixture port against a range of 16,384,
// and three audit runs lost to it.
//
// Connection pools inside a transport are already per-host, so sharing one
// across clients pointed at different targets keeps their connections apart.
// Timeouts live on the http.Client, not here, so they stay per-client.
//
// Keyed by pool size because that is the only field that varies, and a scan
// that lowers -concurrency must not inherit a pool sized for the default.
var (
	transportsMu sync.Mutex
	transports   = map[int]*http.Transport{}
)

func transportFor(concurrency int) *http.Transport {
	transportsMu.Lock()
	defer transportsMu.Unlock()
	if tr, ok := transports[concurrency]; ok {
		return tr
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		// Size the pool to the concurrency cap so connections are reused
		// rather than renegotiated; TLS handshakes dominate otherwise.
		MaxIdleConns:          concurrency * 2,
		MaxIdleConnsPerHost:   concurrency * 2,
		MaxConnsPerHost:       concurrency * 2,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}
	transports[concurrency] = tr
	return tr
}

// normalisePrefix puts the mount path in the one form the URL builders expect:
// no trailing slash, and EMPTY for the root rather than "/".
//
// Shared because it was not. New normalised; WithRestPrefix did not, so a
// client moved to the root built every URL with a doubled slash -- a different
// path, which PostgREST answers 404 -- and the prefix correction that exists to
// rescue a scan silently produced the same empty report it was written to
// prevent.
func normalisePrefix(p string) string {
	if p == "" {
		return "/rest/v1"
	}
	if p = "/" + strings.Trim(p, "/"); p == "/" {
		return ""
	}
	return p
}

// WithSchema returns a client that speaks to a different PostgREST schema,
// sharing this one's transport, limiter and credentials.
func (c *Client) WithSchema(schema string) *Client {
	o := c.opts
	o.Schema = schema
	return &Client{opts: o, http: c.http, limiter: c.limiter, base: c.base, counters: c.counters}
}

// Schema reports which schema this client addresses; empty is the default.
func (c *Client) Schema() string { return c.opts.Schema }

// baseURL resolves the API origin, preferring an explicit override.
func baseURL(o Options) string {
	if o.BaseURL != "" {
		return strings.TrimRight(o.BaseURL, "/")
	}
	return fmt.Sprintf("https://%s.supabase.co", o.ProjectRef)
}

// BaseURL is the project's API origin.
func (c *Client) BaseURL() string { return c.base }

// RestURL builds a PostgREST URL for a relation.
func (c *Client) RestURL(relation string) string {
	return c.base + c.opts.RestPrefix + "/" + relation
}

// RestBase is the origin plus the PostgREST mount path. Findings use it so
// the replayable request in the evidence points where the scan actually went.
func (c *Client) RestBase() string { return c.base + c.opts.RestPrefix }

// RPCURL builds a PostgREST URL for a routine.
func (c *Client) RPCURL(name string) string {
	return c.base + c.opts.RestPrefix + "/rpc/" + name
}

// Do issues one request with retries. It never returns a nil Response, so
// callers can always record evidence.
func (c *Client) Do(ctx context.Context, method, url string, body []byte, hdr map[string]string) Response {
	if c.gaveUp.Load() {
		return Response{Err: ErrRefused, Request: curlLine(method, url, hdr, body)}
	}
	var last Response
	attempts := c.opts.Retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		c.limiter.Wait(ctx)
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rdr)
		if err != nil {
			return Response{Err: err, Request: curlLine(method, url, hdr, body)}
		}
		// Only when there is one. Setting apikey:"" and "Authorization: Bearer "
		// with nothing after it is not a neutral act: Google's APIs reject an
		// empty bearer outright, so every Firestore probe answered 401 and the
		// Firebase provider reported a wide-open project as clean. A credential
		// this client does not have is a header it must not send.
		if c.opts.AnonKey != "" {
			req.Header.Set("apikey", c.opts.AnonKey)
		}
		// The gateway authenticates the project from apikey and the caller from
		// Authorization. They are the same credential for an anonymous scan and
		// deliberately different for an elevated one.
		bearer := c.opts.AnonKey
		if c.opts.Bearer != "" {
			bearer = c.opts.Bearer
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		req.Header.Set("User-Agent", c.opts.UserAgent)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		// PostgREST selects the schema per request: Accept-Profile for reads,
		// Content-Profile for writes. Both are set because a request is one or
		// the other and sending the unused one costs nothing. Set BEFORE the
		// caller's own headers so an explicit override still wins.
		if c.opts.Schema != "" {
			req.Header.Set("Accept-Profile", c.opts.Schema)
			req.Header.Set("Content-Profile", c.opts.Schema)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}

		c.sent.Add(1)
		resp, err := c.http.Do(req)
		if err != nil {
			last = Response{Err: err, Request: curlLine(method, url, hdr, body)}
			c.record(last)
			if c.gaveUp.Load() {
				return last
			}
			continue
		}
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, c.bodyLimit()))
		// Drain what the read limit left behind before closing. Go returns a
		// connection to the pool only when the body reaches EOF; closing a
		// partially read body discards it instead, silently. Measured: ten
		// responses over the limit opened ten connections, so every large
		// response was paying a fresh TCP and TLS handshake.
		//
		// The drain is itself bounded. A response larger than drainLimit is
		// not worth the bytes to skip past, and letting that connection go is
		// cheaper than reading a gigabyte to save a handshake.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
		resp.Body.Close()
		out := Response{
			Status:  resp.StatusCode,
			Header:  resp.Header,
			Body:    payload,
			Request: curlLine(method, url, hdr, body),
		}
		// Retry only on transient server-side conditions. Any 4xx is a real
		// answer and must be classified, never retried away.
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			last = out
			c.record(out)
			if c.gaveUp.Load() {
				return out
			}
			// Back off before trying again.
			//
			// This used to retry immediately, bounded only by the steady rate
			// limiter. A 429 is the target saying "you are asking too fast",
			// and answering it by asking again at the same rate is both rude
			// and useless: the retry budget is spent on responses that were
			// never going to succeed, and the scan ends up reporting the
			// surface as unresolved anyway.
			//
			// It matters most where this tool is least welcome. Pointed at
			// infrastructure nobody involved owns, ignoring an explicit
			// slow-down request is the difference between measurement and
			// nuisance.
			// Only back off if there is actually another attempt to make.
			//
			// This slept unconditionally, including on the final attempt, so
			// every request that ended in a 429 paid a delay for a retry that
			// never came. Measured on a host answering 429 to everything with
			// retries disabled: fifty requests took twenty-five seconds, all
			// of it spent waiting to do nothing.
			if attempt == attempts-1 {
				return out
			}
			if !sleepCtx(ctx, retryDelay(attempt, resp.Header)) {
				return out
			}
			continue
		}
		c.record(out)
		return out
	}
	if last.Err != nil || last.Status == 0 {
		// Every attempt was exhausted without a usable answer.
		c.failed.Add(1)
	}
	// Not recorded here: every path through the loop above already recorded
	// its own attempt, and counting the last one twice would open the breaker
	// early on a target that was merely retrying.
	return last
}

// Get issues a GET.
func (c *Client) Get(ctx context.Context, url string, hdr map[string]string) Response {
	return c.Do(ctx, http.MethodGet, url, nil, hdr)
}

// Map runs fn over items with bounded concurrency, returning results in INPUT
// order. Order independence is what makes a concurrent scan deterministic.
func Map[T any, R any](ctx context.Context, concurrency int, items []T, fn func(context.Context, T) R) []R {
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	out := make([]R, len(items))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for i, it := range items {
		i, it := i, it
		g.Go(func() error {
			out[i] = fn(gctx, it)
			return nil
		})
	}
	_ = g.Wait()
	return out
}

// curlLine renders a replayable command. The API key is redacted: evidence is
// meant to be pasted into a ticket.
func curlLine(method, url string, hdr map[string]string, body []byte) string {
	var b strings.Builder
	b.WriteString("curl -X " + method + " '" + url + "'")
	b.WriteString(" -H 'apikey: $SUPABASE_ANON_KEY'")
	keys := make([]string, 0, len(hdr))
	for k := range hdr {
		keys = append(keys, k)
	}
	// Deterministic header order in evidence output.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		b.WriteString(" -H '" + k + ": " + hdr[k] + "'")
	}
	if body != nil {
		b.WriteString(" -d '" + string(body) + "'")
	}
	return b.String()
}

// ReadBody reads up to limit bytes of a response, then drains and closes it.
//
// The draining is the part that is easy to forget, and forgetting it costs
// performance rather than correctness, which is why it survives review. Go
// returns a connection to the pool only when the body reaches EOF; closing a
// partially read body discards it. Measured in this package's tests: ten
// responses larger than the read limit opened ten connections instead of one.
//
// Every place that reads a response with a size cap should use this, so the
// next such cap does not reintroduce the same leak.
func ReadBody(resp *http.Response, limit int64) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	// Bounded: skipping past a response far larger than the cap costs more
	// than the handshake it would save.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
	return b, err
}

// Discard throws a response body away and keeps the connection reusable.
//
// The obvious `resp.Body.Close()` on a path that does not want the body is
// the same leak as a truncated read: the body never reaches EOF, so Go drops
// the connection. It matters most on the paths that discard bodies most
// often -- a 429 or 5xx that is about to be retried against the same host.
func Discard(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
	resp.Body.Close()
}

// retryDelay decides how long to wait before retrying a 429 or 5xx.
//
// Retry-After is honoured when the target sends one, in either form the RFC
// allows: a number of seconds, or an HTTP date. It is capped, because a server
// asking for an hour is not a request this scan can usefully wait out, and the
// finding "the surface could not be assessed" is the honest answer in that
// case.
//
// Without a header, exponential backoff from a small base. The first retry is
// quick because most 5xx are transient; later ones give real trouble room.
func retryDelay(attempt int, h http.Header) time.Duration {
	const maxWait = 15 * time.Second
	if v := h.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs >= 0 {
			return min(time.Duration(secs)*time.Second, maxWait)
		}
		if when, err := http.ParseTime(strings.TrimSpace(v)); err == nil {
			if d := time.Until(when); d > 0 {
				return min(d, maxWait)
			}
			return 0
		}
	}
	d := 500 * time.Millisecond * (1 << attempt)
	return min(d, maxWait)
}

// sleepCtx waits, and reports false if the scan was cancelled while waiting.
// A backoff that ignores cancellation turns Ctrl-C into a fifteen-second pause
// per in-flight request.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// AppOptions configures a client for traffic aimed at an APPLICATION rather
// than a backend: a site's HTML, its JS bundles, its own routes.
//
// A separate type, and a short one, because the difference between the two
// kinds of client is not a matter of taste. An application is somebody's web
// server; it may not even be run by the same party as the database, and it
// must never receive that database's credential.
type AppOptions struct {
	Site        string
	Timeout     time.Duration
	Concurrency int
	Retries     int
	RateLimit   int
	Limiter     *Limiter
	UserAgent   string
}

// NewApplication builds the one client every stage uses to read applications.
//
// Before this existed, three stages each built a bare http.Client: three
// connection pools to one host, no retry policy, no circuit breaker, and in
// one case no rate limiting either. A site answering 429 to every request was
// asked 131 times with no backoff, while the database at the other end of the
// same scan was handled correctly.
//
// Two things are decided here rather than by callers, because getting either
// wrong is a defect and not a preference:
//
//   - No credential, ever. ProjectRef, AnonKey and Bearer are cleared rather
//     than left to the caller to omit, so a future stage cannot leak a
//     Supabase key to a web server by forgetting a field.
//   - A larger body cap. A single modern JS bundle routinely exceeds the 1MB
//     that is generous for an API response, and a bundle cut short silently
//     loses whatever vocabulary, project ref or credential sat past the cut.
func NewApplication(o AppOptions) *Client {
	return New(Options{
		BaseURL:    o.Site,
		RestPrefix: "/",
		// Cleared, not omitted: see above.
		ProjectRef:  "",
		AnonKey:     "",
		Bearer:      "",
		Schema:      "",
		Concurrency: o.Concurrency,
		Timeout:     o.Timeout,
		Retries:     o.Retries,
		RateLimit:   o.RateLimit,
		Limiter:     o.Limiter,
		UserAgent:   o.UserAgent,
		MaxBody:     applicationMaxBody,
	})
}

// applicationMaxBody is what the application stages read before this client
// existed: discover asked for 8MB, routes for 8MB, vocabulary for 4MB. The
// largest of the three is kept, because the smaller ones were not chosen as
// limits so much as inherited.
const applicationMaxBody = 8 << 20

// trimDuplicatePrefix removes the REST prefix from a base that already carries
// it, so it is not appended a second time.
//
// Pasting the full REST URL is the obvious thing to do: it is what the vendor
// console displays and what an operator copies. Appending the default prefix
// to it produced /rest/v1/rest/v1, and the damage was not the wasted request.
// Every probe 404s, so the control for a relation that CANNOT exist got the
// same clean 404 as one that can -- the target looked like it reports absence
// correctly while nothing had been reached at all. Measured against a live
// Neon Data API: the scan then ran a fallback expansion it would otherwise
// have skipped, spent 1200 probes asking somebody's project for paths that
// cannot exist, and reported 0 relations with three degraded capabilities.
//
// It is a SUFFIX test, not a contains test. A base of
// https://example.com/rest/v1/api genuinely needs the prefix appended: the
// segment appears in the middle of its path and says nothing about where
// PostgREST is mounted.
func trimDuplicatePrefix(base, prefix string) string {
	if base == "" || prefix == "" {
		return base
	}
	trimmed := strings.TrimSuffix(base, "/")
	if !strings.HasSuffix(trimmed, prefix) {
		return base
	}
	return strings.TrimSuffix(trimmed, prefix)
}
