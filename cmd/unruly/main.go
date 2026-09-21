// Command unruly scans application and *base backends for misconfigurations.
//
// Flag layout, logging and result format follow ProjectDiscovery conventions
// so output composes with existing pipelines.
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/creds"
	"github.com/eppser/unruly/internal/engine"
	"github.com/eppser/unruly/internal/enumerate"
	"github.com/eppser/unruly/internal/escalate"
	"github.com/eppser/unruly/internal/finding"
	"github.com/eppser/unruly/internal/handoff"
	"github.com/eppser/unruly/internal/history"
	"github.com/eppser/unruly/internal/intent"
	"github.com/eppser/unruly/internal/mailbox"
	"github.com/eppser/unruly/internal/probe"
	"github.com/eppser/unruly/internal/provider"
	"github.com/eppser/unruly/internal/wordlist"
	"github.com/eppser/unruly/scan"
)

var version = "0.1.0-beta"

const banner = `
                        _
 _  _  _ _   _ _  _  _ | | _  _
| || || ' \ | '_|| || || || || |
 \_,_||_||_||_|   \_,_||_| \_, |
                           |__/
`

// examples are shown by -h and by a bare invocation.
//
// Running with no arguments used to attempt a scan of nothing: it emitted a
// not-assessed finding about an empty target and exited 3, which is a
// could-not-measure verdict about a scan nobody asked for. A first-time user
// deserves the shape of a working command instead.
const examples = `Examples:
  # Point it at an application. Everything else is discovered: the project
  # reference, the anon key, the table names.
  unruly -u https://my-app.lovable.app

  # Same scan, with the SQL that closes each finding.
  unruly -u https://my-app.lovable.app -fix

  # A report to keep, with the rows redacted so it can be shared.
  unruly -u https://my-app.lovable.app -redact -json -o report.jsonl

  # Establish exposure WITHOUT retrieving anyone's rows. Use this for a
  # project you do not own.
  unruly -u https://my-app.lovable.app -measure

  # Also test whether an anonymous caller can INSERT. Writes to the target,
  # so it is gated on you saying the project is yours.
  unruly -u https://my-app.lovable.app -write -yes-i-own-this

Exit codes: 0 clean and fully measured, 2 findings at high or above,
3 something could not be assessed — which is not a clean result.
`

type options struct {
	target     string
	list       string
	projectRef string
	anonKey    string
	site       string
	baseURL    string
	restPrefix string
	// provider is POSITIVE SELECTION: the operator naming what the target
	// runs. A credential is not that statement -- see supabaseSelected.
	provider string
	// routeParams are -route-param values: identifiers the operator supplies
	// for path templates, so /invoices/{id} can be probed as a record THEY
	// named rather than one this scan invented.
	routeParams stringList
	// principals are -principal values: labelled identities used to ask
	// whether one account can read another's record. Two are needed; one
	// cannot distinguish a broken ownership check from a public catalogue.
	principals stringList
	// allowedOrigins are exact cross-origin application backends the operator
	// explicitly placed in scan scope.
	allowedOrigins stringList
	// harFiles are browser/runtime inventories whose URL+method pairs augment
	// static route discovery without retaining captured credentials or bodies.
	harFiles stringList
	// intentFile is the versioned access-policy manifest to verify against
	// measured facts.
	intentFile string
	// apiLocated records that the OPERATOR said where the API is, captured
	// before the program starts inferring it.
	//
	// baseURL cannot be read for this at gate time: resolveOrigin assigns
	// o.baseURL = o.target for any URL target, so by then the field is
	// non-empty on every scan and the gate passes always. Measured -- the
	// gate's unit tests were green while the built binary sent 2,725 requests
	// at a plain website.
	apiLocated  bool
	concurrency int
	rateLimit   int
	timeout     int
	retries     int
	severity    string
	write       bool
	confirmOwn  bool
	fix         bool
	redact      bool
	jsonOut     bool
	agentOut    bool
	// proven keeps only findings something was retrieved for: rows came back,
	// a write was accepted, or the values were classified. See
	// finding.Writer.Proven -- it filters OUTPUT, never the verdict.
	proven         bool
	csvOut         bool
	plain          bool
	htmlOut        string
	output         string
	silent         bool
	noColor        bool
	verbose        bool
	stats          bool
	showVersion    bool
	sampleRows     int
	noResidue      bool
	mailbox        string
	maxRPC         int
	maxRelation    int
	maxSeeds       int
	maxCollections int
	vocabOnly      bool
	// emitVocab writes the harvested vocabulary to a file and stops; vocabFile
	// reads one back. Between the two, anything may edit the list -- an
	// operator who knows the schema, an agent reading the application, or a
	// tool that parses an artifact unruly cannot. See internal/handoff.
	emitVocab       string
	vocabFile       string
	maxBundles      int
	maxRoutes       int
	maxBypassRoutes int
	maxPages        int
	measure         bool
	maxColProbe     int
	userAgent       string
	// keyWithheldRef names the project the supplied key belongs to, when it
	// was deliberately not sent to this target.
	keyWithheldRef string
	userJWT        string
	invoke         bool
	skipRoutes     bool
	subdomains     bool
	skipRealtime   bool
	checkHistory   bool
	previewHosts   string
	archiveBase    string
	// keyFromEnv records that anonKey came from SUPABASE_ANON_KEY rather than
	// from -k. An env var is ambient context about the operator's own work,
	// not an instruction about the target in front of them.
	keyFromEnv bool
	// keyDiscovered records that anonKey was harvested from the target's own
	// client-side content rather than supplied. It matters only when the key
	// turns out not to work: "the key you gave me was rejected" and "the key
	// your application ships was rejected" send the reader to different places.
	keyDiscovered bool
	// inList marks a target scanned as part of -l. A mismatched key is fatal
	// for a single target (the operator meant something else) and merely
	// dropped for a list entry (the other entries are still worth scanning).
	inList bool

	// Data classification by a local model. Empty endpoint means off, which is
	// the default and must stay a working no-op.
	classifier          string
	classifierModel     string
	classifierThreshold int
}

// resolveClassifier turns -classifier into an endpoint, once, before the scan.
//
// "auto" asks discover to look; anything else is taken literally and nothing
// is probed. Resolving once rather than per column keeps a run's behaviour
// fixed: a report should not depend on when a model server happened to start.
//
// A failed auto returns a warning rather than an error. The scan is still
// worth running -- the rules are the part that proves things -- but an
// operator who asked for a classifier and silently got none would read a
// rule-only report as a complete one.
func resolveClassifier(flag string, discover func() string) (endpoint, warning string) {
	if flag != "auto" {
		return flag, ""
	}
	if ep := discover(); ep != "" {
		return ep, ""
	}
	return "", "-classifier auto found no local model server on loopback; " +
		"continuing with the deterministic rules only. Start one (ollama serve, " +
		"or llama-server --port 8080) or pass the endpoint directly."
}

// newFlagSet registers every flag.
//
// Extracted from main so the flag surface can be tested: a previous commit
// advertised -classifier in an error message before the flag existed, and the
// only check that noticed was a source-parsing audit.
func newFlagSet(o *options) *goflags.FlagSet {
	fs := goflags.NewFlagSet()
	fs.SetDescription("unruly — deterministic Supabase misconfiguration scanner\n\n" + examples)

	fs.CreateGroup("input", "Input",
		fs.StringVarP(&o.target, "target", "u", "", "target site or Supabase URL to scan"),
		fs.StringVarP(&o.list, "list", "l", "", "file of targets, one per line (# comments ignored)"),
		fs.StringVarP(&o.projectRef, "project-ref", "p", "", "Supabase project reference (skips discovery)"),
		fs.StringVarP(&o.anonKey, "key", "k", "", "anon/publishable key (env: SUPABASE_ANON_KEY)"),
		fs.StringVarP(&o.site, "site", "s", "", "application URL to harvest vocabulary from"),
		fs.StringVar(&o.baseURL, "base-url", "", "API origin override for self-hosted Supabase"),
		fs.StringVar(&o.restPrefix, "rest-prefix", "/rest/v1", "PostgREST mount path (use / for bare PostgREST)"),
		fs.Var(&o.principals, "principal", "a labelled identity for cross-account "+
			"checks (repeatable: -principal a=<jwt> -principal b=<jwt>). TWO are "+
			"needed: with one there is no third answer to compare against, and a "+
			"public catalogue looks identical to a broken ownership check"),
		fs.Var(&o.routeParams, "route-param", "supply a value for a path template so "+
			"an endpoint like /invoices/{id} can be probed (repeatable: -route-param "+
			"id=42). Without one the template is left alone: inventing an identifier "+
			"means requesting somebody's record on nobody's authority"),
		fs.Var(&o.allowedOrigins, "allow-origin", "include this exact cross-origin "+
			"application backend in route probing (repeatable). A bundle mention is "+
			"reported but never widens scan scope by itself"),
		fs.Var(&o.harFiles, "har", "ingest runtime route URLs from this HAR file "+
			"(repeatable; headers, cookies and bodies are never retained; cross-origin "+
			"URLs still require -allow-origin)"),
		fs.StringVar(&o.intentFile, "intent", "", "verify measured access against a "+
			"versioned YAML intent manifest; unmeasured expectations remain unverified"),
		fs.StringVar(&o.provider, "provider", "", "scan this backend even without "+
			"evidence of it at the target (currently: supabase). A credential is not "+
			"evidence: an anon key says what you hold, not what the target runs"),
	)

	fs.CreateGroup("probes", "Probes",
		// This description is the consent notice. It said "issues INSERT" while
		// the flag had grown to permit four kinds of write, including invoking
		// functions that send email and routines that delete rows. A user
		// cannot authorise what they have not been told.
		// Two levels, because the risks are not comparable. -write creates data:
		// an INSERT the probe cleans up, and a POST to an application route.
		// -invoke RUNS code the operator did not write — a database routine or
		// an Edge Function — which may send email, charge a card or delete
		// rows. Bundling them made a user authorising "a test INSERT" also
		// authorise executing arbitrary functions.
		fs.BoolVarP(&o.write, "write", "w", false,
			"permit writes: INSERT into relations, and POST to application routes "+
				"(requires -yes-i-own-this)"),
		fs.BoolVar(&o.invoke, "invoke", false,
			"additionally CALL discovered database routines and Edge Functions to learn "+
				"whether they are reachable. Calling one RUNS it: a routine named purge or "+
				"a function named send-email does what it says (requires -write)"),
		fs.BoolVar(&o.confirmOwn, "yes-i-own-this", false,
			"confirm you are authorised to send those writes to this target"),
		fs.IntVar(&o.sampleRows, "sample", 3, "rows to sample as proof for each exposed relation"),
		fs.BoolVar(&o.noResidue, "no-residue", false,
			"write-probe only where an INSERT should be rejected before a row is created: "+
				"re-send a sampled row so the primary key collides, and decline to probe "+
				"relations this scan cannot read (costs write recall on those)"),
		fs.IntVar(&o.maxRPC, "max-rpc-probes", 1200,
			"maximum RPC NAMES probed; each costs up to two requests, and secondary "+
				"schemas may spend half the budget between them"),
		// Relation probing is the largest single source of traffic this tool
		// produces: the fallback expansion is ~13,700 requests, more than ten
		// times the RPC budget, and it had no cap while RPC probing did. An
		// operator scanning infrastructure that is theirs but shared needs a
		// number they can lower, and a courtesy control that covers the small
		// half of the traffic is not a courtesy control.
		fs.IntVar(&o.maxRelation, "max-relation-probes", 15000,
			"maximum relation name probes in the fallback expansion, which runs only "+
				"when no vocabulary could be harvested"),
		// Exposed because the scan now reports when this bound binds, and a
		// finding that says "re-run with more" has to name a flag that exists.
		fs.IntVar(&o.maxPages, "max-pages", 8,
			"maximum LINKED pages read from the application to harvest vocabulary, "+
				"beyond the conventional paths. Recall is a function of the words a "+
				"project uses about itself, and half of those live one link away. Same "+
				"origin only; 0 disables it"),
		fs.IntVar(&o.maxBundles, "max-bundles", 8,
			"maximum JS bundles read from the application; unread bundles lower the "+
				"vocabulary before it is assembled"),
		fs.IntVar(&o.maxRoutes, "max-routes", 200,
			"maximum application endpoint paths probed across all explicitly scoped "+
				"origins; allocation is round-robin so one origin cannot consume the bound"),
		fs.IntVar(&o.maxBypassRoutes, "max-bypass-routes", 20,
			"maximum refused application paths given the alternative-request bypass "+
				"matrix; each selected path costs ten read-only variants"),
		fs.StringVar(&o.emitVocab, "emit-vocab", "",
			"harvest the application's vocabulary to this file and stop, without "+
				"probing any backend"),
		fs.StringVar(&o.vocabFile, "vocab", "",
			"read candidate relation and routine names from a vocabulary file "+
				"(see -emit-vocab); merged with anything harvested"),
		fs.BoolVar(&o.vocabOnly, "vocab-only", false,
			"probe ONLY the names given by -vocab, skipping the pinned list and "+
				"anything harvested; every probe is metered on the project being "+
				"scanned, and an operator who already knows their schema should not "+
				"pay for 884 guesses"),
		fs.IntVar(&o.maxCollections, "max-collections", 0,
			"maximum Firestore collection names to probe (0 = unbounded); every probe "+
				"is a metered read on the project being scanned"),
		fs.IntVar(&o.maxSeeds, "max-seeds", 2000,
			"maximum harvested vocabulary tokens; the seeds feed both relation and "+
				"routine discovery, so this bounds the recall of each"),
		fs.StringVar(&o.userJWT, "user-jwt", "", "authenticated JWT; re-reads relations as that role and reports the delta"),
		fs.BoolVar(&o.skipRoutes, "no-routes", false, "skip the application route authorisation check"),
		fs.BoolVar(&o.subdomains, "subdomains", false,
			"list other hosts under the target's domain; scans none of them"),
		fs.BoolVar(&o.skipRealtime, "no-realtime", false, "skip the Realtime subscription check"),
		fs.BoolVar(&o.checkHistory, "history", false, "search public web archives for previously shipped credentials"),
		fs.StringVar(&o.previewHosts, "preview", "",
			"comma-separated preview deployment hostnames to sweep for credentials. "+
				"Netlify and Cloudflare Pages hosts are derived from -site automatically; "+
				"Vercel's embed a team slug that cannot be guessed and must be given here"),
		fs.StringVar(&o.archiveBase, "archive", history.DefaultArchiveBase,
			"origin of the web archive to query: a mirror, a proxy, or a local "+
				"replay of a CDX response"),
	)

	fs.CreateGroup("rate-limit", "Rate limit",
		fs.IntVarP(&o.concurrency, "concurrency", "c", defaultConcurrency(),
			"concurrent requests (measured PostgREST saturation point is 64)"),
		fs.IntVarP(&o.rateLimit, "rate-limit", "rl", 0, "maximum requests per second (0 = unlimited)"),
		fs.IntVar(&o.timeout, "timeout", 15, "request timeout in seconds"),
		fs.IntVar(&o.retries, "retries", 1, "retries for 5xx and 429 responses"),
	)

	fs.CreateGroup("output", "Output",
		fs.StringVarP(&o.severity, "severity", "sv", "info", "minimum severity: info,low,medium,high,critical"),
		fs.BoolVar(&o.proven, "proven", false, "report only findings something was "+
			"actually retrieved for: rows came back, a write was accepted, or the "+
			"values were classified as sensitive. Implies -severity high. The exit "+
			"code and the coverage report are unchanged, because a quiet report is "+
			"not a clean one"),
		fs.BoolVar(&o.fix, "fix", false, "print recommended SQL remediation for each finding"),
		fs.BoolVar(&o.redact, "redact", false, "suppress sampled row values in output"),
		fs.BoolVar(&o.csvOut, "csv", false,
			"write findings as CSV, one row each, never carrying sampled data"),
		fs.BoolVar(&o.plain, "plain", false,
			"explain the result in plain language: who can reach what data"),
		fs.StringVar(&o.htmlOut, "html", "",
			"write a self-contained HTML report to this path, with the fix SQL in one button"),
		// -redact hides rows that were already fetched. -measure never fetches
		// them: the read probe asks for limit=0 with an exact count, so
		// PostgREST answers "465 rows are readable" in two bytes without one
		// of them leaving the database.
		//
		// For studying populations of projects nobody owns, that difference is
		// the whole argument. Retrieving strangers' personal data to prove
		// their RLS is broken is not defensible however true the finding is.
		// Measurement research is expected to be attributable: an operator who
		// sees the traffic should be able to find out who is scanning and why.
		// The default already names the tool and a URL, but that URL is only
		// as useful as what is published there.
		fs.StringVar(&o.userAgent, "user-agent", "",
			"override the User-Agent, e.g. to point at a page or mailbox you control"),
		fs.IntVar(&o.maxColProbe, "max-column-probes", probe.DefaultMaxColumnProbes,
			"maximum sensitive-column probes under -measure, across the whole scan"),
		fs.BoolVar(&o.measure, "measure", false,
			"establish exposure WITHOUT retrieving any data: counts only, no sampled rows "+
				"(severity cannot be refined by column name, and GraphQL is skipped)"),
		fs.BoolVarP(&o.jsonOut, "json", "j", false, "write findings as JSONL"),
		fs.BoolVar(&o.agentOut, "agent", false, "write compact versioned JSONL for agents "+
			"(fingerprints, coverage, classes and replay; no samples or remediation prose)"),
		fs.StringVarP(&o.output, "output", "o", "", "write findings to a file"),
		fs.StringVar(&o.mailbox, "mailbox", "",
			"receive the signup confirmation mail through this provider, so a project "+
				"that withholds the session until the address is verified can still be "+
				"measured (currently: agentmail; needs AGENTMAIL_API_KEY). Calls a third "+
				"party, so it is off unless asked for"),
		fs.BoolVar(&o.stats, "stats", false, "print scan statistics"),
	)

	// Optional, off by default, and separate from everything above it: this is
	// the only group that can put a statement in a report that was not proven.
	//
	// The rules are structural -- Luhn plus an issuer length, mod-97, a JWT
	// header that decodes -- and measure 2 false positives across 500 ordinary
	// columns. They are also blind to a street address or a diagnosis, which
	// carry nothing checkable: 14.9% recall across 22 data classes. A local
	// model closes most of that gap and brings its own error rate, so what it
	// produces lands in a separate field and only above the gate.
	fs.CreateGroup("classifier", "Data classification (optional)",
		fs.StringVar(&o.classifier, "classifier", "",
			"URL of a LOCAL model server, or \"auto\" to look for one on loopback, used to "+
				"classify columns the deterministic rules "+
				"cannot read, such as addresses and diagnoses. Off by default. The rules "+
				"always win: the model is asked only about columns they left unclassified, "+
				"and what it returns is reported separately as model-derived. Works with "+
				"llama.cpp (/completion), Ollama (/api/generate) and anything speaking "+
				"OpenAI /v1/completions -- the server must return logprobs"),
		fs.StringVar(&o.classifierModel, "classifier-model", "",
			"model name to request, for servers that host several (Ollama, vLLM)"),
		// goflags has no float, and an integer percent is the better interface
		// anyway: -classifier-threshold 80 reads as a threshold, 0.80 reads as
		// a magic number.
		fs.IntVar(&o.classifierThreshold, "classifier-threshold", 80,
			"minimum confidence percent before a model class is reported; below this the "+
				"column is left unclassified rather than guessed at"),
	)

	fs.CreateGroup("debug", "Debug",
		fs.BoolVar(&o.silent, "silent", false, "show only findings"),
		fs.BoolVarP(&o.noColor, "no-color", "nc", false, "disable colour"),
		fs.BoolVarP(&o.verbose, "verbose", "v", false, "verbose output"),
		fs.BoolVar(&o.showVersion, "version", false, "show version"),
	)
	return fs
}

func main() {
	o := &options{}
	fs := newFlagSet(o)

	// goflags builds its flag.FlagSet with flag.ExitOnError, so an unknown flag
	// exits 2 -- which is this program's code for "findings at high severity or
	// above". A typo therefore told CI a vulnerability had been found.
	//
	// Switching the flag set to ContinueOnError does not help: goflags
	// discards parse errors internally (see below), so the run continues with
	// an empty target and exits 3 instead, and -h stops working. So the
	// argument list is checked against the registered flags first, before
	// anything can exit on our behalf.
	if bad := unknownFlags(fs); len(bad) > 0 {
		gologger.Fatal().Msgf("unknown flag %s (see -h); this is a usage error, not a finding",
			strings.Join(bad, ", "))
	}

	if err := fs.Parse(); err != nil {
		// goflags discards flag-parsing errors internally; the only error it
		// returns is a failure to CREATE its default config file. That happens
		// whenever HOME is unset — minimal containers, cron, systemd units,
		// some CI runners — where the config path resolves relative to the
		// working directory and the write fails with "not a directory".
		//
		// The tool takes no required configuration, so refusing to start over
		// an unwritable config file is a scanner that cannot run in exactly
		// the environments it is meant to run in. Warn once and continue.
		gologger.Warning().Msgf("could not write the default config file (%s); continuing", err)
	}

	client.Version = version
	if o.showVersion {
		fmt.Printf("unruly %s\n", version)
		return
	}
	// No target at all is a usage error, not a scan. Left to run, the pipeline
	// probes the empty string, finds nothing it can assess, and exits 3 -- a
	// could-not-measure verdict about a target that was never given. Exit 1
	// says "you did not tell me what to scan", which is what happened.
	if o.target == "" && o.list == "" && o.projectRef == "" && o.baseURL == "" && o.site == "" {
		fmt.Fprint(os.Stderr, banner)
		fmt.Fprintf(os.Stderr, "nothing to scan. Give it a target:\n\n%s\nAll flags: %s -h\n",
			examples, os.Args[0])
		os.Exit(1)
	}
	// gologger orders levels Fatal, Silent, Error, Info, Warning, Debug,
	// Verbose -- Warning is MORE verbose than Info, not less. Its default
	// MaxLevel is Info, so every gologger.Warning() in this program was
	// silently dropped, including "write probing enabled: INSERT requests will
	// be issued". A safety notice nobody sees is not a safety notice.
	//
	// Verified in isolation: a three-line program logging Info, Warning and
	// Error against the stock logger prints the Info and the Error only.
	switch {
	case o.silent:
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	case o.verbose:
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	default:
		gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	}
	if !o.silent {
		fmt.Fprint(os.Stderr, banner)
		gologger.Info().Msgf("unruly %s", version)
	}

	if err := run(o); err != nil {
		gologger.Fatal().Msgf("%s", err)
	}
}

// targets resolves the list to scan from -target and -list.
//
// Targets are scanned SEQUENTIALLY, not concurrently. Each scan already runs at
// the measured PostgREST saturation point, so overlapping two would push both
// past the knee where throughput collapses, and would interleave their output.
// Sequential is slower in wall clock and kinder to every target involved.
func (o *options) targets() ([]string, error) {
	var out []string
	if o.target != "" {
		out = append(out, o.target)
	}
	if o.list != "" {
		b, err := os.ReadFile(o.list)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			out = append(out, line)
		}
	}
	// Deduplicate while preserving file order: a list is usually curated, and
	// reordering it would make output harder to compare between runs.
	seen := map[string]bool{}
	uniq := out[:0]
	for _, t := range out {
		if !seen[t] {
			seen[t] = true
			uniq = append(uniq, t)
		}
	}
	return uniq, nil
}

// validateFlags rejects flag combinations before anything is sent.
//
// Extracted from run() so the refusals are testable without performing a scan:
// a guard that is only reachable by scanning a real project is a guard nobody
// exercises.
func validateFlags(o *options) error {
	if o.agentOut && (o.jsonOut || o.csvOut || o.plain) {
		return fmt.Errorf("-agent is a complete output format and cannot be combined with " +
			"-json, -csv or -plain")
	}
	if o.invoke && !o.write {
		return fmt.Errorf("-invoke runs code on the target and requires -write as well")
	}
	if o.vocabOnly {
		// Naming a file is not enough. suppliedVocabulary swallows a read or
		// parse error and returns nil, so an unreadable handoff file would
		// leave -vocab-only probing NOTHING and reporting a clean project --
		// the exact false negative this tool exists to refuse. The test that
		// wrote a plain-text file instead of a handoff found this.
		if o.vocabFile == "" {
			return fmt.Errorf("-vocab-only restricts probing to the names in -vocab, " +
				"but no -vocab file was given: that would probe nothing and report silence as safety")
		}
		if len(suppliedVocabulary(o)) == 0 {
			return fmt.Errorf("-vocab-only was given %s, but no usable names could be read "+
				"from it: probing nothing would report the project clean without asking a question",
				o.vocabFile)
		}
	}
	if o.write && !o.confirmOwn {
		return fmt.Errorf("-write issues INSERT requests against the target; " +
			"pass -yes-i-own-this to confirm you are authorised")
	}
	return nil
}

func run(o *options) error {
	if o.anonKey == "" {
		// Ambient, not an instruction. A key exported for one project must not
		// decide how a different project is scanned, so where it came from is
		// remembered and discovery is allowed to overrule it.
		o.anonKey = os.Getenv("SUPABASE_ANON_KEY")
		o.keyFromEnv = o.anonKey != ""
	}
	// What the OPERATOR said, recorded before anything is inferred from it.
	o.apiLocated = o.baseURL != "" || (o.restPrefix != "" && o.restPrefix != defaultRestPrefix)
	if err := validateFlags(o); err != nil {
		return err
	}
	// The scan's SHAPE, checked while nothing has been sent.
	//
	// Not where it used to be. This ran just above the stage loop, after the
	// application had been harvested and the OpenAPI document fetched, while
	// its own comment claimed it ran before the first request. It did not, and
	// a check that runs once the target has served requests is an audit rather
	// than a precondition.
	planIsRunnable(o)
	// Refuse a privileged key. Every finding this tool produces is a statement
	// about what an ANONYMOUS caller can reach, and service_role bypasses
	// row-level security by design — so a scan with it reports correctly
	// protected relations as exposed. Measured on the reference target: 14
	// read-exposed relations claimed where the truth is 7, with the other
	// seven labelled "readable by the anonymous role" when they are not.
	//
	// That is worse than a missed finding. It sends an operator to fix seven
	// things that are not broken, and it discredits the findings that are
	// real. There is also no reason to put a service_role key on the wire and
	// into scan evidence when the anon key answers the question being asked.
	if role := escalate.JWTRole(o.anonKey); role == "service_role" {
		return fmt.Errorf("the supplied key is a service_role key, which bypasses row-level " +
			"security: every relation would read as exposed and the report would be wrong. " +
			"Use the project's anon (publishable) key — that is the credential an attacker " +
			"has, and the one these findings are about")
	}
	if strings.HasPrefix(o.anonKey, "sb_secret_") {
		return fmt.Errorf("the supplied key is a secret key, which bypasses row-level " +
			"security: every relation would read as exposed. Use the publishable key")
	}

	minSev, ok := finding.ParseSeverity(o.severity)
	if !ok {
		return fmt.Errorf("unknown severity %q", o.severity)
	}
	// -proven asks for what is actionable, and nothing below high is. Raising
	// rather than overriding: an operator who asked for -proven -sv critical
	// meant critical, and quietly widening that would be the filter deciding
	// what they wanted.
	if o.proven && minSev < finding.High {
		minSev = finding.High
	}

	// Reading an application is not a scan of anything, so -emit-vocab needs
	// no target, no credential and no permission to probe a backend: it
	// fetches the site the operator named, writes what the words in it
	// suggest, and stops. Whoever reads that file next -- a person, or a model
	// that knows the product this application sells -- hands it back through
	// -vocab, and every name in it is then measured the same deterministic way
	// as one of our own.
	if o.emitVocab != "" {
		if o.site == "" && o.target != "" {
			o.site = o.target
		}
		if o.site == "" {
			return fmt.Errorf("-emit-vocab harvests an application: name it with -site")
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		limiter := client.NewLimiter(o.rateLimit)
		v := enumerate.Harvest(ctx, enumerate.HarvestOptions{
			Web: client.NewApplication(client.AppOptions{
				Site: o.site, Timeout: time.Duration(o.timeout) * time.Second,
				Concurrency: o.concurrency, Retries: o.retries,
				RateLimit: o.rateLimit, Limiter: limiter, UserAgent: o.userAgent,
			}),
			Site: o.site, Timeout: time.Duration(o.timeout) * time.Second,
			Limiter: limiter, MaxSeeds: o.maxSeeds, MaxBundles: o.maxBundles,
			MaxPages: crawlBudget(o), UserAgent: o.userAgent,
		})
		if err := handoff.Write(o.emitVocab, handoff.NewVocabulary(
			"unruly "+version, o.site, v.Seeds, v.Sources)); err != nil {
			return err
		}
		gologger.Info().Msgf("%d seeds from %d source(s) written to %s; edit it and "+
			"pass it back with -vocab", len(v.Seeds), len(v.Sources), o.emitVocab)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; gologger.Warning().Msg("interrupted"); cancel() }()

	// A file destination ADDS a destination; it does not replace the terminal.
	// Replacing it meant a run that wrote a report showed the operator log
	// lines and no findings, and capturing both renderings of one scan was
	// impossible: two scans disagreed because a write probe adds a row between
	// them.
	var w finding.Writers
	if o.output != "" {
		f, err := os.Create(o.output)
		if err != nil {
			return err
		}
		defer f.Close()
		if o.csvOut {
			// Header once, before any row: the Writer is a value and renders
			// one finding at a time, so it has nowhere to keep "have I started
			// yet". Emitting it here also means an empty scan still produces a
			// readable file rather than zero bytes.
			if err := finding.CSVHeader(f); err != nil {
				return err
			}
		}
		w = append(w, finding.Writer{
			Out: f, NoColor: true, JSON: o.jsonOut && !o.csvOut, Agent: o.agentOut,
			CSV:     o.csvOut,
			ShowFix: o.fix, Redact: o.redact, MinSev: minSev, Proven: o.proven,
		})
	}
	// The terminal gets the human rendering unless it was told to be quiet, or
	// unless there is no file and the operator asked for JSON on stdout, which
	// is the pipeline case.
	if !o.silent || o.output == "" {
		w = append(w, finding.Writer{
			Out: os.Stdout, NoColor: o.noColor, JSON: o.jsonOut && o.output == "",
			Agent:   o.agentOut,
			ShowFix: o.fix, Redact: o.redact, MinSev: minSev, Proven: o.proven,
		})
	}

	list, err := o.targets()
	if err != nil {
		return err
	}
	if len(list) == 0 {
		// A bare -base-url/-key invocation has no "target" string but is still
		// a scan of one thing.
		list = []string{""}
	}

	// Captured before the per-target loop rewrites it.
	explicitSite := o.site != ""

	// One limiter for the scheme probes across every target in a list, created
	// here rather than per-target so `-l targets.txt -rl 5` is a promise about
	// this program's traffic and not about each entry's share of it.
	schemeLimiter := client.NewLimiter(o.rateLimit)

	overall := time.Now()
	worst := finding.Info
	totalFindings := 0
	var blindSurfaces []string

	for i, target := range list {
		// Each target gets its own copy: discovery writes back into projectRef,
		// anonKey and site, and leaking those between targets would scan the
		// second project with the first one's credentials.
		to := *o

		// A target written without a scheme is resolved BEFORE anything else
		// reads it, because everything downstream -- the site to harvest, the
		// host to enumerate, the origin in every finding -- is derived from
		// this string.
		//
		// Until this existed, `unruly -u example.com` reached the network zero
		// times and reported "no Supabase project reference found; supply
		// -project-ref or -base-url", then exited 3 with the host listed as
		// unreachable. Nothing had been requested, so "unreachable" described a
		// request that was never sent, and the operator was pointed at a missing
		// project reference when the problem was a missing "https://".
		//
		// A failure here is logged and the raw target is left exactly as it was,
		// so this can only ADD information: a scan that worked before still
		// takes the same path, and one that could not resolve now says which
		// two URLs it tried instead of naming a project reference.
		if target != "" {
			resolved, fellBack, err := resolveScheme(ctx, schemeProbeClient(time.Duration(o.timeout)*time.Second), schemeLimiter, target)
			switch {
			case err != nil:
				gologger.Warning().Msgf("%s: %s", target, err)
			case fellBack:
				// Said out loud rather than left to be inferred from a URL in
				// the report: from here on every request in this scan travels
				// in cleartext, including the ones carrying the anon key.
				gologger.Warning().Msgf("%s answers over HTTP but not HTTPS; scanning %s — this scan and its credentials travel in cleartext",
					target, resolved)
				target = resolved
			case resolved != target:
				gologger.Info().Msgf("no scheme given; scanning %s", resolved)
				target = resolved
			}
		}

		to.target = target
		if target != "" {
			// An explicit -site is an instruction about where the APPLICATION
			// lives, and it used to be discarded here: `-u <api> -s <app>` reset
			// site to "" and then set it from the target, so the app was never
			// harvested and never inspected for disclosure. Found by pointing a
			// scan at a page that ships a service_role key and getting silence.
			//
			// Only DERIVE the site from the target when the operator did not say
			// where it is. The reset itself is still needed for a target list,
			// where each entry must discover its own.
			if !explicitSite {
				to.site = ""
				if !strings.Contains(target, ".supabase.co") {
					to.site = target
				}
			}
			// A ref supplied on the command line applies to a single target
			// only; with a list, each entry must discover its own.
			//
			// The key is different. A managed Supabase anon key is a JWT
			// naming the project it belongs to, so reusing one across a list
			// sends project A's credential to project B's server and then
			// reports on the 401s it gets back. Where the claim says the key
			// belongs elsewhere, it is dropped and the target discovers its
			// own. A key with no ref claim -- self-hosted, or minted for a
			// fixture -- is kept, because "cannot tell" is not "wrong".
			if len(list) > 1 {
				to.projectRef, to.anonKey, to.baseURL = "", o.anonKey, ""
				to.inList = true
				// A managed project's reference IS its hostname, so a
				// mismatched key can be caught before a single request. That
				// matters most when the host is unreachable: discovery then
				// finds no ref, the post-discovery guard has nothing to
				// compare, and the credential would go to a host nothing is
				// known about. Silent for any other URL shape, because a ref
				// cannot be derived from one.
				if ref := refFromHost(target); ref != "" {
					if keyRef := escalate.JWTProjectRef(o.anonKey); keyRef != "" && keyRef != ref {
						to.anonKey = ""
						to.keyWithheldRef = keyRef
						gologger.Warning().Msgf("the supplied key belongs to project %q; "+
							"not sending it to %q, which will discover its own", keyRef, ref)
					}
				}
			}
		}
		if len(list) > 1 {
			gologger.Info().Msgf("[%d/%d] %s", i+1, len(list), target)
		}

		found, sev, blind, err := scanTarget(ctx, &to, w)
		if err != nil {
			// One unreachable target must not abandon the rest of the list.
			// It is still a surface that could not be assessed, so it has to
			// reach the exit code: otherwise a list of unreachable targets
			// exits 0 and reads as a clean sweep.
			gologger.Error().Msgf("%s: %s", target, err)
			blindSurfaces = append(blindSurfaces, target+" (unreachable)")
			// And it has to reach the REPORT. This stopped at the exit code:
			// a target that failed produced no finding at all, so a list of
			// fifty projects where ten errored wrote a report covering forty
			// with nothing saying which ten were missing. Diffing two runs
			// showed targets appearing and disappearing for no stated reason,
			// and a per-target report was simply absent rather than negative.
			// Through emitAll like every other report write, so the rule has
			// no exceptions to remember. Canonicalising one finding is a
			// no-op; having a second way to write the report is not.
			if _, _, _, werr := emitAll(w, []finding.Finding{
				finding.TargetFailed(target, err, to.keyWithheldRef)}); werr != nil {
				return werr
			}
			totalFindings++
			continue
		}
		blindSurfaces = append(blindSurfaces, blind...)
		totalFindings += found
		if sev > worst {
			worst = sev
		}
		if ctx.Err() != nil {
			break
		}
	}

	if len(list) > 1 {
		gologger.Info().Msgf("%d targets, %d findings, %s",
			len(list), totalFindings, time.Since(overall).Round(time.Millisecond))
	}
	// Exit codes are a contract with CI, and CI cannot read prose. Before
	// this, a hardened project, a host that is not Supabase, a 500 origin and
	// an unreachable address all exited 0 -- the same as a clean scan -- so
	// `unruly ... && echo secure` printed secure for a typo in the URL.
	//
	//   2  findings at High or above
	//   3  scan completed but some surface could not be assessed
	//   0  scanned, nothing at or above High, coverage complete
	//
	// 2 outranks 3: a confirmed exposure is more actionable than an unmeasured
	// surface, and the log still names what was not assessed.
	sort.Strings(blindSurfaces)
	switch {
	case worst >= finding.High:
		os.Exit(2)
	case len(blindSurfaces) > 0:
		gologger.Warning().Msgf("exit 3: nothing at or above high severity, but these "+
			"surfaces could not be assessed: %s — this is not a clean result",
			strings.Join(dedupStrings(blindSurfaces), ", "))
		os.Exit(3)
	}
	return nil
}

func writeHTMLReport(o *options, where string, start time.Time, all []finding.Finding) error {
	f, err := os.Create(o.htmlOut)
	if err != nil {
		return err
	}
	err = finding.WriteHTML(f, where, start.UTC().Format(time.RFC3339), all)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// harvestFor reads the application's own pages and bundles for candidate
// names.
//
// Harvesting is a property of the SITE, not of Supabase, but the existing call
// sits inside the Supabase pipeline behind its credential gate -- which a
// Firebase application never passes. Rather than move that call and disturb a
// path the whole audit covers, this one runs for the providers that need it.
//
// A site serving BOTH backends therefore harvests twice. That is a real cost
// and a rare shape; sharing one harvest across both paths is the tidier fix and
// is worth doing when the Supabase side moves behind the same interface.
func harvestFor(ctx context.Context, o *options, limiter *client.Limiter) []string {
	supplied := suppliedVocabulary(o)
	if o.site == "" {
		return supplied
	}
	v := enumerate.Harvest(ctx, enumerate.HarvestOptions{
		Site: o.site, Timeout: time.Duration(o.timeout) * time.Second,
		Limiter: limiter, MaxSeeds: o.maxSeeds, MaxBundles: o.maxBundles,
		MaxPages: crawlBudget(o),
	})
	// Case is preserved here, and the one consumer is why.
	//
	// This list becomes ScanOptions.Harvested, which nothing reads except the
	// Cloud Functions check -- and a function name is a path segment the server
	// compares byte for byte. Everything else that wants these names folds them
	// downstream anyway: firebaseCandidates merges this result through
	// wordlist.Merge, so relation and collection probing is unchanged.
	return wordlist.MergeKeepingCase(v.Seeds, supplied)
}

// suppliedVocabulary is the names an operator or an agent handed over.
//
// Read here as well as in the Supabase pipeline, because -vocab reached the
// PostgREST enumerator and nothing else: the feature claimed to widen
// enumeration and widened half the tool. On PostgREST a supplied name is a
// convenience -- the hint oracle recovers names on its own. On Firestore it is
// the only route there is, because listCollectionIds is administrator-only and
// a protected collection answers 403 identically to one that never existed. A
// scan of the Firebase lab tried every pinned name, found none of them,
// and correctly reported that it could not see -- which is honest and still a
// scan saying nothing about two publicly readable collections.
//
// Errors are silent HERE and reported where the file is loaded for the
// Supabase pass, so a bad path is named once rather than twice.
func suppliedVocabulary(o *options) []string {
	if o.vocabFile == "" {
		return nil
	}
	v, _, err := handoff.ReadVocabulary(o.vocabFile)
	if err != nil {
		return nil
	}
	return v.Seeds
}

func boundedCount(total, limit int) int {
	if limit > 0 && total > limit {
		return limit
	}
	return total
}

// keyOrigin says where the scanning credential came from, for the one finding
// where that is the whole point.
func keyOrigin(o *options) string {
	switch {
	case o.keyDiscovered:
		return "harvested from the target's own client-side content"
	case o.keyFromEnv:
		return "the SUPABASE_ANON_KEY environment variable"
	default:
		return "supplied with -key"
	}
}

// escalationProject keys the stored identity. The project reference where
// there is one, the origin otherwise -- a self-hosted deployment has no
// reference, and keying every one of them under "" would hand one deployment's
// account to the next.
func escalationProject(o *options) string {
	if o.projectRef != "" {
		return o.projectRef
	}
	return o.baseURL
}

// finishReport emits everything the operator ASKED for, on every path that ends
// a scan.
//
// The outputs were wired in one at a time at the end of the Supabase pipeline,
// so each new terminating path silently lost them: -plain printed nothing for a
// Firebase project, and -html wrote no file at all -- a shareable report
// requested and simply absent, with no error. One tail, so a third output
// cannot diverge from the first two.
//
// CSV and JSONL are not here on purpose: those go through finding.Writer, which
// every path already uses, and that is why they were the two that worked.
type reportStats struct {
	Relations          int
	ApplicationRoutes  int
	ApplicationOrigins int
	ProviderNames      int
	Requests           int
	Relational         bool
	Abandoned          bool
	Spend              *ledger
}

func finishReport(o *options, all []finding.Finding, start time.Time, stats reportStats) {
	printReportStats(o, all, start, stats)
	printPlain(o, all)
	if o.htmlOut == "" {
		return
	}
	// A failure here is reported and does not abort: the scan already
	// succeeded, and losing its result because a file could not be written
	// would be the tool discarding work the target already paid for.
	//
	// The timestamp is passed in rather than read inside the renderer, so the
	// rendering stays a pure function of its inputs and two runs of an
	// unchanged project differ only where the project did.
	if err := writeHTMLReport(o, target(o), start, all); err != nil {
		gologger.Error().Msgf("html report: %s", err)
		return
	}
	gologger.Info().Msgf("html report written to %s", o.htmlOut)
}

func printReportStats(o *options, all []finding.Finding, start time.Time, stats reportStats) {
	if !o.stats && o.silent {
		return
	}
	statf := func(format string, a ...any) {
		if o.silent {
			fmt.Fprintf(os.Stderr, format+"\n", a...)
			return
		}
		gologger.Info().Msgf(format, a...)
	}

	counts := map[finding.Severity]int{}
	for _, f := range all {
		counts[f.Severity]++
	}
	statf("%d findings (critical:%d high:%d medium:%d low:%d info:%d)",
		len(all), counts[finding.Critical], counts[finding.High],
		counts[finding.Medium], counts[finding.Low], counts[finding.Info])
	if stats.Relational {
		statf("%d relations, %d requests, %s", stats.Relations, stats.Requests,
			time.Since(start).Round(time.Millisecond))
	} else {
		statf("%d application routes across %d origins, %d provider candidate names, %d requests, %s",
			stats.ApplicationRoutes, stats.ApplicationOrigins, stats.ProviderNames,
			stats.Requests, time.Since(start).Round(time.Millisecond))
	}
	if stats.Spend != nil {
		if by := stats.Spend.summary(4); by != "" {
			if stats.Abandoned {
				statf("abandoned plan (not sent): %s", by)
			} else {
				statf("spent on: %s", by)
			}
		}
	}
	if stats.Relational {
		if !o.write {
			statf("%s", "reads only: whether an anonymous caller can INSERT was "+
				"NOT tested. On a project you own, add -write -yes-i-own-this")
		} else {
			statf("%s", finding.WriteCoverage(all))
		}
	}
}

// printPlain renders the plain-language answer, on EVERY path that ends a scan.
//
// It used to sit only at the end of the Supabase pipeline, so a scan that
// returned earlier printed nothing: a Firebase-only application takes the
// no-Supabase-credential return, and a target whose REST mount path could not
// be resolved takes another. Measured on the Firebase lab, where a critical
// finding was present -- a Stripe-shaped key served to every client -- and
// -plain produced no output at all. The reader who was given this mode
// precisely because they cannot read the technical one saw silence, which is
// indistinguishable from a clean project.
func printPlain(o *options, all []finding.Finding) {
	if !o.plain {
		return
	}
	if p := finding.Plain(all); p != "" {
		fmt.Fprint(os.Stderr, "\n"+p)
		return
	}
	fmt.Fprintln(os.Stderr,
		"\nNothing in this project could be reached without an account.")
}

// defaultConcurrency is the flag's default, overridable by UNRULY_CONCURRENCY.
//
// An env default rather than a flag on every invocation, because the caller
// that needs it most cannot pass flags: the eval suite execs this binary from
// twenty-eight places, and each process closes its whole connection pool on
// exit. Measured on one audit check: a peak of 8,080 sockets in TIME_WAIT,
// half this host's ephemeral range, which is why the gate passed from a clean
// start and failed whenever anything had run before it.
//
// Concurrency changes how fast a scan asks, never what it finds, so capping it
// for the fixtures costs the evals nothing they measure.
func defaultConcurrency() int {
	if v := os.Getenv("UNRULY_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return client.DefaultConcurrency
}

// hostOf extracts the host from a target URL, for domain enumeration.
func hostOf(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return target
}

// target names what was scanned, for findings that describe the scan itself.
func target(o *options) string {
	switch {
	case o.site != "":
		return o.site
	case o.projectRef != "":
		return "https://" + o.projectRef + ".supabase.co"
	default:
		return o.baseURL
	}
}

// scanTarget runs the full scan against one target and writes its findings.
// It returns how many were emitted and the highest severity seen.
func scanTarget(ctx context.Context, o *options, w finding.Writers) (int, finding.Severity, []string, error) {
	if o.site == "" && o.target != "" && !strings.Contains(o.target, ".supabase.co") {
		o.site = o.target
	}
	var policy *intent.Manifest
	haveIntent := o.intentFile != ""
	if haveIntent {
		b, err := os.ReadFile(o.intentFile)
		if err != nil {
			return 0, finding.Info, nil, fmt.Errorf("read intent manifest: %w", err)
		}
		parsed, err := intent.Parse(b)
		if err != nil {
			return 0, finding.Info, nil, err
		}
		policy = &parsed
	}

	// One budget for the whole scan. Created here so discovery, vocabulary
	// harvesting, relation probing, routes and archive fetching all draw from
	// it: -rl is a promise to the target, not to one package.
	limiter := client.NewLimiter(o.rateLimit)
	// -timeout used to bind only the PostgREST client while every other stage
	// hardcoded its own (15s, 20s, 60s). An operator shortening it to keep a
	// scan bounded still waited a minute per archive fetch. Same shape as the
	// rate limit: a flag that held in the place its author was looking.
	timeout := time.Duration(o.timeout) * time.Second
	// One client for everything aimed at the APPLICATION, as distinct from the
	// backend: the site's HTML, its JS bundles, and its own routes.
	//
	// Three stages each built their own bare http.Client, which meant three
	// connection pools to one host, no retry policy, no circuit breaker, and
	// -- in routes.probe -- no rate limiting either. Measured: a site
	// answering 429 to every request was asked 131 times with no backoff,
	// while the database at the other end of the same scan was handled
	// correctly. The site and the database belong to the same person.
	//
	// Two deliberate differences from the backend client. It carries NO
	// credential: the anon key names a Supabase project and has no business
	// being sent to a web server, which may not even be the same party. And
	// its body cap is 8MB rather than 1MB, because a single JS bundle
	// routinely exceeds a megabyte and a bundle cut short loses whatever
	// vocabulary, project ref or credential sat past the cut.
	//
	// Its breaker is its own, so a site that refuses everything stops the site
	// fetching without stopping the database scan, and the reverse.
	// Through the constructor, not by hand. The fields that make this client
	// safe -- no Supabase credential, and a body cap large enough for a real JS
	// bundle -- are decided inside it, so a caller cannot get them wrong by
	// omission. Writing the same literal here as well meant one policy in two
	// places, identical on the day it was written and free to drift on any day
	// after, with the divergence sitting exactly between what the binary does
	// and what the packages' own tests exercise.
	webClient := client.NewApplication(client.AppOptions{
		Site: o.site, Timeout: timeout, Concurrency: o.concurrency,
		Retries: o.retries, RateLimit: o.rateLimit, Limiter: limiter,
		UserAgent: o.userAgent,
	})

	start := time.Now()
	var all []finding.Finding
	requests := 0
	spend := newLedger()
	// -max-rpc-probes is a budget for the SCAN, not for each schema.
	//
	// It was passed unchanged to every surface.Routines call, so a project
	// exposing five schemas spent five times the stated maximum while the flag
	// help said "maximum RPC name probes". A bound that multiplies with the
	// target's shape is not a bound, and this project's rule is that every
	// budget is bounded and says so when it binds.
	rpcLeft := o.maxRPC
	// Secondary schemas run BEFORE the default one, so a plain shared budget
	// would let them starve public -- the surface that matters most and the one
	// an operator assumes was searched hardest. They may spend at most half
	// between them; whatever they leave goes to public, which is therefore
	// guaranteed at least half.
	extraLeft := o.maxRPC / 2

	// ---- discovery --------------------------------------------------------
	// Discovery serves two purposes and they were conflated: recovering
	// credentials, and reporting what the application leaks about itself.
	//
	// It used to run only when a credential or origin was missing, so a user
	// who supplied -p and -k lost the project-ref disclosure finding — a
	// quieter report for being more specific, with nothing saying a check had
	// been skipped. Whenever a site is known it is now inspected for findings;
	// what it recovers is only ADOPTED as credentials when they are absent.
	// A target that is itself a Supabase URL IS an origin.
	//
	// Without this, the most natural first invocation there is --
	//
	//	unruly -u https://<ref>.supabase.co -k <anon key>
	//
	// -- was refused, with a message telling the operator to supply -site "(or
	// -target)" when -u IS -target and they had just supplied it. The scan
	// produced an empty report and exit 3 against a project with seven
	// anonymously readable tables, one of them holding session tokens. Exit 3
	// meant it did not claim the project was clean, which is the safety net
	// doing its job, but the scan never ran.
	//
	// The code to handle it was already there and thirty lines too late:
	// "treat the target itself as the API origin" runs after this guard, and
	// this guard returned first. A .supabase.co target deliberately does not
	// become the -site, because it is an API rather than an application, and
	// that left it counting as neither.
	loginWall := false
	// An API origin the application declared for itself, hoisted out of the
	// discovery block because it is only consulted once the project-reference
	// route has come up empty -- which is every self-hosted deployment.
	declared, declaredFrom := "", ""
	// Carried out of the discovery block for the same reason: the scan summary
	// is emitted later, on a path that has no relations to count.
	providerNames := 0
	applicationRoutes, applicationOrigins := 0, 0
	// Requests sent by provider-owned clients. The application and Supabase
	// clients have authoritative counters read at finalisation; these clients
	// are created inside the provider seam and return their sent counts here.
	externalProviderRequests := 0
	// Computed once, before discovery mutates o: the log line below asks what
	// was true on the way IN.
	origin := haveOrigin(o)
	// Carried out of the discovery block so the withholding decision below can
	// see it. That decision is 74 lines further down and outside this block, so
	// the credential discovered HERE was invisible there -- which is how a scan
	// came to throw away a working key and report that it could not look.
	var discoveredKey string
	detections := dedupeDetections(detectionsFromTarget(o))
	if shouldDiscover(o) {
		d, err := discovery(ctx, o, webClient, limiter, timeout, origin)
		if err != nil {
			return 0, finding.Info, nil, err
		}
		requests += d.Requests
		spend.add("discovery", d.Requests)
		loginWall = d.LoginWall
		declared, declaredFrom = d.Declared, d.DeclaredFrom
		detections = dedupeDetections(append(detections, d.Detections...))
		discoveredKey = d.DiscoveredKey
		all = append(all, d.Findings...)
	}
	for _, d := range detections {
		gologger.Info().Msgf("%s backend detected: %s (%s)", d.Provider, d.Project, d.Reason)
	}

	// Every backend-independent and non-Supabase assessment now enters through
	// one engine. Discovery above returns facts only; finding a backend in a
	// bundle and naming it directly therefore produce the same validation,
	// consent, accounting and result merge path.
	var otherDetections []provider.Detection
	for _, d := range detections {
		if d.Provider != "supabase" {
			otherDetections = append(otherDetections, d)
		}
	}
	var providerHarvested, providerSupplied, providerSeeds []string
	if len(otherDetections) > 0 {
		providerHarvested = harvestFor(ctx, o, limiter)
		providerSupplied = suppliedVocabulary(o)
		providerSeeds = firebaseCandidatesFrom(o, providerHarvested)
		providerNames = boundedCount(len(providerSeeds), o.maxCollections)
	}
	var providerTargets []engine.ProviderTarget
	var providerClients []*client.Client
	for _, d := range otherDetections {
		pc := client.New(client.Options{
			BaseURL: provider.APIBase(d), RestPrefix: "/",
			ProjectRef: "", AnonKey: "", Bearer: "", MaxBody: 0,
			RateLimit: o.rateLimit, Concurrency: o.concurrency, Timeout: timeout,
			Retries: o.retries, UserAgent: o.userAgent, Limiter: limiter,
		})
		providerClients = append(providerClients, pc)
		providerTargets = append(providerTargets, engine.ProviderTarget{
			Detection: d, Inputs: seamInputsFrom(o, providerSeeds,
				providerHarvested, providerSupplied, pc),
			Consent: scan.Consent{Write: o.write && o.confirmOwn},
		})
	}
	engineRequest := engine.Request{
		Target: target(o), Intent: policy,
		Application: &engine.ApplicationTarget{
			Site: o.site, AllowedOrigins: append([]string(nil), o.allowedOrigins...),
			HARFiles: append([]string(nil), o.harFiles...),
			Web:      webClient, Limiter: limiter, Timeout: timeout,
			Concurrency: o.concurrency, MaxBundles: o.maxBundles,
			MaxRoutes: o.maxRoutes, MaxBypassRoutes: o.maxBypassRoutes,
			UserAgent: o.userAgent, Redact: o.redact,
			AllowPOST: o.write && o.confirmOwn, WriteConsent: o.write && o.confirmOwn,
			NoResidue:  o.noResidue,
			SkipRoutes: o.skipRoutes, RouteParams: append([]string(nil), o.routeParams...),
			Principals: append([]string(nil), o.principals...),
		},
		Providers: providerTargets, OnNote: renderNotes,
	}
	// Exactly one invocation per target. Providers may be added below after
	// target resolution, but application routes and every backend enter this
	// same request and therefore share consent, validation and accounting.
	runUnified := func() engine.Report {
		engineRequest.Findings = append(engineRequest.Findings, all...)
		all = nil
		r := engine.Run(ctx, engineRequest)
		all = append(all, r.Findings...)
		applicationRoutes = r.Application.Routes
		applicationOrigins = r.Application.Origins
		addProviderSpend(spend, r.Requests, r.Spending)
		externalProviderRequests = 0
		for _, pc := range providerClients {
			n, _ := pc.Stats()
			externalProviderRequests += int(n)
		}
		return r
	}
	// The key names the project it was issued for. Checking it here costs
	// nothing and stops a typo from firing thousands of requests at a project
	// its owner never asked to have scanned.
	//
	// The comparison has to happen HERE, after discovery, not against the target
	// string. A project's ref does not appear in its own site URL: the reference
	// target is example-app.test and its key says examplerefexampleref, so a
	// URL-substring check drops the correct key.
	if cr := credentialFor(o.anonKey, escalate.JWTProjectRef(o.anonKey), o.projectRef,
		discoveredKey, o.inList); cr.Err != nil {
		return 0, finding.Info, nil, cr.Err
	} else if cr.WithheldRef != "" {
		gologger.Warning().Msg(cr.Warn)
		o.anonKey, o.keyWithheldRef = cr.Key, cr.WithheldRef
	}
	// A role other than anon answers a different question. It is allowed —
	// -user-jwt exists precisely to measure the difference — but findings
	// would describe that role while saying "anonymous", so say so once.
	// Only a JWT has a role claim to disagree with. Supabase's current
	// publishable format is an opaque sb_publishable_ string, and JWTRole
	// reports "unknown" for anything it cannot parse -- so a correct,
	// current-format key was drawing the warning meant for a privileged one:
	//
	//   the supplied key claims role "unknown", not anon
	//
	// Crying wolf over the right credential is worse than saying nothing,
	// because the warning that matters -- a real service_role JWT -- looks
	// identical to the one the user has already learned to ignore.
	if role := escalate.JWTRole(o.anonKey); role != "" && role != "anon" && role != "unknown" {
		gologger.Warning().Msgf("the supplied key claims role %q, not anon: findings will "+
			"describe what %s can reach, which is not what an anonymous attacker sees",
			role, role)
	}

	// A target that is not a managed Supabase project still has an origin: if
	// discovery found no project ref and the target is a URL, treat the target
	// itself as the API origin. This is what makes a list of self-hosted
	// deployments work without a per-entry -base-url.
	if oc := resolveOrigin(o.projectRef, o.baseURL, o.target, declared, declaredFrom); oc.BaseURL != "" {
		o.baseURL = oc.BaseURL
		gologger.Info().Msg(oc.Msg)
	}

	// Decide which provider pipeline applies BEFORE constructing its client or
	// sending one of its probes. An ambient or explicitly supplied credential
	// is not evidence that a plain application speaks PostgREST. Discovery's
	// corroborated SUPABASE_URL is evidence even on a self-hosted custom domain,
	// so preserve that ordinary path explicitly.
	supabaseOK, whyNot := supabaseSelected(o)
	if !supabaseOK && declared != "" {
		supabaseOK, whyNot = true, ""
	}
	if !supabaseOK {
		gologger.Info().Msgf("no Supabase pipeline: %s", whyNot)
		all = append(all, finding.SkippedStage(target(o), "supabase", whyNot))
		runUnified()
		sentApplication, _ := webClient.Stats()
		requests = int(sentApplication) + externalProviderRequests
		all = append(all, finding.ScanSummarySurfaces(target(o), applicationRoutes,
			applicationOrigins, providerNames, requests))
		all, worst, blind, err := emitAll(w, all)
		if err != nil {
			return 0, finding.Info, nil, err
		}
		finishReport(o, all, start, reportStats{
			ApplicationRoutes: applicationRoutes, ApplicationOrigins: applicationOrigins,
			ProviderNames: providerNames, Requests: requests, Spend: spend,
		})
		return len(all), worst, blind, nil
	}
	if o.projectRef == "" && o.baseURL == "" {
		return 0, finding.Info, nil, fmt.Errorf("no Supabase project reference found; " +
			"supply -project-ref or -base-url")
	}
	if o.anonKey == "" {
		// Keep application and secondary-provider results even though the
		// selected Supabase surface could not start. One backend's missing
		// credential is a coverage gap, not a reason to discard measurements
		// another stage already made.
		runUnified()
		if len(all) > 0 {
			sentApplication, _ := webClient.Stats()
			requests = int(sentApplication) + externalProviderRequests
			all = append(all,
				finding.ScanSummarySurfaces(target(o), applicationRoutes,
					applicationOrigins, providerNames, requests),
				finding.NotAssessedBackend(target(o), requests),
			)
			all, worst, blind, err := emitAll(w, all)
			if err != nil {
				return 0, finding.Info, nil, err
			}
			gologger.Info().Msg("no Supabase credential, so that surface was not examined; " +
				"the findings above come from the other backends detected here")
			finishReport(o, all, start, reportStats{
				ApplicationRoutes: applicationRoutes, ApplicationOrigins: applicationOrigins,
				ProviderNames: providerNames, Requests: requests, Spend: spend,
			})
			return len(all), worst, blind, nil
		}
		// Say which of the two situations this is. Measured over a list of
		// real sites, a large share of "no anon key found" verdicts were
		// applications behind a sign-in screen -- their key ships in the
		// bundle loaded after authenticating -- and reading that as "not a
		// Supabase application" is wrong in a way the operator cannot see.
		return 0, finding.Info, nil, noKey(o.site, loginWall)
	}

	c := client.New(client.Options{
		ProjectRef:  o.projectRef,
		BaseURL:     o.baseURL,
		RestPrefix:  o.restPrefix,
		AnonKey:     o.anonKey,
		Concurrency: o.concurrency,
		Timeout:     timeout,
		Retries:     o.retries,
		RateLimit:   o.rateLimit,
		Limiter:     limiter,
		UserAgent:   o.userAgent,
		// The anonymous scan's own credential is the bearer, and API responses
		// take the default body cap. Both stated rather than omitted, so the
		// three clients this program builds can be read side by side and
		// compared field for field.
		Bearer:  "",
		MaxBody: 0,
	})

	// ---- vocabulary + enumeration ----------------------------------------
	// With no application to harvest, the pinned lists carry the scan alone.
	var harvested []string
	// Kept beyond the block below so the fallback can tell "nothing answered"
	// from "answered, but had nothing in it".
	vocabSources := 0
	if o.site != "" {
		gologger.Info().Msgf("harvesting vocabulary from %s", o.site)
		v := enumerate.Harvest(ctx, enumerate.HarvestOptions{
			Web:  webClient,
			Site: o.site, Timeout: timeout, Limiter: limiter, MaxSeeds: o.maxSeeds,
			MaxBundles: o.maxBundles, MaxPages: crawlBudget(o), UserAgent: o.userAgent})
		harvested = v.Seeds
		vocabSources = len(v.Sources)
		gologger.Info().Msgf("%d seeds harvested from %d sources", len(v.Seeds), len(v.Sources))
		// The most upstream bound in the scan, and it was silent. Seeds feed
		// relation AND routine discovery, so truncating here lowers both, and
		// neither can tell that it happened.
		// Pages count too. A crawl that stopped at its budget is vocabulary
		// that was never collected, and silent truncation is the failure this
		// finding exists to prevent -- adding a bound without adding it here
		// would have introduced one.
		if v.Harvested > len(v.Seeds) || v.BundlesFound > v.BundlesRead ||
			v.PagesFound > v.PagesRead {
			gologger.Info().Msgf("vocabulary truncated: %d of %d harvested tokens kept, "+
				"%d of %d bundles read, %d of %d linked pages read",
				len(v.Seeds), v.Harvested, v.BundlesRead, v.BundlesFound,
				v.PagesRead, v.PagesFound)
			all = append(all, enumerate.VocabularyBudgetFinding(o.site, len(v.Seeds),
				v.Harvested, v.BundlesRead, v.BundlesFound, v.PagesRead, v.PagesFound))
		}
	}
	// Names from outside this process. They are candidates exactly like the
	// harvested and pinned ones -- nothing here is a finding, and a name is a
	// guess until PostgREST answers for it -- so they join the same list and
	// take the same measurement.
	//
	// Counted, because recall is a number this report makes claims about. A
	// scan that recovered 30 relations because somebody handed it 30 names is
	// not the same result as one that found them, and the summary has to be
	// able to tell an operator which it was.
	supplied := 0
	var suppliedNames []string
	if o.vocabFile != "" {
		v, dropped, err := handoff.ReadVocabulary(o.vocabFile)
		if err != nil {
			return 0, finding.Info, nil, err
		}
		supplied = len(v.Seeds)
		// Kept SEPARATE from harvested now, rather than appended into it.
		// Both describe this target and both are merged, but the scan summary
		// reports what each source contributed, and a count cannot be
		// recovered once the slices are joined.
		suppliedNames = v.Seeds
		gologger.Info().Msgf("%d seeds supplied by %s", supplied, o.vocabFile)
		// A seed becomes a URL path. Anything that is not an identifier is
		// refused rather than sent, and saying so is the difference between a
		// shorter enumeration and a shorter enumeration nobody noticed.
		if len(dropped) > 0 {
			gologger.Warning().Msgf("%d supplied seed(s) are not identifiers and were "+
				"not probed: %s", len(dropped), strings.Join(dropped, ", "))
		}
	}
	// With no site to harvest, the pinned list has to reach the schema alone,
	// and measured against a second project it reached 2 of 7 relations while
	// the hint oracle would have answered for all 7 — the seeds were the
	// limit, not the oracle. Expanding them into near-misses recovers 5 of the
	// 7, at the cost of roughly 13k extra probes.
	//
	// Only when there is nothing harvested. An application's own vocabulary is
	// far better than any expansion of a generic list, so paying this on every
	// scan would slow the good path to improve the one that is already the
	// fallback.

	// The shared routine allowances. Created here rather than at the schemas
	// pass because the stage list needs them, and nothing reads extraLeft or
	// rpcLeft between the flag parse and that pass, so the values are the same.
	extraRoutines := scan.NewBudget(extraLeft)
	rpcRoutines := scan.NewBudget(rpcLeft)
	// Provider preparation acquires advertised names after resolving the
	// provider's protocol mount. Command orchestration supplies only sources it
	// actually owns: application harvest and explicit vocabulary handoff.
	seedSet := vocabularySources(o, harvested, nil, suppliedNames)
	seedSet.SourcesRead = vocabSources

	// POSITIVE EVIDENCE, or this pipeline does not run.
	//
	// Measured: with SUPABASE_ANON_KEY exported and the target a plain
	// website, this ran 1,200 relation probes and a routine sweep against a
	// host with no database behind it, then reported degraded capabilities
	// because enumeration "cannot be distinguished from a target with nothing
	// to find". The traffic was real and the conclusion was noise.
	//
	// Placed after discovery so a project reference recovered from the
	// application's own bundles counts -- that is the common case for a
	// managed project behind a custom domain, and gating before discovery
	// would refuse it.
	// Pinned lists cover conventional names; harvested vocabulary covers the
	// domain-specific ones a list can never guess. Neither alone is enough.
	// Ported to backend/supabase.VocabularyStage: the Enumerate phase of the
	// provider contract, which decides what will be asked about rather than
	// assessing anything. Its output is exactly what scan.Inputs.Seeds carries
	// to every other backend.
	if o.write {
		gologger.Warning().Msg("write probing enabled: INSERT requests will be issued")
		if !o.noResidue {
			gologger.Warning().Msg("a relation that accepts anonymous INSERT, refuses " +
				"anonymous SELECT and has no NOT NULL column will receive a probe row that " +
				"cannot be deleted with an anon key; pass -no-residue to skip that probe")
		}
	}

	// ---- privilege escalation -------------------------------------------
	//
	// Mint a token when the operator has authorised mutations and has not
	// supplied one. Without this the middle tier of the threat model -- what
	// anybody who registers can reach -- was measured only when somebody had
	// gone and made an account by hand first, which on a real engagement is
	// almost never.
	if o.userJWT == "" && o.write && o.confirmOwn {
		acct, err := escalate.Acquire(ctx, c, escalationProject(o),
			escalate.AcquireOptions{NoResidue: o.noResidue, Mailbox: mailboxFor(o, limiter, timeout)})
		n := accountNote(c.RestBase(), c.BaseURL(), acct, err)
		o.userJWT = n.Token
		if n.Warn {
			gologger.Warning().Msg(n.Msg)
		} else {
			gologger.Info().Msg(n.Msg)
		}
		all = append(all, n.Findings...)
	}

	// Supabase enters the same engine as every other provider. The lifecycle
	// above resolved its origin, public credential and optional signed-in
	// identity; the registry now owns the plan and the engine owns execution.
	supProject := o.projectRef
	if supProject == "" {
		supProject = o.baseURL
	}
	supDetection := provider.Detection{Provider: "supabase", Project: supProject,
		Credential: o.anonKey, Source: "resolved target",
		Reason: "the target was positively identified as Supabase"}
	supInputs := seamInputsFrom(o, nil, seedSet.Harvested, seedSet.Supplied, c)
	supInputs.SeedSet = seedSet
	supInputs.Client, supInputs.Limiter, supInputs.Timeout = c, limiter, timeout
	supInputs.Credential, supInputs.Bearer = o.anonKey, o.userJWT
	supInputs.ExtraRoutines, supInputs.RPCRoutines = extraRoutines, rpcRoutines
	engineRequest.Providers = append(engineRequest.Providers, engine.ProviderTarget{
		Detection: supDetection, Inputs: supInputs,
		Consent: scan.Consent{Write: o.write && o.confirmOwn,
			ThirdParty: o.checkHistory},
	})
	supReport := runUnified()
	cov := supReport.Coverage["supabase/"+supProject]
	skipped := skippedChecks(o, cov.OpenSignup)
	if f, ok := finding.Coverage(target(o), skipped); ok {
		all = append(all, f)
	}
	// How much was actually examined, in the artifact that gets STORED.
	//
	// "21 relations, 12780 requests" was printed to the terminal and appeared
	// nowhere in the JSON report. So a stored report with no exposures could
	// not be told apart from a scan that discovered nothing and reported the
	// silence -- the exact confusion this scanner refuses everywhere else,
	// left in the one output that outlives the session.
	//
	// Found by reading a hundred real reports and being unable to answer
	// "was this project hardened, or unexamined?" from any of them.
	// The count in the STORED report is what the client actually sent, not what
	// the stages asked for.
	//
	// Those were the same number until the breaker started refusing to send.
	// Then a scan that issued 88 requests reported 1,827 -- every request the
	// plan wanted, including the seventeen hundred it declined to make. A
	// report that overstates its own traffic is the same class of error as one
	// that overstates its coverage: the reader cannot tell effort from intent.
	sentBackend, _ := c.Stats()
	sentApplication, _ := webClient.Stats()
	requests = int(sentBackend+sentApplication) + externalProviderRequests
	// Only when the pipeline ran. The summary says how many relations were
	// discovered across how many schemas, and with no pipeline those are not
	// zero -- they are unmeasured. Printing "0 relations across 0 schemas"
	// would invent a measurement, which is the one thing this finding exists
	// to prevent.
	if supabaseOK {
		all = append(all, finding.ScanSummary(target(o), cov.Relations, cov.Schemas,
			requests, cov.SeedOrigins))
	}

	// A target that refused everything gets said plainly, next to the summary
	// that would otherwise read "0 relations" the same way a hardened project
	// does. Emitted here for the same reason the cut-short notice below is:
	// this is the last point before the sort and the write loop.
	if c.GaveUp() {
		sentN, _ := c.Stats()
		all = append(all, gaveUpFinding(target(o), sentN, c.KeyRejected(),
			creds.JWTRole(o.anonKey), keyOrigin(o)))
	}

	all, worst, blind, err := emitAll(w, all)
	if err != nil {
		return 0, worst, nil, err
	}

	finishReport(o, all, start, reportStats{
		Relations: cov.Relations, ApplicationRoutes: applicationRoutes,
		ApplicationOrigins: applicationOrigins, ProviderNames: providerNames,
		Requests: requests, Relational: true, Abandoned: c.GaveUp(), Spend: spend,
	})

	// The summary table, before the plain rendering and the exit code.
	//
	// Suppressed for -json on stdout, which is the pipeline case: a table
	// interleaved with JSONL corrupts both. Suppressed for -silent too, unlike
	// -plain, because this is a nicer view of output the operator has already
	// seen rather than an answer they asked for.
	if !o.silent && !(o.jsonOut && o.output == "") && !o.csvOut && !o.agentOut {
		if tbl := finding.Table(all, o.noColor); tbl != "" {
			fmt.Fprint(os.Stderr, tbl)
		}
	}

	// Outside the stats block on purpose. -silent suppresses the running
	// commentary, but -plain is not commentary: it is the answer somebody asked
	// for, and a flag another flag quietly cancels gets reported as broken.
	printPlain(o, all)

	// The exit code is decided once, after every target, so a list does not
	// terminate on the first project that happens to have a problem.
	return len(all), worst, blind, nil
}

// dedupStrings removes adjacent duplicates from a sorted slice.
func dedupStrings(xs []string) []string {
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

// unknownFlags returns argv entries that look like flags and are not
// registered. It runs before Parse so a typo cannot reach the flag package's
// ExitOnError, whose exit code collides with this program's "findings" code.
//
// Everything after a bare "--" is a positional argument by convention and is
// left alone.
func unknownFlags(fs *goflags.FlagSet) []string {
	var bad []string
	for _, a := range os.Args[1:] {
		if a == "--" {
			break
		}
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		name := strings.TrimLeft(a, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if name == "" || name == "h" || name == "help" {
			continue
		}
		if fs.CommandLine.Lookup(name) == nil {
			bad = append(bad, a)
		}
	}
	return bad
}

// refFromHost returns the project reference encoded in a managed Supabase
// hostname, or "" for any other URL.
//
//	https://abcdefghijklmno.supabase.co  ->  abcdefghijklmno
//	https://app.example.com              ->  ""
func refFromHost(target string) string {
	h := target
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	const suffix = ".supabase.co"
	if !strings.HasSuffix(h, suffix) {
		return ""
	}
	ref := strings.TrimSuffix(h, suffix)
	if strings.Contains(ref, ".") || ref == "" {
		return ""
	}
	return ref
}

// mailboxFor builds the confirmation-mail provider the operator asked for.
//
// Nil unless -mailbox names one, because it is a call to a third party and the
// scan path is otherwise free of them. The key comes from the environment, not
// a flag: a credential on the command line is a credential in the shell history
// and in `ps` output for every other user on the machine.
func mailboxFor(o *options, limiter *client.Limiter, timeout time.Duration) mailbox.Provider {
	switch o.mailbox {
	case "":
		return nil
	case "agentmail":
		key := os.Getenv("AGENTMAIL_API_KEY")
		if key == "" {
			gologger.Warning().Msg("-mailbox agentmail needs AGENTMAIL_API_KEY; " +
				"a confirm-required project will be reported as unmeasured")
			return nil
		}
		return &mailbox.AgentMail{Key: key, Client: client.New(client.Options{
			BaseURL: "https://api.agentmail.to", RestPrefix: "/",
			// No project credential reaches a mailbox service, for the same
			// reason none reaches a web server.
			ProjectRef: "", AnonKey: "", Bearer: "", Schema: "",
			Concurrency: 1, Timeout: timeout, Retries: 1,
			RateLimit: 0, Limiter: limiter, UserAgent: client.UserAgent(),
			MaxBody: 0,
		})}
	default:
		gologger.Warning().Msgf("unknown -mailbox provider %q; confirmation mail will "+
			"not be received", o.mailbox)
		return nil
	}
}

// crawlBudget is -max-pages, or zero when the operator has said not to touch
// the application's own pages.
//
// -no-routes means "skip the application route authorisation check", and the
// audit read that as a promise about traffic rather than about one check:
// TestNoRoutesStopsProbingApplicationRoutes counts requests to the site's
// pages and fails if any arrive. Adding a crawler broke it immediately, which
// is the guard doing precisely its job -- following links IS touching the
// project's own pages, whatever the feature is called, and an operator who
// asked for silence there meant it.
func crawlBudget(o *options) int {
	if o.skipRoutes {
		return 0
	}
	return o.maxPages
}
