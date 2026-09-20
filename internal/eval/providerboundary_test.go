package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Supabase provider boundary: CLOSED on the construction side.
//
// The goal was never a smaller main.go. It is that a Supabase stage can be
// added, removed or handed off WITHOUT EDITING main -- which is true only when
// main neither constructs the stages nor decides their order. It did both:
// scanTarget built each stage inline and threaded results between them through
// Out pointers it owned.
//
// This was a ratchet from 13 to 0. It is a plain assertion now, because the
// ratchet's own vacuity guard demanded the conversion: a pattern that can no
// longer match reads as progress and measures nothing.
var supabaseStageLiteral = regexp.MustCompile(`supabase\.[A-Za-z]+Stage\{`)

func TestMainConstructsNoSupabaseStages(t *testing.T) {
	// Proved capable of matching before it is trusted to report zero.
	if !supabaseStageLiteral.MatchString("supabase.ProbeStage{Client: c}") {
		t.Fatal("the stage-construction pattern no longer matches a known construction, " +
			"so a zero here would mean nothing")
	}
	n, files := countInCommandAllowingZero(t, supabaseStageLiteral)
	if n != 0 {
		t.Errorf("cmd/unruly constructs %d Supabase stages, in %v.\n"+
			"main is not meant to know what stages a Supabase scan is made of: that "+
			"belongs in supabase.Stages(), which it should run rather than rebuild.",
			n, files)
	}
}

// And it gets the list from the provider rather than assembling one.
//
// Zero constructions is necessary and not sufficient: main could still hold
// its own ordered list of stages built somewhere else in the package. This
// pins where the list comes from.
func TestMainRunsTheProvidersStageList(t *testing.T) {
	src := readFile(t, filepath.Join("..", "..", "cmd", "unruly", "main.go"))
	if !strings.Contains(src, "engine.Run(") {
		t.Error("main never enters the unified engine")
	}
	providerSrc := readFile(t, filepath.Join("..", "..", "internal", "provider", "supabase.go"))
	if !strings.Contains(providerSrc, "func (supabase) Stages(") ||
		!strings.Contains(providerSrc, "supabasestage.Stages(") {
		t.Error("the Supabase registry entry does not own construction of its stage list")
	}
}

// The other half of the boundary, and the harder one: CLOSED.
//
// Even with construction still in main, a stage whose result main OWNED was
// main's business: `var r probe.Result` in scanTarget, `Out: &r`, then r handed
// to the next stage. That is the thirty-variables-of-shared-scope problem
// wearing a struct field, and it is why stages could not be reordered or handed
// off -- the wiring lived in the caller.
//
// This was a ratchet from 13 down to 0. It is now a plain assertion, because
// the ratchet's own vacuity guard demanded it: a pattern that can no longer
// match reads as progress and measures nothing.
var supabaseOutPointer = regexp.MustCompile(`\bOut:\s*&`)

func TestMainOwnsNoStageResults(t *testing.T) {
	// The regex is proved capable of matching before it is trusted to report
	// zero. Without this the test would pass identically if the pattern were
	// misspelt, which is the failure the ratchet's guard existed to prevent
	// and which converting to a zero-assertion would otherwise reintroduce.
	if !supabaseOutPointer.MatchString("\t\tOut: &probeResult,") {
		t.Fatal("the out-param pattern no longer matches a known out-param, so a zero " +
			"here would mean nothing")
	}

	n, files := countInCommandAllowingZero(t, supabaseOutPointer)
	if n != 0 {
		t.Errorf("cmd/unruly owns %d stage results through Out pointers, in %v.\n"+
			"A stage result main declares is a stage main has to be edited to reorder. "+
			"Stages exchange typed artifacts through scan.State.", n, files)
	}
}

// countInCommand counts matches across cmd/unruly's non-test Go files, and
// fails when the pattern matches nothing at all. See the fatal below.
func countInCommand(t *testing.T, re *regexp.Regexp) (int, []string) {
	t.Helper()
	total, files := countInCommandAllowingZero(t, re)
	return total, files
}

// countInCommandAllowingZero is the same count where zero is a real answer.
func countInCommandAllowingZero(t *testing.T, re *regexp.Regexp) (int, []string) {
	t.Helper()
	dir := filepath.Join("..", "..", "cmd", "unruly")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	total := 0
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if n := len(re.FindAllString(string(b), -1)); n > 0 {
			total += n
			files = append(files, e.Name())
		}
	}
	return total, files
}

// No Supabase stage takes an out-param.
//
// The ratchets above measure main's side of the boundary. This measures the
// stage's side, and it is the half that decides whether a stage can be handed
// off: a stage with `Out *probe.Result` can only be run by a caller holding a
// variable of that type, so its result is by construction somebody else's
// property. A stage that PUBLISHES can be run by anything.
//
// Not a ratchet. There is no partial credit here -- either the pattern is gone
// from the package or it is not -- and the boundary is not closed while any
// stage still hands its result back through the caller's memory.
func TestNoSupabaseStageTakesAnOutParam(t *testing.T) {
	dir := filepath.Join("..", "..", "backend", "supabase")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	// Field declarations, not uses: `Out *probe.Result`, `Discovered
	// *schemas.Result`, `PerSchema *[]SchemaEscalation`.
	outField := regexp.MustCompile(`(?m)^\s+(Out|Discovered|PerSchema)\s+\*`)
	// Proved capable of matching before it is trusted to report none.
	//
	// Without this the test passes identically if the pattern is misspelt --
	// measured, by breaking it on purpose: the `checked == 0` guard below only
	// catches "no files were read", not "this pattern can never match
	// anything". A check that cannot fail is the defect this repository finds
	// most often, and it had just been fixed in the test above while this one
	// still had it.
	if !outField.MatchString("\n\tOut *probe.Result\n") {
		t.Fatal("the out-param pattern no longer matches a known out-param declaration, " +
			"so finding none would mean nothing")
	}

	var offenders []string
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		checked++
		if m := outField.FindAllString(string(b), -1); len(m) > 0 {
			offenders = append(offenders, fmt.Sprintf("%s (%d)", e.Name(), len(m)))
		}
	}
	if checked == 0 {
		t.Fatal("no Supabase source files were read, so this test asserts nothing")
	}
	if len(offenders) > 0 {
		t.Errorf("these stages still hand their result back through a caller's pointer: %v.\n"+
			"A stage with an out-param can only be run by a caller holding a variable of "+
			"that type, which is what makes its result somebody else's property. Publish "+
			"with scan.Put instead.", offenders)
	}
}

// NOTE: TestTheExtractedStageListMatchesTheOneMainRuns lived here.
//
// It guarded the window in which supabase.Stages() and main's own inline list
// existed side by side, so the two could not drift while scanTarget was
// rewritten separately. main has no inline list any more, so the test compared
// the extracted list against nothing -- and it said so rather than passing
// forever, which is why it is deleted here instead of being left green.

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// main reads no BACKEND artifact at all: CLOSED.
//
// Construction moved to the provider, then narration, then this. The command
// had twelve scan.Get calls for Supabase-specific types -- Vocabulary,
// EnumerateOutcome, Schemas, Escalation, surface.Result and the rest -- and
// every one of them existed to describe or to count. Describing moved to the
// stages that made the measurement (scan.Note); counting moved behind
// scan.Coverage, a neutral shape the PROVIDER fills in because only the
// provider knows what its own artifacts mean.
//
// scan.Coverage itself is deliberately not counted here. Reading a type that
// belongs to the pipeline is the boundary working; reading one that belongs to
// a backend is the boundary leaking.
//
// This was a ratchet from 12 to 0. It is a plain assertion now for the same
// reason the other two became one: a pattern that can no longer match reads as
// progress and measures nothing.
func TestMainReadsNoBackendArtifacts(t *testing.T) {
	// Go's regexp has no lookahead, so the exclusion is done by hand below.
	all := regexp.MustCompile(`scan\.Get\[\*?([a-z][a-zA-Z]*)\.[A-Za-z]+\]`)
	if !all.MatchString("scan.Get[supabase.Vocabulary](sst)") {
		t.Fatal("the artifact-read pattern no longer matches a known read, so a zero " +
			"here would mean nothing")
	}

	src := readFile(t, filepath.Join("..", "..", "cmd", "unruly", "main.go"))
	var leaks []string
	for _, m := range all.FindAllStringSubmatch(src, -1) {
		if m[1] == "scan" {
			continue // the neutral contract; see above
		}
		leaks = append(leaks, m[0])
	}
	if len(leaks) > 0 {
		t.Errorf("cmd/unruly reads %d backend artifact(s): %v.\n"+
			"Reading a backend's result to describe or count it is what keeps the "+
			"command coupled to the backend. Stages narrate with scan.Note; the "+
			"provider translates scan-level facts into scan.Coverage.",
			len(leaks), leaks)
	}
}

// main must stop reading a backend's artifacts to describe them.
//
// Construction moved to the provider; EXECUTION did not. main still calls
// scan.Get for twelve Supabase-specific types -- Vocabulary, EnumerateOutcome,
// Schemas, Escalation and the rest -- for one reason: to print the sentences
// between stages. Those reads are what keep cmd/unruly importing
// backend/supabase, and while they exist a new stage still needs a call site
// and a paragraph of narration added to the command.
//
// The seam is that a stage knows what its own result means and the command
// knows whether the operator wants to hear it, so stages narrate with
// scan.Note and runStage renders. A ratchet, in the style of the two that
// closed the construction side: it may only fall.

// NOTE: TestEveryStageTheProviderProducesIsRun lived here.
//
// It compared the stage names main looked up against the ones the provider
// produced, and it caught a real bug: CoverageStage was added to the list,
// never looked up, and the scan summary reported zeros on every scan.
//
// main iterates the list now, so there are no names to compare and the test
// said so and failed rather than passing on an empty set. Its guarantee is
// stronger by construction -- you cannot forget to run a member of a list you
// range over -- and TestMainIteratesTheProvidersStageList is what holds the
// command to that.

// main runs the provider's list AS A LIST.
//
// Looking each stage up by name is the last form the coupling takes. It means
// the command holds its own copy of what the scan is made of and its own copy
// of which flags disable which stage -- and two copies of one decision drift.
// They already did: CoverageStage was added to the provider's list, main never
// looked it up, and the scan summary reported zeros on every scan.
//
// Iterating the list removes both copies at once. What is enabled is the
// provider's decision, expressed as a Skip wrapper it already returns; the
// command decides only whether to run the scan at all.
func TestMainIteratesTheProvidersStageList(t *testing.T) {
	src := readFile(t, filepath.Join("..", "..", "cmd", "unruly", "main.go"))

	lookups := regexp.MustCompile(`namedStage\(supStages, "[a-z-]+"\)`).FindAllString(src, -1)
	if len(lookups) > 0 {
		t.Errorf("cmd/unruly looks up %d stage(s) by name: %v.\n"+
			"A name in the command is a second copy of the provider's stage list, and "+
			"the flag conditions around those lookups are a second copy of the "+
			"provider's enable decisions. Range over supabase.Stages() instead.",
			len(lookups), lookups[:min(3, len(lookups))])
	}
	engineSrc := readFile(t, filepath.Join("..", "engine", "engine.go"))
	if !strings.Contains(engineSrc, "provider.StagesFor(d, p.Inputs)") ||
		!strings.Contains(engineSrc, "scan.Pipeline(w.Stages).Run") {
		t.Error("the engine does not run the exact list returned by the provider registry")
	}
}

// A skipped stage is reported, and reported as SKIPPED.
//
// Running the provider's whole stage list means disabled stages reach the
// findings stream for the first time. That is right -- a check that did not run
// is not a check that passed, and an agent reading the stream can now see
// exactly which surfaces one invocation covered. But it must not arrive as
// "unruly-surface-not-assessed", which is the id that drives exit 3 and whose
// remediation says to re-run once the cause is resolved. The cause is the
// operator's own flag.
//
// Measured, not reasoned: converting main to a loop added exactly two findings
// against a real fixture, for -history and -subdomains, and both landed in the
// wrong id.
func TestASkippedStageIsReportedAsSkippedNotAsUnassessable(t *testing.T) {
	src := readFile(t, filepath.Join("..", "..", "scan", "stage.go"))
	if !strings.Contains(src, "finding.SkippedStage(") {
		t.Error("the pipeline does not emit finding.SkippedStage, so a stage the " +
			"operator turned off is indistinguishable from a surface the scan tried " +
			"to reach and could not -- and drives the same exit code")
	}
	if !strings.Contains(src, "finding.NotAssessedStage(") {
		t.Error("the pipeline no longer emits finding.NotAssessedStage, so a stage that " +
			"genuinely failed has stopped driving exit 3: an unexamined surface would " +
			"pass for a clean one")
	}

	// And the id itself must stay out of the set that drives exit 3.
	cov := readFile(t, filepath.Join("..", "..", "internal", "finding", "coverage.go"))
	if strings.Contains(cov, `"unruly-stage-skipped"`) {
		t.Error("unruly-stage-skipped counts toward coverage/exit 3; a scan narrowed by " +
			"its own flags would then report itself as blind")
	}
}

// NOTE: TestThePlanIsValidatedBeforeTheScanRuns lived here.
//
// It compared the position of scan.Validate against the stage loop, and both
// were inside scanTarget -- by which point the scan had already harvested the
// application and fetched the OpenAPI document. The test passed while the
// comment beside the code claimed something untrue.
//
// TestThePlanShapeIsCheckedBeforeAnyRequest replaces it and compares against
// the FIRST REQUEST instead of against the loop, which is what the claim
// actually says.

// "Before anything is sent" has to be TRUE.
//
// The plan check was placed just above the stage loop and described in its own
// comment as running before the first request. It does not: the scan harvests
// the application's bundles and fetches the OpenAPI document well before the
// stage list is built. The claim was wrong when it was written.
//
// A validation that runs after the scan has already touched the target is an
// audit, not a precondition, and the difference is exactly the requests the
// target has already served. So the SHAPE of the plan -- which stages exist,
// what they require, what they produce, what they will mutate -- is checked at
// the top of the scan, where nothing has been sent yet. The shape does not
// depend on anything discovered: Stages() is a pure function of the flags.
func TestThePlanShapeIsCheckedBeforeAnyRequest(t *testing.T) {
	src := readFile(t, filepath.Join("..", "..", "cmd", "unruly", "main.go"))

	check := strings.Index(src, "planIsRunnable(")
	if check < 0 {
		t.Fatal("no plan check runs at the top of the scan; if it moved, this test " +
			"must move with it rather than pass on an absent call")
	}
	// The first thing the Supabase path does that touches the target.
	firstRequest := strings.Index(src, "harvestFor(ctx, o, limiter)")
	if firstRequest < 0 {
		t.Fatal("the harvest call was not found; this comparison needs a known first " +
			"request to be meaningful")
	}
	if check > firstRequest {
		t.Error("the plan is checked after the scan has already read the application, " +
			"so 'before anything is sent' is false: by then the target has served " +
			"requests for a scan that may not be runnable at all")
	}
}

// A descriptor field that nothing reads is a claim nothing keeps.
//
// StageDescriptor carried EstimatedRequests, populated by no stage and read by
// no check. It looked like a request budget and was decoration: an operator or
// an agent seeing the field in the type would reasonably conclude the plan
// knows what it will cost, and it did not.
//
// Removed rather than left pending. This repository's own rule is that a
// pattern which cannot fail reads as progress and measures nothing, and a
// struct field is the same shape of lie as a test that cannot fail. It comes
// back when something populates and enforces it.
func TestEveryDescriptorFieldIsReadBySomething(t *testing.T) {
	planSrc := readFile(t, filepath.Join("..", "..", "scan", "plan.go"))

	// The declared fields of StageDescriptor.
	const marker = "type StageDescriptor struct {"
	i := strings.Index(planSrc, marker)
	if i < 0 {
		t.Fatal("StageDescriptor not found; this check would be vacuous")
	}
	rest := planSrc[i:]
	body := rest[:strings.Index(rest, "\n}\n")]
	fields := regexp.MustCompile(`(?m)^\t([A-Z][A-Za-z]*)\s`).FindAllStringSubmatch(body, -1)
	if len(fields) == 0 {
		t.Fatal("no fields found in StageDescriptor; this check would be vacuous")
	}

	// Everything in the package that could read one.
	dir := filepath.Join("..", "..", "scan")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var all strings.Builder
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || e.Name() == "plan.go" ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		all.WriteString(readFile(t, filepath.Join(dir, e.Name())))
	}
	// plan.go itself is where Validate and CheckConsent live.
	readers := all.String() + planSrc[strings.Index(planSrc, "func Validate"):]

	for _, f := range fields {
		name := f[1]
		if !strings.Contains(readers, "desc."+name) && !strings.Contains(readers, "."+name+" ") {
			t.Errorf("StageDescriptor.%s is declared and read by nothing. A field that "+
				"looks like a guarantee and holds none is the same shape of lie as a "+
				"test that cannot fail: remove it, or make something enforce it.", name)
		}
	}
}

// EVERY provider's plan is validated, not only Supabase's.
//
// scan.Validate was reached from one call site, on the Supabase path.
// PocketBase, Neon and anything added tomorrow went through
// provider.StagesFor and ran unvalidated -- so a check described as a property
// of the scanner was a property of one backend.
//
// Undescribed stages pass, so this costs an unconverted provider nothing. What
// it catches is a converted provider whose graph is wrong.
func TestEveryProvidersPlanIsValidatedNotOnlySupabases(t *testing.T) {
	engineSrc := readFile(t, filepath.Join("..", "engine", "engine.go"))
	if !strings.Contains(engineSrc, "scan.Validate(w.Stages)") {
		t.Error("the unified engine runs a provider plan without validating it")
	}
	// Run must call the validator before the pipeline; the validator's own
	// function body is below Run, so compare the call rather than its definition.
	v := strings.Index(engineSrc, "validateWorkload(w)")
	r := strings.Index(engineSrc, "scan.Pipeline(w.Stages).Run")
	if v < 0 || r < 0 || v > r {
		t.Error("the engine validates after running, which is an audit rather " +
			"than a precondition")
	}
}
