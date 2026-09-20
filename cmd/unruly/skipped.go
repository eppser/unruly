package main

import "github.com/eppser/unruly/internal/finding"

// skippedChecks is the report's account of its own blindness: every check that
// did not run, why, and the flag that would run it.
//
// Extracted from scanTarget, where it was 111 lines with no section marker of
// its own -- so every measurement of that function counted it as part of the
// escalation stage above it.
//
// It is a pure function of the options plus one scan fact, which is why it can
// be tested without a client, a fixture or Docker. Before this it could only
// be exercised end-to-end through the binary.
//
// ORDER IS PART OF THE CONTRACT. The slice feeds finding.Coverage, and reports
// are diffed between runs -- eval-determinism requires byte-identical output.
// The tests assert the SEQUENCE of names, not membership: a set comparison
// would pass while the report churned.
func skippedChecks(o *options, signupOpen bool) []finding.SkippedCheck {
	var skipped []finding.SkippedCheck
	if o.measure {
		skipped = append(skipped, finding.SkippedCheck{
			Name: "graphql", Enable: "drop -measure",
			Reason: "the GraphQL surface was not examined: telling a readable relation " +
				"from a filtered one requires retrieving node ids, which decode to real " +
				"primary keys, and -measure retrieves no data"})
	}
	if !o.invoke {
		skipped = append(skipped,
			finding.SkippedCheck{Name: "routine-callability", Enable: "-write -invoke -yes-i-own-this",
				Reason: "learning whether a routine can be called requires calling it, and a callable routine runs"},
			finding.SkippedCheck{Name: "edge-functions", Enable: "-write -invoke -yes-i-own-this",
				Reason: "detecting a function requires a POST that invokes it"})
	}
	if !o.write {
		skipped = append(skipped,
			finding.SkippedCheck{Name: "realtime-delivery", Enable: "-write -yes-i-own-this",
				Reason: "proving a relation's changes reach an anonymous listener means " +
					"CAUSING a change, and a subscription acknowledgement proves nothing: " +
					"Supabase accepts one for a relation that does not exist"},
			finding.SkippedCheck{Name: "write-exposure", Enable: "-write -yes-i-own-this",
				Reason: "determining whether a relation accepts anonymous INSERT requires attempting one"})
		if !o.skipRoutes && o.site != "" {
			skipped = append(skipped, finding.SkippedCheck{
				Name: "route-post-probing", Enable: "-write -yes-i-own-this",
				Reason: "a POST-only route family answers 405 to GET, which is not an authorisation signal"})
		}
	}
	// -no-residue declines checks that -write would otherwise have performed,
	// so the two flags together leave a gap neither one alone reports. Recorded
	// here rather than left silent: for this project, a check that did not run
	// and a check that found nothing must never look the same in the artifact.
	if o.write && o.noResidue {
		skipped = append(skipped,
			finding.SkippedCheck{Name: "bucket-write", Enable: "-write -yes-i-own-this without -no-residue",
				Reason: "deciding whether a public bucket accepts an anonymous upload means " +
					"uploading, and a bucket granting INSERT without DELETE keeps the file"},
			finding.SkippedCheck{Name: "realtime-delivery", Enable: "-write -yes-i-own-this without -no-residue",
				Reason: "delivery is proven by CAUSING a change, and a write that collides " +
					"with a unique constraint changes no row, so there is nothing to deliver"})
		if !o.skipRoutes && o.site != "" {
			skipped = append(skipped, finding.SkippedCheck{
				Name: "route-post-probing", Enable: "-write -yes-i-own-this without -no-residue",
				Reason: "an application route whose fields are all optional accepts an empty " +
					"POST body and creates a record"})
		}
	}
	// The preview-deployment sweep needs somewhere to sweep.
	//
	// Without a site or explicit hosts it cannot run, and it must not invent
	// hostnames to give itself something to do: those requests would go to
	// whoever owns the names it guessed. Silence there reads exactly like a
	// sweep that ran and found nothing, which is the confusion this disclosure
	// exists to prevent -- and historical-credentials, a check skipped for the
	// same reason, has always been listed.
	if o.site == "" && o.previewHosts == "" {
		skipped = append(skipped, finding.SkippedCheck{
			Name: "preview-deployments", Enable: "-site <url> or -preview <hosts>",
			Reason: "no site or host list was given, so preview and staging deployments " +
				"were not swept. Those frequently ship the same credentials as production " +
				"behind weaker access control, and hostnames are never guessed"})
	}
	if !o.checkHistory && o.site != "" {
		skipped = append(skipped, finding.SkippedCheck{
			Name: "historical-credentials", Enable: "-history",
			Reason: "public archives were not searched for credentials this application used to ship"})
	}
	// Two more surfaces that go quiet when nothing was supplied. Found by
	// TestEveryStageThatCanDeclineIsAccountedFor, which reads the stages
	// rather than trusting this list to be complete -- not by an operator
	// wondering why a report said nothing about either.
	//
	// The note further down covers checks the operator TURNED OFF. These are
	// checks that never had an input, which is the preview-deployments case
	// exactly: RoutesStage returns immediately on an empty site, and
	// SubdomainStage on an empty domain, and both did so in silence.
	if o.site == "" {
		skipped = append(skipped, finding.SkippedCheck{
			Name: "application-routes", Enable: "-site <url>",
			Reason: "no application was named, so route authorisation consistency was not " +
				"examined; a route answering anonymously while its siblings demand " +
				"credentials would not be seen"})
	}
	if !o.subdomains || o.site == "" {
		enable := "-subdomains"
		if o.site == "" {
			enable = "-subdomains -site <url>"
		}
		skipped = append(skipped, finding.SkippedCheck{
			Name: "subdomain-enumeration", Enable: enable,
			Reason: "sibling hostnames under the application's registrable domain were not " +
				"enumerated, so a staging or admin host serving the same project was not " +
				"looked for"})
	}
	// Every read in this report was performed as `anon`, and a relation this
	// scan calls protected is protected FROM ANON. Policies written TO
	// authenticated are routinely far looser -- that is the whole reason the
	// escalation pass exists -- so a scan without one measured half the read
	// surface and the report has to say which half.
	//
	// This was a log line, eight lines above the comment explaining that a log
	// line is exactly what does not survive: the findings stream is what gets
	// stored, diffed and read by somebody who was not watching the terminal.
	// It also only fired when signup was open, so a project with closed signup
	// and thousands of authenticated users said nothing at all.
	//
	// Signing up automatically would answer it, and is deliberately not done:
	// minting a JWT that way creates an account, which is a mutation against
	// somebody else's project.
	// Withholding the operator's key changes what this scan could see, and it
	// was another decision that existed only as a log line. A reader of the
	// report for the second project sees a thin result and no way to know the
	// -key they passed was deliberately not used here.
	if o.keyWithheldRef != "" {
		skipped = append(skipped, finding.SkippedCheck{
			Name:   "supplied-credential",
			Enable: "scan this project on its own, with a key issued for it",
			Reason: "the -key supplied claims project \"" + o.keyWithheldRef + "\" and was " +
				"NOT sent to this one; sending it would have put another project's " +
				"credential on this server and reported on the 401s. Anything below was " +
				"found with credentials discovered from this target alone, or with none"})
	}
	if o.userJWT == "" {
		reason := "every read was performed as the anonymous role, so policies written " +
			"TO authenticated were not assessed; a relation reported as protected here " +
			"is protected from anon and may be readable by any signed-in user"
		if signupOpen {
			reason += ". PUBLIC SIGNUP IS OPEN on this project, so anyone at all can " +
				"obtain that role"
		}
		skipped = append(skipped, finding.SkippedCheck{
			Name: "role-escalation", Enable: "-user-jwt <token>", Reason: reason})
	}
	// A check the operator TURNED OFF is a check that did not run, and the
	// report has to say so. These were the only two flags whose effect was
	// invisible: passing -no-realtime or -no-routes disabled the check AND
	// suppressed any note that it had been disabled, so a scan with them read
	// exactly like a scan where those surfaces came back clean. An audit
	// found it. The guard on route-post-probing above has the same shape and
	// the same cause.
	if o.skipRealtime {
		skipped = append(skipped, finding.SkippedCheck{
			Name: "realtime", Enable: "remove -no-realtime",
			Reason: "the Realtime surface was not examined at all; whether relation " +
				"changes reach anonymous listeners is unknown"})
	}
	if o.skipRoutes && o.site != "" {
		skipped = append(skipped, finding.SkippedCheck{
			Name: "application-routes", Enable: "remove -no-routes",
			Reason: "route authorisation consistency was not examined; a route answering " +
				"anonymously while its siblings demand credentials would not be seen"})
	}
	return skipped
}
