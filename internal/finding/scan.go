// Findings that describe the SCAN rather than the target.
//
// They live here, not in cmd/unruly, because the coverage check builds
// its profile from ./internal/... only -- a constructor in main.go can never
// have an emit site the check can see, and passes only by accident when some
// other package happens to construct the same id. That accident held for
// three of these until a fourth was added and the audit failed.

package finding

import (
	"strconv"
	"strings"
)

// NotAssessedSchema reports that an exposed schema could not be judged. It
// reuses the id the exit code already keys on, so an unmeasured schema drives
// exit 3 exactly like an unmeasured surface.
func NotAssessedSchema(restBase, schema, detail string) Finding {
	return Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "An exposed schema was not assessed",
		Severity: Info,
		Protocol: "postgrest",
		Matched:  restBase,
		Resource: "schema:" + schema,
		Description: "PostgREST exposes the schema " + schema + " and this scan could not " +
			"establish what is in it: " + detail + ". Relations there are reachable with an " +
			"Accept-Profile header, so this is an unmeasured part of the read surface, not " +
			"an empty one.",
		Remediation: "Enumerate it directly with names you know:\n\n" +
			"curl -sS '" + restBase + "/<relation>?select=*&limit=1' \\\n" +
			"  -H 'apikey: $SUPABASE_ANON_KEY' -H 'Accept-Profile: " + schema + "'\n\n" +
			"If the schema is not meant to be part of the public API, stop exposing it.",
		Evidence: Evidence{Reason: detail},
	}
}

// NotAssessedWrite reports that write access to a relation was requested but
// could not be established either way.
//
// Before this, an inconclusive write verdict produced NOTHING: probe.Findings
// emitted a finding for WriteReached only, so a relation the write probe
// declined vanished from the report and from the exit code. On the reference
// target, `-write -no-residue` tests four INSERT-reachable relations, silently
// skips cve_articles -- which is INSERT-reachable but not read-exposed, so
// there is no sampled row to collide with -- and exits as though the write
// surface had been assessed in full. That is the tool's own thesis inverted:
// absence of a finding is only evidence when the scan could see.
//
// It reuses the id the exit code already keys on, so an unassessed write drives
// exit 3 exactly like an unmeasured schema. That does mean -no-residue exits 3
// on any project with an unreadable relation, which is the honest answer rather
// than the notBlindResources case: the routine cap is a DEFAULT that binds
// almost everywhere, while -no-residue is a mode the operator chose and whose
// help text says it "costs write recall". Having opted in, they are owed the
// list of what it cost. Not passing -write at all stays exit 0, because no
// write assessment was requested.
func NotAssessedWrite(restURL, relation, detail string) Finding {
	return Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "Write access to a relation was not assessed",
		Severity: Info,
		Protocol: "postgrest",
		Matched:  restURL,
		Resource: "write:" + relation,
		Description: "This scan tried to establish whether the anonymous role can INSERT " +
			"into " + relation + " and could not: " + detail + ". The relation is neither " +
			"known writable nor known protected, so treat it as untested rather than safe.",
		Remediation: "-- Test it on a project you own, accepting that a probe row may be\n" +
			"-- created:\n" +
			"--   unruly -u <target> -write -yes-i-own-this\n" +
			"-- -no-residue avoids creating rows by re-sending a sampled row so the\n" +
			"-- primary key collides, which it cannot do for a relation this scan could\n" +
			"-- not read. Either drop that flag for this relation, or read the policy:\n" +
			"SELECT polname, polcmd, pg_get_expr(polqual, polrelid) FROM pg_policy " +
			"WHERE polrelid = '" + relation + "'::regclass;",
		Evidence: Evidence{Reason: detail},
	}
}

// NotAssessedVerb reports that UPDATE or DELETE could not be established.
//
// Kept separate from NotAssessedWrite so the report names the verb. "Write was
// not assessed" on a relation whose INSERT verdict is confident reads as a
// contradiction; "DELETE was not assessed" is the actual fact.
//
// DELETE lands here most often, and by design. The only DELETE probe that is
// both sound and non-destructive is one aimed at a row the scan created itself,
// so a relation that refuses INSERT can be read, written and updated by an
// anonymous caller with its DELETE permission still unknown. That is a real
// hole in the report and is stated as one.
func NotAssessedVerb(restURL, relation, verb, detail string) Finding {
	return Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     verb + " access to a relation was not assessed",
		Severity: Info,
		Protocol: "postgrest",
		Matched:  restURL,
		Resource: strings.ToLower(verb) + ":" + relation,
		Description: "This scan tried to establish whether the anonymous role can " + verb +
			" rows in " + relation + " and could not: " + detail + ". The relation is neither " +
			"known open nor known protected for this verb, so treat it as untested.",
		// Prose is commented. Remediation blocks are executed verbatim by the
		// remediation eval -- every line that is not a comment is fed to psql --
		// so an explanatory sentence in column 1 is a syntax error that aborts
		// the whole fix. That is not a test artefact: it is what happens to an
		// operator who pipes the -fix output into their database.
		Remediation: "-- Read the policies directly; this answers all four verbs at once.\n" +
			"-- polcmd is r=SELECT, a=INSERT, w=UPDATE, d=DELETE, *=ALL. A policy written\n" +
			"-- FOR ALL grants every verb, which is the usual reason a table that should\n" +
			"-- only be readable also accepts DELETE.\n" +
			"SELECT polname, polcmd, pg_get_expr(polqual, polrelid) FROM pg_policy " +
			"WHERE polrelid = '" + relation + "'::regclass;",
		Evidence: Evidence{Reason: detail},
	}
}

// Interrupted records that the scan did not finish.
//
// It carries the blindness id the exit code already keys on, so an interrupted
// scan is treated the same as any other surface that could not be assessed --
// no new precedence rule, and CI behaviour that operators already understand.
func Interrupted(where string, cause error) Finding {
	return Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "The scan did not finish",
		Severity: Info,
		Protocol: "unruly",
		Matched:  where,
		Resource: InterruptedResource,
		Description: "The scan was stopped before it completed (" + cause.Error() + "). " +
			"Everything below was found before it stopped and is real, but the list is a " +
			"FRAGMENT: relations that were never probed are missing, and surfaces that were " +
			"never reached are absent rather than clean. Re-run without the interruption " +
			"before treating this as a result.",
		Remediation: "-- Re-run the scan and let it finish. If it was a CI timeout, raise the " +
			"limit or narrow the scan with -severity or -no-routes; if it was a deadline, " +
			"raise -timeout.",
		Evidence: Evidence{Reason: "scan cancelled: " + cause.Error()},
	}
}

// TargetFailed records a target the scan could not get started on.
//
// It carries the blindness id the exit code already keys on, so a failed
// target behaves like any other unmeasured surface rather than needing a rule
// of its own.
func TargetFailed(target string, cause error, keyWithheldRef string) Finding {
	desc := "This target was not scanned: " + cause.Error() + ". Nothing in this report " +
		"describes it, and absence of findings for it is not evidence that it is sound."
	if keyWithheldRef != "" {
		desc += " The -key supplied claims project \"" + keyWithheldRef + "\", so it was " +
			"deliberately not sent here; this target had to discover its own credentials " +
			"and could not."
	}
	return Finding{
		ID:          "unruly-surface-not-assessed",
		Name:        "Target could not be scanned",
		Severity:    Info,
		Protocol:    "unruly",
		Matched:     target,
		Resource:    "target",
		Description: desc,
		Remediation: "-- Re-run against this target on its own to see the failure in full. If " +
			"it is one of several in a -list, give it a credential issued for it.",
		Evidence: Evidence{Reason: cause.Error()},
	}
}

// TargetRefused reports that the scan stopped because the target refused every
// request it had made so far.
//
// This is the loudest possible "could not measure", and it exists because the
// alternative is worse than a slow scan. A host answering 429 or 5xx to
// everything produces a report full of "not assessed" lines and no findings,
// which is shaped exactly like a clean project. The reader has to notice the
// absence to get the answer right, and readers do not.
//
// Severity is Info because it is a statement about the scan, not the target --
// the same rule every scan-diagnostic follows. The exit code is what carries
// the weight: could-not-measure is 3, and 3 is not clean.
func TargetRefused(base string, sent int64, reason string) Finding {
	return Finding{
		ID:       "unruly-target-refused",
		Name:     "The target refused every request, so nothing was measured",
		Severity: Info,
		Protocol: "unruly",
		Matched:  base,
		Resource: "target",
		Description: "Every one of the first " + itoa(sent) + " requests was refused -- " +
			reason + " -- and not one returned anything this scan could classify. " +
			"Probing was stopped rather than continued against a wall. NOTHING is " +
			"known about this project's posture: this is not a clean result, and the " +
			"absence of findings below is the absence of measurement.",
		Remediation: "-- Nothing to fix on the target: this is about reaching it.\n" +
			"--   * If a rate limit or WAF is in front of it, scan more slowly:\n" +
			"--       unruly -u <target> -rate-limit 2\n" +
			"--   * If the address is being blocked, scan from one that is allowed.\n" +
			"--   * If the host is simply down, the result is unknown, not clean --\n" +
			"--     re-run when it is up rather than recording this scan.\n" +
			"-- Nothing below this line is a statement about the database.",
		Evidence: Evidence{Reason: reason, Status: 0},
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// CredentialRejected reports that the project refused the key this scan used,
// so nothing measured is a statement about the project.
//
// Kept separate from TargetRefused because the cause and the fix are different.
// A refusing host is unreachable; a rejected credential means the host is
// talking to us and declining to answer as anybody. The remedy is a different
// key, and the report has to say which key was tried and what role it claimed,
// because "no relations found" and "the key was wrong" look identical from the
// outside and only one of them is about the project.
func CredentialRejected(base string, sent int64, role, source string) Finding {
	which := "The key this scan used"
	switch role {
	case "service_role":
		which = "The key this scan used claims the service_role role. It was found " +
			"in client-side content, and the project would not accept it"
	case "anon":
		which = "The key this scan used claims the anon role, and the project would " +
			"not accept it"
	}
	return Finding{
		ID:       "unruly-credential-rejected",
		Name:     "The project rejected this scan's credential",
		Severity: Info,
		Protocol: "unruly",
		Matched:  base,
		Resource: "credential",
		Description: which + ". All " + itoa(sent) + " requests were answered with an " +
			"authentication failure and not one was accepted, so NOTHING below is a " +
			"statement about this project's posture -- an empty result here means the " +
			"scan was never allowed to look, not that there is nothing to find. Keys " +
			"are rejected for ordinary reasons: rotated since the bundle was built, " +
			"taken from an archived copy, or belonging to a different project. " +
			"Credential source: " + source + ".",
		Remediation: "-- Nothing to fix on the database: this is about the key.\n" +
			"--   * Take the current anon key from the project's API settings and pass\n" +
			"--     it directly:\n" +
			"--       unruly -u <target> -key <anon-key>\n" +
			"--   * If the key came from a bundle behind a sign-in screen, point the\n" +
			"--     scan at a page loaded AFTER authenticating -- that is the bundle\n" +
			"--     carrying the working key.\n" +
			"--   * A service_role key is never used to scan: it bypasses row-level\n" +
			"--     security, so a scan holding one measures nothing about what the\n" +
			"--     PUBLIC can reach. Its exposure is reported separately, and that\n" +
			"--     finding is the serious one.\n" +
			"-- Re-run with a working key before recording this project as clean.",
		Evidence: Evidence{
			Reason: "all " + itoa(sent) + " requests answered 401/403, none accepted",
			Status: 401,
		},
	}
}

// RestPrefixCorrected records that PostgREST was not where the scan first
// asked, and that the scan moved rather than reporting an empty project.
//
// Reported, not silent. A scan that quietly changes where it is looking has
// changed what its result means, and the reader is entitled to know which
// address the findings below describe.
func RestPrefixCorrected(base, from, to string) Finding {
	return Finding{
		ID:       "unruly-rest-prefix-corrected",
		Name:     "PostgREST was mounted somewhere other than the default",
		Severity: Info,
		Protocol: "unruly",
		Matched:  base + to,
		Resource: "rest-prefix",
		Description: "PostgREST answered PGRST125 (\"Invalid path specified in request URL\") " +
			"under " + from + ", which is PostgREST itself saying it is listening but not " +
			"mounted there, and served its OpenAPI document under " + to + ". The scan " +
			"continued against " + to + ". Had it not, every probe would have been " +
			"answered PGRST125 and the report would have said 0 relations -- which reads " +
			"exactly like a project with nothing exposed. The managed product routes " +
			"PostgREST through Kong at /rest/v1; self-hosted deployments commonly serve " +
			"it at the root.",
		Remediation: "-- Nothing to fix: the scan corrected itself and the findings below\n" +
			"-- describe " + base + to + ".\n" +
			"-- To pin it explicitly, and skip the two probes that discovered it:\n" +
			"--   unruly -u <target> -rest-prefix " + to,
		Evidence: Evidence{
			Reason: "PGRST125 under " + from + ", OpenAPI document under " + to,
			Status: 200,
		},
	}
}

// RestPrefixUnresolved reports that PostgREST rejected the mount path the scan
// was using and no alternative could be confirmed.
//
// The scan stops here rather than sending its whole plan to a path the server
// has already refused. Measured: continuing costs 18,756 requests, every one
// answered PGRST125, and produces a report that says 0 relations -- which is
// indistinguishable from a project with nothing exposed.
func RestPrefixUnresolved(base, prefix string) Finding {
	return Finding{
		ID:       "unruly-rest-prefix-unresolved",
		Name:     "PostgREST is not mounted where this scan was asking",
		Severity: Info,
		Protocol: "unruly",
		Matched:  base + prefix,
		Resource: "rest-prefix",
		Description: "PostgREST answered PGRST125 (\"Invalid path specified in request URL\") " +
			"for " + prefix + ", which is PostgREST itself saying it is listening but not " +
			"mounted there. The scan looked for it at the root and could not confirm it, " +
			"so probing stopped instead of sending the rest of the plan to a path the " +
			"server has already rejected. NOTHING below is a statement about this " +
			"project's data: no relation was ever asked about at an address that exists.",
		Remediation: "-- Nothing to fix on the database: the scan was knocking on the wrong door.\n" +
			"--   * Find where PostgREST is mounted -- self-hosted deployments commonly\n" +
			"--     serve it at the root, behind their own gateway path otherwise -- and\n" +
			"--     name it:\n" +
			"--       unruly -u <target> -rest-prefix /\n" +
			"--   * If the root also refused, the credential is likely not accepted here\n" +
			"--     either; supply the project's current anon key with -key.\n" +
			"-- Re-run before recording this project as clean.",
		Evidence: Evidence{
			Reason: "PGRST125 under " + prefix + " and no candidate mount point confirmed",
			Status: 404,
		},
	}
}

// ProbeAccountLeftBehind reports a user account this scan created on the
// target.
//
// Reported for the same reason a probe row is: it is this scanner's own mess,
// not a property of the project, and hiding it would be the least defensible
// silence in the tool. The account is reused on later scans rather than
// recreated, so the litter is one per project and not one per run -- but one is
// still one, and the operator is the person who has to delete it.
func ProbeAccountLeftBehind(base, email string) Finding {
	return Finding{
		ID:       "unruly-probe-account-left-behind",
		Name:     "This scan created a user account and could not remove it",
		Severity: Info,
		Protocol: "gotrue",
		Matched:  base + "/auth/v1/signup",
		Resource: "account:" + email,
		Description: "Measuring what a logged-in user can reach requires being one, and " +
			"on a project with open signup the only way to become one is to sign up. " +
			"This scan registered " + email + " and has no way to delete it: account " +
			"removal needs the service_role key, which a public scan does not have. " +
			"The credential is stored locally and reused, so later scans of this project " +
			"will not create another.",
		Remediation: "-- Delete the account this scan created. It is named after the\n" +
			"-- project so it is findable, and it is the only one this tool makes.\n" +
			"DELETE FROM auth.users WHERE email = '" + email + "';\n" +
			"-- Or from the dashboard: Authentication -> Users -> search for\n" +
			"--   unruly-probe\n" +
			"-- If signup being open is itself unintended, that is the finding worth\n" +
			"-- acting on, and it is reported separately as supabase-open-signup.",
		Evidence: Evidence{Reason: "account " + email + " created by this scan", Status: 200},
	}
}

// WeakPasswordAccepted reports that the project let this scanner register an
// account with a password no policy worth the name would allow.
//
// It costs nothing to establish. The signup path tries the weak password first
// because if it is accepted the account exists after one request instead of
// two -- so the password-policy answer is a by-product of work already done,
// and throwing it away would be discarding a measured fact.
//
// Low, and deliberately so. A weak-password policy is not exposure: nobody's
// data moves because of it. It matters as the cheapest route into the
// authenticated tier for an attacker credential-stuffing a real user, which is
// a different report from the ones above it.
func WeakPasswordAccepted(base, password string) Finding {
	return Finding{
		ID:       "supabase-weak-password-policy",
		Name:     "No password policy above the minimum length",
		Severity: Low,
		Protocol: "gotrue",
		Matched:  base + "/auth/v1/signup",
		Resource: "auth",
		Description: "This project accepted the password " + password + " when registering " +
			"an account, so nothing is enforced beyond the default six-character floor -- " +
			"no complexity requirement, and no check against the lists of passwords every " +
			"credential-stuffing tool starts from. Real users will choose passwords from " +
			"those lists, and each one is an authenticated session an attacker can take " +
			"without touching this project's configuration at all.",
		Remediation: "-- Not a database change: it is an Auth setting.\n" +
			"--   Authentication > Providers > Email > Minimum password length, and\n" +
			"--   Password Requirements (letters, digits, symbols).\n" +
			"--   Leaked-password protection, which checks HaveIBeenPwned, is under\n" +
			"--   Authentication > Attack Protection.\n" +
			"-- Existing weak passwords are not re-checked when the policy changes, so\n" +
			"-- see who would still be affected:\n" +
			"SELECT count(*) FROM auth.users WHERE encrypted_password IS NOT NULL;",
		Evidence: Evidence{
			Reason: "signup accepted " + password,
			Status: 200,
		},
	}
}

// NotAssessedBackend reports that a backend was recognised in the application
// but never examined, because no credential for it was found.
//
// The distinction this draws is the one the whole report rests on. A scan that
// found a service_role key in a bundle and stopped there has produced a real
// finding AND examined no data at all; without this line the reader sees one
// critical result and a silence they will read as "nothing else".
func NotAssessedBackend(where string, requests int) Finding {
	return Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "The backend was recognised but never examined",
		Severity: Info,
		Protocol: "unruly",
		Matched:  where,
		Resource: "backend",
		Description: "A backend was identified in this application and no usable credential " +
			"for it was found, so none of its surfaces were probed: not one relation, " +
			"bucket or routine was asked about. " + itoa(int64(requests)) + " request(s) " +
			"were spent establishing that. Any finding above comes from the application's " +
			"own content rather than from the database, and the absence of database " +
			"findings here is the absence of a scan.",
		Remediation: "-- Nothing to fix: the scan could not start.\n" +
			"--   * Supply the key directly:  unruly -u <target> -key <anon-key>\n" +
			"--   * If the application is behind a sign-in screen, its key ships in the\n" +
			"--     bundle loaded AFTER authenticating; point -u at a page past it.\n" +
			"--   * A service_role key found in the bundle is NOT used for scanning: it\n" +
			"--     bypasses row-level security, so a scan holding one measures nothing\n" +
			"--     about what the public can reach. Its exposure is the finding.",
		Evidence: Evidence{
			Reason: "no usable credential for the detected backend; " +
				itoa(int64(requests)) + " request(s) spent",
		},
	}
}

// SubdomainsFound reports other hosts under the same domain, and does not
// pretend to have scanned them.
//
// The value is the forgotten deployment: a staging or preview host that shipped
// the same backend, was never decommissioned, and nobody has audited since.
// Production gets the review; the second copy is where an anon key with looser
// policies is still live.
//
// Info, and no claim about any of them. Discovering that a host exists says
// nothing about its posture, and rating it as though it did would be the same
// error as reporting a Firestore 403 as a finding.
func SubdomainsFound(domain string, hosts []string, tried int) Finding {
	return Finding{
		ID:       "unruly-subdomains-found",
		Name:     "Other hosts exist under this domain",
		Severity: Info,
		Protocol: "unruly",
		Matched:  domain,
		Resource: "subdomains",
		Description: itoa(int64(len(hosts))) + " of " + itoa(int64(tried)) + " candidate " +
			"host name(s) under " + domain + " resolve. NOTHING was scanned on them and " +
			"nothing is claimed about them: a name resolving says only that it exists. " +
			"They are listed because a second deployment of the same application is where " +
			"an old key with looser policies tends to still be live, and because the host " +
			"nobody audits is the one nobody has fixed. Scanning them is a separate " +
			"decision, deliberately left to you: a subdomain is not automatically yours, " +
			"and status pages and documentation portals commonly point at somebody else's " +
			"infrastructure.",
		Remediation: "-- Nothing to fix. To scan the ones you own, put them in a file and:\n" +
			"--   unruly -l hosts.txt\n" +
			"-- Check first that each is actually yours. This list is what DNS answered,\n" +
			"-- not a statement of ownership.",
		Evidence: Evidence{
			Reason:  itoa(int64(len(hosts))) + " of " + itoa(int64(tried)) + " candidates resolve",
			Columns: hosts,
		},
	}
}

// NotAssessedApplication reports that -site was given and could not be read.
//
// It carries the same id as every other "this scan could not see" statement,
// because that is precisely what it is, and because the exit code already
// treats that id as blindness: an operator who asked for the application to be
// harvested and did not get it must not receive exit 0.
//
// The alternative -- staying quiet and falling back to the pinned wordlist --
// is what the tool did before. Recall dropped, the report got shorter, and
// nothing in it said why.
func NotAssessedApplication(site, detail string) Finding {
	return Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "Application could not be read — enumeration recall is a lower bound",
		Severity: Info,
		Protocol: "unruly",
		Matched:  site,
		Resource: "application",
		Description: "The application at " + site + " was supplied with -site but could " +
			"not be harvested (" + detail + "). Enumeration therefore ran on the pinned " +
			"wordlist alone, which reaches conventional relation names and cannot reach " +
			"the domain-specific ones this project actually uses. Every relation count " +
			"below is a lower bound, and a relation this scan never named cannot appear " +
			"in it.",
		Remediation: "-- Nothing to fix in the database. Check that the -site URL is reachable\n" +
			"-- from where the scan runs, that it is the application rather than an API\n" +
			"-- origin, and that a WAF or rate limit is not refusing the scanner; then\n" +
			"-- re-run. -user-agent can point at a page or mailbox you control if the\n" +
			"-- site blocks unknown clients.",
		Evidence: Evidence{
			Reason:  detail,
			Request: "curl -sS " + site,
		},
	}
}

// NotAssessedStage reports that a whole stage of the scan could not be run.
//
// The pipeline turns every stage error into one of these rather than aborting,
// so a surface that refused a connection is reported as unexamined instead of
// silently passing for clean. It reuses the id the exit code keys on, which is
// what makes an unexamined surface drive exit 3.
func NotAssessedStage(where, stage, detail string) Finding {
	return Finding{
		ID:       "unruly-surface-not-assessed",
		Name:     "A stage of the scan did not run",
		Severity: Info,
		Protocol: "unruly",
		Matched:  where,
		Resource: stage,
		Description: "The " + stage + " stage did not complete: " + detail + ". Nothing in " +
			"this report describes that surface, so its absence from the findings is not " +
			"evidence that it is safe -- it is evidence that it was not looked at.",
		Remediation: "-- Nothing to fix here. Re-run the scan once the cause above is " +
			"resolved, then compare: a surface that reports nothing after being examined " +
			"is a different result from one that was never reached.",
		Evidence: Evidence{Reason: detail},
	}
}

// SkippedStage reports a stage the OPERATOR turned off.
//
// Distinct from NotAssessedStage, and the distinction is this project's own
// argument applied one level down. "Could not be assessed" means the scan
// tried and the surface refused; it drives exit 3, because an unexamined
// surface must not pass for a clean one. "The operator did not ask for this"
// means the scan was told not to look -- reporting that as a failure tells
// somebody to fix a cause that is their own flag, and inflates exit 3 into a
// number that no longer distinguishes a blind scan from a deliberately narrow
// one.
//
// Still reported, and still info: a check that did not run is not a check that
// passed, and the reason names what would enable it.
func SkippedStage(where, stage, reason string) Finding {
	return Finding{
		ID:       "unruly-stage-skipped",
		Name:     "A stage of the scan was not run",
		Severity: Info,
		Protocol: "unruly",
		Matched:  where,
		Resource: stage,
		Description: "The " + stage + " stage was not run: " + reason + ". This scan " +
			"therefore says nothing about that surface. Its absence from the findings " +
			"is not evidence that it is sound -- nobody looked.",
		Remediation: "-- Nothing to fix. Re-run with the option named above to cover " +
			"this surface.",
		Evidence: Evidence{Reason: reason},
	}
}
