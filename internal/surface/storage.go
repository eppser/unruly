package surface

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// ControlBucketName is a bucket that cannot exist. If the target claims it
// does, no answer about any bucket means anything.
//
// Underscore style deliberately: the hyphenated form reads like a finding id,
// and the coverage audit that walks the tree for id literals picks it up as a
// check that has never fired. That exact mistake was made with the Edge
// Function control probe and fixed by renaming; making it again two surfaces
// later is the argument for the audit catching it rather than for trusting
// anyone to remember.
const ControlBucketName = "unruly_control_bucket_that_cannot_exist"

// probeBuckets finds public buckets by name, because they cannot be listed.
//
// GET /storage/v1/bucket returns [] to the anonymous role even when a public
// bucket exists, which is why the storage check reported nothing against a
// project whose bucket was serving invoices to anyone who asked. The exploit
// harness proved the file retrievable while the scan called the surface clean.
//
// Existence is decided by the body of a 400, not its status. Both cases answer
// 400, and the distinction is inside:
//
//	bucket exists    {"error":"not_found","message":"Object not found"}
//	bucket does not  {"error":"Bucket not found"}
//
// The probe asks for an object that will not be there, so it never downloads
// anybody's data to find out whether a bucket exists.
//
// It uses the /object/public path, which is the one a stranger with a URL
// would use. The request DOES carry the scan's credentials: internal/client
// sets apikey and Authorization on every request and has no credential-free
// path. An earlier version of this comment claimed otherwise, and an audit
// caught the same false claim in the exploit harness, where it was fixed with
// doAnonymous — the identical claim here was left standing. Saying "no
// credential is sent" when one is sent is the kind of small untruth that
// makes a report's other claims worth less.
func probeBuckets(ctx context.Context, c *client.Client, o Options, res *Result) []Bucket {
	names := append([]string{}, o.BucketSeeds...)
	sort.Strings(names)
	names = dedupSorted(names)
	if len(names) == 0 {
		return nil
	}

	base := strings.TrimSuffix(c.BaseURL(), "/") + "/storage/v1/object/public/"
	const probeObject = "unruly_probe_object"

	// bucketState is deliberately three-valued. The first version returned a
	// bool and decided existence as NOT(body says "bucket not found"), which
	// makes every unreadable answer a positive: a 429, a 5xx, a 401 from a
	// wrong key, all carry JSON bodies containing no such string, so every
	// candidate in the ~700-name list would be reported as a public bucket,
	// and under -write each would also receive an unsolicited upload attempt.
	//
	// That is the "2684 relations discovered" bug from a bad key, reintroduced
	// one surface over. The control probe cannot catch it: it is a single
	// request issued before any throttling starts.
	//
	// Existence is now affirmative only. Anything else is unknown, counted,
	// and reported — because a bucket the scan could not classify is not a
	// bucket the scan found absent.
	type bucketState int
	const (
		bucketAbsent bucketState = iota
		bucketExists
		bucketUnknown
	)

	classify := func(ctx context.Context, name string) bucketState {
		resp := c.Get(ctx, base+name+"/"+probeObject, nil)
		if resp.Err != nil {
			return bucketUnknown
		}
		// The probe object itself exists, which proves the bucket does.
		if resp.Status == 200 {
			return bucketExists
		}
		// Only Supabase's own storage errors say anything about a bucket.
		// Everything else — throttling, auth, gateway failures — is unknown.
		if resp.Status != 400 && resp.Status != 404 {
			return bucketUnknown
		}
		var body struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			Code    string `json:"code"`
		}
		if json.Unmarshal(resp.Body, &body) != nil {
			return bucketUnknown
		}
		text := strings.ToLower(body.Error + " " + body.Message + " " + body.Code)
		switch {
		case strings.Contains(text, "bucket not found"), strings.Contains(text, "nosuchbucket"):
			return bucketAbsent
		case strings.Contains(text, "not_found"), strings.Contains(text, "nosuchkey"),
			strings.Contains(text, "object not found"):
			// The bucket resolved and the object did not: affirmative
			// evidence the bucket is there.
			return bucketExists
		}
		return bucketUnknown
	}

	// Control first, same discipline as relation and function discovery: a
	// name that cannot exist must be refused, or every candidate looks real
	// and the wordlist is reported back as 687 buckets.
	res.Requests++
	if classify(ctx, ControlBucketName) == bucketExists {
		res.Findings = append(res.Findings, uncheckedFinding(c, "storage-buckets", base,
			"Public buckets were not assessed. A control probe for a bucket that cannot "+
				"exist was answered as though it does, so every candidate name would look "+
				"real. This happens behind a CDN or a catch-all router."))
		return nil
	}

	states := client.Map(ctx, o.Concurrency, names, func(ctx context.Context, name string) bucketState {
		return classify(ctx, name)
	})
	res.Requests += len(names)

	var out []Bucket
	var unknown int
	for i, st := range states {
		switch st {
		case bucketExists:
			out = append(out, Bucket{Name: names[i], ID: names[i], Public: true})
		case bucketUnknown:
			unknown++
		}
	}
	// A candidate the scan could not classify is not one it ruled out. Say so,
	// or a throttled sweep reports "no public buckets" having established
	// nothing about most of the names it tried.
	if unknown > 0 {
		res.Findings = append(res.Findings, uncheckedFinding(c, "storage-buckets", base,
			fmt.Sprintf("%d of %d bucket names could not be classified: the target answered "+
				"in a way that says nothing about whether the bucket exists — rate limiting, "+
				"an authentication failure or a gateway error. Those names were neither "+
				"confirmed nor ruled out, so the buckets reported are a LOWER BOUND.",
				unknown, len(names))))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// listBucketObjects names what is inside a discovered bucket, which turns
// "this bucket is public" into evidence somebody can act on.
func listBucketObjects(ctx context.Context, c *client.Client, bucket string, limit int) []string {
	url := strings.TrimSuffix(c.BaseURL(), "/") + "/storage/v1/object/list/" + bucket
	body := fmt.Sprintf(`{"prefix":"","limit":%d}`, limit)
	resp := c.Do(ctx, "POST", url, []byte(body),
		map[string]string{"Content-Type": "application/json"})
	if resp.Err != nil || resp.Status != 200 {
		return nil
	}
	var objects []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(resp.Body, &objects) != nil {
		return nil
	}
	out := make([]string, 0, len(objects))
	for _, o := range objects {
		if o.Name != "" {
			out = append(out, o.Name)
		}
	}
	sort.Strings(out)
	return out
}

// probeBucketWrite tests whether an anonymous caller can PUT an object into a
// bucket, and removes what it wrote.
//
// A separate question from whether the bucket is readable, and a larger one.
// Public read is disclosure: an attacker sees files. Public write is control:
// an attacker places files that other people's browsers fetch from a domain
// they trust — a script, a fake invoice, a payload with a legitimate-looking
// URL. An audit found this project scoring a proven upload-and-fetch-back
// exploit against supabase-public-storage-bucket, whose entire description is
// a read claim, and whose remediation (`SET public = false`) closes reads and
// leaves the INSERT policy exactly where it was.
//
// Gated behind -write. It creates an object on somebody's storage, which is a
// write however small, and the consent model does not bend for small ones.
func probeBucketWrite(ctx context.Context, c *client.Client, bucket string, res *Result) (bool, string) {
	content := "unruly write probe — safe to delete"
	var name, url string

	// A unique key per run, and NOT an upsert. Two attempts to reuse one name
	// both failed against the real platform, for different reasons:
	//
	//	POST same key                 400 Duplicate
	//	POST same key, x-upsert:true  403 "new row violates row-level security"
	//
	// The second is the instructive one: an upsert is an UPDATE, and a bucket
	// that grants anon INSERT commonly grants no UPDATE and no DELETE. So the
	// probe cannot remove what it wrote and cannot overwrite it either, and a
	// fixed name means the SECOND scan of a target reports no write exposure —
	// the check disabled by its own residue. Measured: the finding fired on
	// the first run against the lab and vanished on the next.
	//
	// The name is therefore unique, which makes a write scan of an unchanged
	// target differ between runs. That is already true of write scans and
	// already excluded from the determinism eval, because an INSERT probe
	// changes the row counts it then reports. The name reaches the output only
	// when cleanup fails, and then it must: the operator needs to know which
	// file to delete.
	// A request counter is not unique across runs: it is deterministic by
	// design, so both scans generated the same key and the second was refused
	// as a duplicate. The clock is what actually varies.
	name = fmt.Sprintf("unruly_write_probe_%d.txt", time.Now().UnixNano())
	url = strings.TrimSuffix(c.BaseURL(), "/") + "/storage/v1/object/" + bucket + "/" + name
	up := c.Do(ctx, "POST", url, []byte(content),
		map[string]string{"Content-Type": "text/plain"})
	res.Requests++
	if up.Err != nil || up.Status < 200 || up.Status > 299 {
		return false, ""
	}

	// An accepted upload is not a stored object, for the same reason a 201 is
	// not a written row: verify by fetching it back through the public path,
	// which is how a stranger would reach it. The request carries the scan's
	// credentials like every other — see the note above.
	down := strings.TrimSuffix(c.BaseURL(), "/") + "/storage/v1/object/public/" + bucket + "/" + name
	got := c.Get(ctx, down, nil)
	res.Requests++
	stored := got.Err == nil && got.Status == 200 && string(got.Body) == content

	// Clean up whatever landed, and report honestly if it could not be
	// removed: a probe that leaves a file behind has changed the target, and
	// the operator needs to know which file to delete.
	del := c.Do(ctx, "DELETE", url, nil, nil)
	res.Requests++
	residue := ""
	if del.Err != nil || del.Status < 200 || del.Status > 299 {
		residue = name
	}
	return stored, residue
}

// bucketWriteFinding reports a bucket an anonymous caller can write to.
func bucketWriteFinding(c *client.Client, bucket, residue string) finding.Finding {
	extra := ""
	if residue != "" {
		extra = fmt.Sprintf(" The probe object %q could not be deleted afterwards and is "+
			"still in the bucket; remove it manually.", residue)
	}
	return finding.Finding{
		ID:       "supabase-storage-anon-write",
		Name:     "Storage bucket accepts anonymous uploads",
		Severity: finding.Critical,
		Protocol: "storage",
		Matched:  strings.TrimSuffix(c.BaseURL(), "/") + "/storage/v1/object/" + bucket,
		Resource: bucket,
		Description: fmt.Sprintf(
			"An anonymous caller holding only the public key uploaded an object to %q and "+
				"fetched it back through the public URL. This is control rather than "+
				"disclosure: a file placed here is served from your domain, so it is fetched "+
				"by browsers that already trust the origin — a script, a fake document, or a "+
				"payload with an entirely legitimate-looking URL. Making the bucket private "+
				"does NOT fix this; the write is permitted by a policy on storage.objects and "+
				"survives that change.%s", bucket, extra),
		Remediation: fmt.Sprintf(`-- Find the policy that grants the write. Marking the bucket
-- private does not remove it:
SELECT policyname, cmd, roles FROM pg_policies
WHERE schemaname = 'storage' AND tablename = 'objects';

-- Drop the anonymous INSERT policy for this bucket:
-- DROP POLICY "<policy name>" ON storage.objects;

-- If uploads must stay open, bind them to an authenticated owner and a path
-- that user controls, rather than to the bucket alone:
-- CREATE POLICY "%[1]s_owner_upload" ON storage.objects
--   FOR INSERT TO authenticated
--   WITH CHECK (bucket_id = '%[1]s' AND (storage.foldername(name))[1] = (select auth.uid())::text);`, bucket),
		Evidence: finding.Evidence{
			Request: fmt.Sprintf("curl -X POST '%s/storage/v1/object/%s/probe.txt' "+
				"-H 'apikey: $SUPABASE_ANON_KEY' --data 'x'",
				strings.TrimSuffix(c.BaseURL(), "/"), bucket),
			Reason: "object uploaded anonymously and fetched back byte for byte",
		},
	}
}

// RoutineBudgetFinding reports that routine discovery stopped at its probe
// budget rather than at the end of the candidate list.
//
// -max-rpc-probes has existed since early on and truncated in silence. When
// -max-relation-probes was added it got a lower-bound note immediately,
// because adding a cap without one manufactures a false negative on request —
// and nobody went back to the older cap. An audit did.
func RoutineBudgetFinding(restBase string, probed, wanted int) finding.Finding {
	return finding.Finding{
		ID:       "unruly-probe-budget-exhausted",
		Name:     "Routine discovery stopped at the probe budget",
		Severity: finding.Info,
		Protocol: "postgrest",
		Matched:  restBase,
		Resource: "routine-discovery",
		Description: fmt.Sprintf(
			"Routine discovery probed %d of %d candidate names before -max-rpc-probes "+
				"bound the search, so the routines reported are a LOWER BOUND and this scan "+
				"cannot say the rest are absent.", probed, wanted),
		Remediation: fmt.Sprintf("-- Re-run with -max-rpc-probes %d to probe the whole "+
			"candidate list.", wanted),
		Evidence: finding.Evidence{
			Reason: fmt.Sprintf("%d of %d candidates probed", probed, wanted),
		},
	}
}
