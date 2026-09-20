package surface

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/finding"
)

// Bucket existence was decided as NOT(body says "bucket not found"), which
// makes every unreadable answer a positive. An audit demonstrated it: a server
// that answers the control probe honestly and then starts throttling reported
// four fabricated public buckets, and under -write each would have received an
// unsolicited upload attempt.
//
// This is the "2684 relations discovered from a bad key" bug reintroduced one
// surface over, so these tests are written the way that one's were: the
// question is never "did it find something" but "can it tell absent from
// unmeasured".

func storageServer(t *testing.T, h http.HandlerFunc) *client.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return client.New(client.Options{
		ProjectRef: "x", BaseURL: srv.URL, RestPrefix: "/", AnonKey: "k", Retries: 1,
	})
}

func bucketNotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`{"statusCode":"404","error":"Bucket not found","message":"Bucket not found"}`))
}

// The case that motivated all of this.
func TestBucketProbeDoesNotInventBucketsWhenThrottled(t *testing.T) {
	var n int64
	c := storageServer(t, func(w http.ResponseWriter, r *http.Request) {
		// The control probe is answered honestly; everything after it is
		// throttled, exactly as a real target would behave under load.
		if atomic.AddInt64(&n, 1) == 1 {
			bucketNotFound(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"message":"rate limit exceeded"}`))
	})
	res := Result{}
	got := probeBuckets(context.Background(), c,
		Options{BucketSeeds: []string{"avatars", "backups", "invoices", "logos"}}, &res)

	if len(got) != 0 {
		t.Errorf("a throttled probe says nothing about a bucket; invented %d: %v", len(got), got)
	}
	var said bool
	for _, f := range res.Findings {
		if strings.Contains(f.Description, "LOWER BOUND") {
			said = true
		}
	}
	if !said {
		t.Error("names that could not be classified must be reported, or a throttled " +
			"sweep reads as a project with no public buckets")
	}
}

// A wrong key answers 401 with a JSON body containing no bucket wording. Same
// class, different cause.
func TestBucketProbeDoesNotInventBucketsOnAuthFailure(t *testing.T) {
	var n int64
	c := storageServer(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&n, 1) == 1 {
			bucketNotFound(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Invalid API key"}`))
	})
	res := Result{}
	if got := probeBuckets(context.Background(), c,
		Options{BucketSeeds: []string{"avatars", "uploads"}}, &res); len(got) != 0 {
		t.Errorf("an auth failure says nothing about a bucket; invented %v", got)
	}
}

// The positive path still has to work: an existing bucket answers "object not
// found" for a key that is not there.
func TestBucketProbeFindsARealBucket(t *testing.T) {
	c := storageServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		if strings.Contains(r.URL.Path, "public-uploads") {
			_, _ = w.Write([]byte(`{"statusCode":"404","error":"not_found","message":"Object not found","code":"NoSuchKey"}`))
			return
		}
		_, _ = w.Write([]byte(`{"statusCode":"404","error":"Bucket not found","message":"Bucket not found"}`))
	})
	res := Result{}
	got := probeBuckets(context.Background(), c,
		Options{BucketSeeds: []string{"public-uploads", "nope"}}, &res)
	if len(got) != 1 || got[0].Name != "public-uploads" {
		t.Fatalf("want just public-uploads, got %v", got)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Description, "LOWER BOUND") {
			t.Error("everything was classified; nothing should be reported as unmeasured")
		}
	}
}

// A host that claims every bucket exists must be refused outright, not
// reported as 700 public buckets.
func TestBucketProbeRefusesACatchAllHost(t *testing.T) {
	c := storageServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	res := Result{}
	if got := probeBuckets(context.Background(), c,
		Options{BucketSeeds: []string{"avatars", "uploads"}}, &res); len(got) != 0 {
		t.Errorf("a host answering every name must yield no buckets, got %v", got)
	}
	if len(res.Findings) == 0 {
		t.Error("the refusal must be reported rather than read as no buckets")
	}
}

// A probe object the scan could not delete must be reported even when the
// bucket was NOT proven writable. The residue name used to be discarded on
// that path, leaving a file in somebody's storage with nothing in the report.
func TestResidueFindingNamesTheObject(t *testing.T) {
	c := storageServer(t, func(w http.ResponseWriter, r *http.Request) {})
	f := residueFinding(c, "public-uploads", "unruly_write_probe_123.txt")
	if f.ID != "unruly-probe-object-left-behind" {
		t.Errorf("ID changed to %q; consumers filter on it", f.ID)
	}
	if !strings.Contains(f.Description, "unruly_write_probe_123.txt") {
		t.Error("the operator needs the filename to delete it")
	}
	if !strings.Contains(f.Remediation, "DELETE") {
		t.Error("the remediation must say how to remove it")
	}
	// Severity matches the relation counterpart: this describes a change the
	// scan MADE, not a surface it could not see.
	if f.Severity != finding.High {
		t.Errorf("leaving a file behind is not informational, got %s", f.Severity)
	}
}

// A probe object that could not be removed must produce the canonical id
// whatever else was concluded about the bucket.
//
// This fired only in an `else if`, so it appeared when the bucket was NOT
// proven writable -- the opposite of the common case. A bucket that grants
// INSERT and refuses DELETE is writable AND keeps the object, and there the
// operator was told only in the prose of the write finding while
// unruly-probe-object-left-behind never appeared. Anyone filtering on
// that id to answer "did this scan leave anything behind" got nothing.
//
// Found by building such a bucket on the lab: upload 200, delete 403. The
// lab's ORIGINAL bucket turned out to have the same shape, so the scanner had
// been leaving objects there for the life of the project without once emitting
// the id for it.
func TestObjectResidueIsReportedEvenWhenTheBucketIsWritable(t *testing.T) {
	var uploaded, deleted bool
	var stored []byte
	// The whole handler under one lock: `stored` is written by the upload
	// branch and read back by the public-read branch, so the fixture is shared
	// state even though each branch touches it once.
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/object/"):
			uploaded = true
			stored, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"Key":"x"}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/object/public/"):
			// Byte for byte, or the probe will not call the bucket writable --
			// which is the whole precondition of this test.
			w.WriteHeader(http.StatusOK)
			w.Write(stored)
		case r.Method == http.MethodDelete:
			// INSERT granted, DELETE refused: the shape that keeps the object.
			deleted = true
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"statusCode":"403","error":"Unauthorized"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"Object not found"}`))
		}
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	var res Result
	writable, residue := probeBucketWrite(context.Background(), c, "user-uploads", &res)

	if !uploaded || !deleted {
		t.Fatalf("the probe must upload and then attempt a delete; uploaded=%v deleted=%v",
			uploaded, deleted)
	}
	if !writable {
		t.Fatal("the upload was accepted and read back, so the bucket is writable")
	}
	if residue == "" {
		t.Fatal("the delete was refused, so an object is sitting in the bucket and its " +
			"name must be reported")
	}
}

// And the finding must reach the REPORT, not merely be computed.
//
// The test above asserts probeBucketWrite returns a residue name, which it did
// all along; the defect was in Run, which emitted the canonical id only in an
// else-branch. A mutation restoring that branch survived the test above --
// the emit-site-versus-reachability distinction, again.
func TestRunEmitsObjectResidueForAWritableBucket(t *testing.T) {
	var stored []byte
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.Contains(r.URL.Path, "/storage/v1/object/public/user-uploads/"):
			if stored == nil {
				// Before the probe uploads, the bucket must look present:
				// "Object not found" rather than "Bucket not found".
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"Object not found"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write(stored)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/storage/v1/object/user-uploads/"):
			stored, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"Key":"user-uploads/x"}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"statusCode":"403","error":"Unauthorized"}`))
		case strings.Contains(r.URL.Path, "/storage/v1/object/list/"):
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"Bucket not found"}`))
		}
	}))
	defer srv.Close()

	c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
	res := Run(context.Background(), c, Options{
		BucketSeeds: []string{"user-uploads"}, AllowWrite: true, Concurrency: 2,
	})

	var residue, write bool
	for _, f := range res.Findings {
		switch f.ID {
		case "unruly-probe-object-left-behind":
			residue = true
			if f.Severity != finding.High {
				t.Errorf("residue severity %v: the scan changed the target and cannot undo it",
					f.Severity)
			}
		case "supabase-storage-anon-write":
			write = true
		}
	}
	if !write {
		t.Error("the bucket accepted an anonymous upload and served it back; that is the " +
			"write finding and its absence means this test proved nothing")
	}
	if !residue {
		t.Error("the delete was refused, so an object is sitting in somebody's bucket. " +
			"Reporting it only inside the write finding's prose leaves anyone filtering " +
			"on unruly-probe-object-left-behind with nothing")
	}
}
