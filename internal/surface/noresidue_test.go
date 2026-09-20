package surface

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/internal/testrec"
)

// -no-residue must stop the bucket upload, and nothing offline was checking.
//
// The promise is exact: -no-residue writes NOTHING to the project. The gate is
// `if o.AllowWrite && !o.NoResidue`, and dropping the second term survived all
// 45 tests in this package.
//
// It is not unguarded end to end -- eval-noresidue counts objects per bucket
// with the service key before and after a real scan, and would catch it. But
// that eval needs the live lab and credentials, so a contributor without them
// gets no signal at all, and `make audit --offline` skips it with a reason.
// A promise this specific should fail in half a second, not only after a
// cloud project has been provisioned.
func TestNoResidueStopsTheBucketUpload(t *testing.T) {
	for _, tc := range []struct {
		name       string
		noResidue  bool
		wantUpload bool
	}{
		{name: "-write alone uploads a probe object", noResidue: false, wantUpload: true},
		{name: "-no-residue writes nothing at all", noResidue: true, wantUpload: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent testrec.Log
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sent.Add(r.Method + " " + r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.Contains(r.URL.Path, "/storage/v1/bucket"):
					_, _ = w.Write([]byte(`[{"id":"public-files","name":"public-files","public":true}]`))
				case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/object/"):
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"Key":"public-files/x"}`))
				default:
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`[]`))
				}
			}))
			defer srv.Close()

			c := client.New(client.Options{BaseURL: srv.URL, AnonKey: "k", RestPrefix: "/"})
			Run(context.Background(), c, Options{AllowWrite: true, NoResidue: tc.noResidue})

			// An upload, not a listing. `POST /storage/v1/object/list/<bucket>`
			// is how the API enumerates a bucket's contents -- a read that
			// happens to use POST -- and matching "POST" plus "/object/" flags
			// it as a write. The first version of this test did exactly that
			// and reported -no-residue uploading when it had not.
			uploaded := false
			for _, req := range sent.Entries() {
				if strings.HasPrefix(req, "POST ") &&
					strings.Contains(req, "/object/") &&
					!strings.Contains(req, "/object/list/") {
					uploaded = true
				}
			}
			if uploaded != tc.wantUpload {
				if tc.wantUpload {
					t.Errorf("no upload was attempted, so this case proves nothing about "+
						"the gate: %v", sent.Entries())
				} else {
					t.Errorf("-no-residue was set and the scan uploaded anyway: %v.\n"+
						"The flag's whole promise is that it writes NOTHING to the "+
						"project, and a bucket granting INSERT while refusing DELETE "+
						"keeps what it is given.", sent.Entries())
				}
			}
		})
	}
}
