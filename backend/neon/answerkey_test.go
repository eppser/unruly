package neon

import (
	"context"
	"os"
	"testing"

	"github.com/eppser/unruly/internal/transcript"
	"github.com/eppser/unruly/scan"
	"gopkg.in/yaml.v3"
)

// The committed answer key is what grades this backend.
//
// Until now the expectations lived in Go beside the assertions, and the YAML
// beside the fixture was documentation nobody executed. That is the weaker
// arrangement: the file describing the lab and the file grading the scan could
// disagree indefinitely and both look maintained.
//
// Reading it back carries its own risk -- a parser that quietly returns
// nothing turns this into a test of nothing -- so the shape is asserted before
// any of it is used. That guard is the price of making the key load-bearing.
type neonKey struct {
	Exploitable []struct {
		Table      string `yaml:"table"`
		Capability string `yaml:"capability"`
		Measured   struct {
			Status int `yaml:"status"`
			Rows   int `yaml:"rows_returned"`
		} `yaml:"measured"`
	} `yaml:"exploitable"`
	Protected []struct {
		Table string `yaml:"table"`
		Why   string `yaml:"why"`
	} `yaml:"protected"`
}

func TestTheAnswerKeyGradesTheScan(t *testing.T) {
	b, err := os.ReadFile("../../fixtures/neon/answer-key.yaml")
	if err != nil {
		t.Fatalf("reading the answer key: %v", err)
	}
	var key neonKey
	if err := yaml.Unmarshal(b, &key); err != nil {
		t.Fatalf("parsing the answer key: %v", err)
	}

	// Anti-vacuous guard. A key that parsed to nothing would make every
	// assertion below pass without looking at anything.
	if len(key.Exploitable) != 3 || len(key.Protected) != 3 {
		t.Fatalf("the answer key parsed to %d exploitable and %d protected entries, "+
			"want 3 and 3. Either the fixture changed or the parser stopped "+
			"matching, and in both cases the grading below is meaningless",
			len(key.Exploitable), len(key.Protected))
	}

	tr, err := transcript.Load("../../fixtures/neon/transcript.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := tr.Server(func(msg string) {
		t.Errorf("the stage made a request the lab recording does not cover: %s", msg)
	})
	defer srv.Close()

	var names []string
	for _, e := range key.Exploitable {
		names = append(names, e.Table)
	}
	for _, p := range key.Protected {
		names = append(names, p.Table)
	}

	var st scan.State
	stage := EscalationStage{
		Base: srv.URL, Tables: names, Token: secretToken, Client: testClient(srv.URL),
	}
	if err := stage.Run(context.Background(), &st); err != nil {
		t.Fatalf("stage: %v", err)
	}
	got := map[string]bool{}
	for _, f := range st.Findings() {
		got[f.Resource] = true
	}

	for _, e := range key.Exploitable {
		// Only entries the key says were MEASURED to return rows are graded as
		// recall. anon_readable is exploitable at the database level and was
		// never measured over HTTP -- the key says so, and crediting it here
		// would be grading a claim nobody established.
		if e.Measured.Rows == 0 {
			t.Logf("%s: not graded -- the key records no measured rows (%s)",
				e.Table, e.Capability)
			continue
		}
		if !got[e.Table] {
			t.Errorf("%s is in the answer key with %d measured row(s) and the scan did "+
				"not report it", e.Table, e.Measured.Rows)
		}
	}
	for _, p := range key.Protected {
		if got[p.Table] {
			t.Errorf("%s is recorded as protected (%s) and the scan reported it",
				p.Table, p.Why)
		}
	}
}
