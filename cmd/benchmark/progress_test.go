package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// A twenty-minute run that says nothing until the end cannot be diagnosed.
//
// Two full runs were lost to projects reported as "did not answer within
// 5m0s" that answered in ten seconds when started by hand, and there was no
// way to tell which of bring-up, scan or teardown had consumed the time,
// because the runner printed one report and nothing else. The note goes to
// stderr so the report on stdout stays byte-identical.
func TestProgressNamesThePhaseAndItsCost(t *testing.T) {
	var buf bytes.Buffer
	progressTo(&buf, "16-data-classification", "bring-up", 302*time.Second, nil)
	got := buf.String()
	for _, want := range []string{"16-data-classification", "bring-up", "5m2s"} {
		if !strings.Contains(got, want) {
			t.Errorf("progress line %q is missing %q; it exists to say which "+
				"project and which phase, and neither is guessable later", got, want)
		}
	}
	if !strings.HasSuffix(got, "\n") {
		t.Error("progress lines must terminate, or a tail of the log shows one long line")
	}
}
