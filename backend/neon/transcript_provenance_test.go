package neon

import (
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/transcript"
)

// The committed recording must answer the request this code actually makes.
//
// On 2026-08-22 it stopped. WriteStage's probe changed from
// {"body":"unruly_write_probe"} to {} -- because a scanner cannot know a column
// name and must not invent one -- and five tables answer 400 PGRST204 to the
// first and 403/42501 to the second. The recording kept serving PGRST204, every
// offline eval kept passing, and the stage was being graded against responses
// the live API would never give it again.
//
// Replay keys on method, path and auth class, which is right: a probe should
// not have to send byte-identical JSON to be answered. That is also why the
// mismatch was invisible. This test closes it by comparing the recorded request
// body against the payload the stage is built to send, so a change to one
// without the other fails here rather than in six months against a real target.
func TestTheRecordingAnswersThePayloadWeSend(t *testing.T) {
	tr, err := transcript.Load("../../fixtures/neon/transcript.json")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	var posts int
	for _, e := range tr.Exchanges {
		if e.Method != "POST" || strings.Contains(e.Path, "/rpc/") {
			continue
		}
		posts++
		if e.RequestBody != writeProbePayload {
			t.Errorf("the recording of POST %s [%s] answers the payload %q, and the "+
				"stage sends %q. One of the two moved without the other, so this "+
				"recording is no longer evidence about what the scanner does",
				e.Path, e.Auth, e.RequestBody, writeProbePayload)
		}
	}
	if posts == 0 {
		t.Error("the recording holds no write exchanges at all, so the write tier is " +
			"replayed against nothing and its evals grade an empty set")
	}
}
