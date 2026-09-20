package eval

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/eppser/unruly/internal/client"
)

// ReachabilityProbe is the relation name used to test that a fixture answers.
// Nothing may define it, so a 404 is the expected success case.
const ReachabilityProbe = "unruly_fixture_reachability_probe"

// Reachable reports whether a fixture is actually serving, distinguishing a
// target that answered from one that could not be dialled.
//
// The evals grade recall and precision against fixtures in Docker. When the
// daemon dies mid-run -- which on this machine it has done eleven times --
// every request fails at the transport, every relation classifies as unknown,
// and the graders report what looks like a substantive regression:
//
//	probed 9 relations in 3ms (18 requests)
//	relation-discovery FAIL recall 0.0%
//	read-exposure-classifier is UNSOUND
//
// Each of those took real time to diagnose, and each said nothing about the
// scanner. It is the exact confusion this project exists to prevent -- a
// measurement that could not be taken presenting as a measurement that came
// back bad -- reproduced inside the harness that is supposed to enforce it.
//
// The distinction is the transport, not the status. A 404 or a 401 proves the
// fixture is up and talking; a dial error proves nothing about anything. The
// relation therefore need not exist -- only the dial matters.
func Reachable(ctx context.Context, c *client.Client, relation string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp := c.Get(ctx, c.RestURL(relation)+"?limit=1", nil)
	if resp.Err == nil {
		return nil
	}
	// Two dial failures that look identical in a test log and have opposite
	// causes, so they must not share one message.
	//
	// EADDRNOTAVAIL is the HOST running out of ephemeral ports, not the fixture
	// being down. A full eval run opens tens of thousands of connections to one
	// port, each held in TIME_WAIT afterwards; back-to-back runs accumulate
	// them until the range is gone. Measured while chasing this: 11,410
	// TIME_WAIT sockets to the lab's port alone, against a 16,384-port range.
	//
	// The old message said "bring the fixtures up" and "colima start", which is
	// exactly wrong here -- the fixtures ARE up. Three audit runs were spent
	// restarting Docker, removing containers and re-running before the errno
	// was read. A diagnostic that names the wrong cause costs more than no
	// diagnostic, because it is followed.
	if isAddrNotAvailable(resp.Err) {
		return fmt.Errorf("cannot open a connection to %s: the HOST is out of ephemeral "+
			"ports (%v).\n"+
			"The fixture is almost certainly fine. Sockets sit in TIME_WAIT for a minute "+
			"or so after each run, and a full eval opens tens of thousands of them, so "+
			"back-to-back runs exhaust the range.\n"+
			"Check with: netstat -an | grep -c TIME_WAIT\n"+
			"Wait a minute and re-run, or lower -concurrency. Restarting Docker will not "+
			"help and has been tried.",
			c.BaseURL(), resp.Err)
	}
	return fmt.Errorf("fixture at %s is not reachable (%v).\n"+
		"This is a broken test environment, NOT a scanner regression: no request "+
		"reached the target, so any recall or precision number from this run would "+
		"describe the harness rather than the tool.\n"+
		"Bring the fixtures up with `make fixtures-up`. If Docker itself is down, "+
		"`colima start -p lab` first.",
		c.BaseURL(), resp.Err)
}

// isAddrNotAvailable reports whether the dial failed because no local port was
// free. Matched on the errno rather than the message text, which differs by
// platform and by Go version.
func isAddrNotAvailable(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EADDRINUSE)
}
