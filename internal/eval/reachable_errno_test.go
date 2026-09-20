package eval

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

// The two dial failures must not share a message.
//
// They look identical in a test log and have opposite causes: one means the
// fixture is down, the other means the HOST is out of ephemeral ports and the
// fixture is fine. Three audit runs were spent restarting Docker on the
// strength of the wrong one, so the distinction is checked rather than
// remembered.
func TestPortExhaustionIsNotMistakenForADeadFixture(t *testing.T) {
	exhausted := &net.OpError{
		Op: "dial", Net: "tcp",
		Err: os.NewSyscallError("connect", syscall.EADDRNOTAVAIL),
	}
	if !isAddrNotAvailable(exhausted) {
		t.Error("EADDRNOTAVAIL is not recognised, so a host with no free ports reads " +
			"as a fixture that is down")
	}
	// Connection refused is the genuine case: something is not listening.
	refused := &net.OpError{
		Op: "dial", Net: "tcp",
		Err: os.NewSyscallError("connect", syscall.ECONNREFUSED),
	}
	if isAddrNotAvailable(refused) {
		t.Error("connection refused was read as port exhaustion; that would tell an " +
			"operator to wait when they need to start the fixture")
	}
	if isAddrNotAvailable(errors.New("some other failure")) {
		t.Error("an unrelated error was classified as port exhaustion")
	}
	// Matched on the errno, not on text: the wording differs by platform and
	// by Go version, and a substring match would rot silently.
	if strings.Contains(exhausted.Error(), "EADDRNOTAVAIL") {
		t.Skip("this platform spells the errno in the message; the errno match still holds")
	}
}
