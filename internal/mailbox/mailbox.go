// Package mailbox receives the confirmation mail a project sends when signup
// alone does not issue a session.
//
// A project with email confirmation enabled is NOT a closed one. It admits
// anybody willing to receive a message, which on the open internet is anybody
// at all -- and every relation whose policy reads `TO authenticated` is
// reachable by that person. Without a mailbox the scan stops at "signup
// succeeded but no session was issued", which is honest but leaves the whole
// authenticated tier unmeasured on a large share of real projects.
//
// Three properties this package must have, and each is a constraint rather
// than a preference:
//
//   - OPT-IN. It calls a third party, and the scan path is otherwise free of
//     them. The operator asks for it by flag, exactly like -write.
//   - ONE ADDRESS PER PROJECT, derived deterministically, so a second scan
//     reuses the first scan's identity instead of registering another account
//     in somebody's user table.
//   - REMOVABLE. The inbox is residue this tool created, and residue it cannot
//     remove is residue it must report.
package mailbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"time"
)

// Mailbox is one address, its inbound mail, and the ability to remove it.
type Mailbox interface {
	// Address is what to register with.
	Address() string
	// Await blocks until a message arrives carrying a link, or the deadline
	// passes. It returns the FIRST link found, which is what a confirmation
	// mail leads with.
	Await(ctx context.Context, within time.Duration) (string, error)
	// Close removes the mailbox. A provider that cannot remove one must say so
	// rather than silently leaving it.
	Close(ctx context.Context) error
}

// Provider hands out mailboxes.
type Provider interface {
	// Name identifies the service in findings and diagnostics.
	Name() string
	// Open returns the mailbox for a project, creating it if needed. Called
	// twice with the same project it must return the same address, so a repeat
	// scan reuses one identity.
	Open(ctx context.Context, project string) (Mailbox, error)
}

// UserFor derives the local part of the address for a project.
//
// Deterministic on purpose. The alternative -- a random address per scan --
// registers a fresh account every time the scanner runs, which turns a
// measurement into a slow leak of junk users into somebody's auth table. The
// hash keeps the project reference itself out of the address, since that
// address ends up stored in a third party's inbox list.
func UserFor(project string) string {
	sum := sha256.Sum256([]byte("unruly-mailbox/" + project))
	return "unruly-" + hex.EncodeToString(sum[:])[:12]
}

// linkRe finds the confirmation URL in a message body.
//
// Anchored on http(s) and stopping at whitespace or a quote: confirmation mail
// is HTML as often as text, and a link that runs into the surrounding markup
// is a link that 404s when followed.
var linkRe = regexp.MustCompile(`https?://[^\s"'<>)\]]+`)

// FirstLink returns the first URL in body, or "" when there is none.
func FirstLink(body string) string {
	return linkRe.FindString(body)
}
