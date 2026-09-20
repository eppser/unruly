package mailbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/eppser/unruly/internal/client"
)

// AgentMail is api.agentmail.to.
//
// Chosen after exercising every step against the live API rather than reading
// its description: authenticate, create an inbox, receive (the probe message
// arrived on the FIRST poll, under two seconds), read the body, recover the
// link, and DELETE the inbox afterwards.
//
// The delete is why it is here. Two of the alternatives could not remove an
// address once created, which would have left a permanent artefact behind
// every confirm-required scan -- and this tool reports its own leftovers
// rather than hiding them, so there would have been nowhere honest to put it.
type AgentMail struct {
	Key    string
	Client *client.Client
	// Base is the API origin. A field so tests can point it at a stub; a scan
	// never sets it.
	Base string
}

func (a *AgentMail) Name() string { return "agentmail" }

func (a *AgentMail) base() string {
	if a.Base != "" {
		return strings.TrimSuffix(a.Base, "/")
	}
	return "https://api.agentmail.to"
}

func (a *AgentMail) auth() map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + a.Key,
		"Content-Type":  "application/json",
	}
}

// Open creates the project's inbox, or re-opens the one a previous scan made.
//
// The create is NOT idempotent, which is worth stating because the first
// version of this file asserted that it was. Creating a username that already
// exists returns 403 `already_exists`, not 200 -- so a second scan of the same
// project failed outright at the step whose entire purpose is reuse. The claim
// had been inferred from creating a FRESH name once and never testing the
// repeat, and a stub built to match the inference passed happily.
//
// So: fetch first, create only if absent, and treat a create that loses a race
// as a fetch. That last case is not hypothetical -- two scans of one project
// started together would both see "absent" and both POST.
func (a *AgentMail) Open(ctx context.Context, project string) (Mailbox, error) {
	if a.Key == "" {
		return nil, errors.New("no AgentMail API key: set AGENTMAIL_API_KEY")
	}
	addr := UserFor(project) + "@agentmail.to"

	if mb, ok := a.fetch(ctx, addr); ok {
		return mb, nil
	}
	body, _ := json.Marshal(map[string]string{"username": UserFor(project)})
	r := a.Client.Do(ctx, "POST", a.base()+"/v0/inboxes", body, a.auth())
	if r.Err != nil {
		return nil, fmt.Errorf("creating inbox: %w", r.Err)
	}
	if r.Status == 403 || r.Status == 409 {
		// Someone else created it between the fetch and the create.
		if mb, ok := a.fetch(ctx, addr); ok {
			return mb, nil
		}
		return nil, fmt.Errorf("inbox %s exists but could not be fetched", addr)
	}
	if r.Status < 200 || r.Status >= 300 {
		return nil, fmt.Errorf("creating inbox: HTTP %d", r.Status)
	}
	var out struct {
		Email   string `json:"email"`
		InboxID string `json:"inbox_id"`
	}
	if json.Unmarshal(r.Body, &out) != nil || out.Email == "" {
		return nil, errors.New("creating inbox: no address in the response")
	}
	return &agentMailbox{api: a, addr: out.Email, id: out.InboxID}, nil
}

// fetch returns the mailbox for addr when it already exists.
func (a *AgentMail) fetch(ctx context.Context, addr string) (Mailbox, bool) {
	r := a.Client.Do(ctx, "GET", a.base()+"/v0/inboxes/"+url.PathEscape(addr), nil, a.auth())
	if r.Err != nil || r.Status != 200 {
		return nil, false
	}
	var out struct {
		Email   string `json:"email"`
		InboxID string `json:"inbox_id"`
	}
	if json.Unmarshal(r.Body, &out) != nil || out.Email == "" {
		return nil, false
	}
	return &agentMailbox{api: a, addr: out.Email, id: out.InboxID}, true
}

type agentMailbox struct {
	api  *AgentMail
	addr string
	id   string
}

func (m *agentMailbox) Address() string { return m.addr }

// pollEvery is how often Await asks. Measured against the live service, a sent
// message was already listed on the first poll, so this is not a throughput
// question -- it is how quickly the scan notices, balanced against how many
// requests it makes at somebody else's API while waiting.
const pollEvery = 2 * time.Second

func (m *agentMailbox) Await(ctx context.Context, within time.Duration) (string, error) {
	deadline := time.Now().Add(within)
	for {
		link, err := m.latestLink(ctx)
		if err == nil && link != "" {
			return link, nil
		}
		if time.Now().After(deadline) {
			// The timeout is reported as itself, never as "no mail was sent".
			// A project whose mail is slow, filtered or misrouted is not a
			// project that declined to send.
			return "", fmt.Errorf("no message with a link arrived at %s within %s",
				m.addr, within)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollEvery):
		}
	}
}

func (m *agentMailbox) latestLink(ctx context.Context) (string, error) {
	u := m.api.base() + "/v0/inboxes/" + url.PathEscape(m.id) + "/messages"
	r := m.api.Client.Do(ctx, "GET", u, nil, m.api.auth())
	if r.Err != nil || r.Status != 200 {
		return "", errors.New("listing messages")
	}
	var list struct {
		Messages []struct {
			MessageID string `json:"message_id"`
		} `json:"messages"`
	}
	if json.Unmarshal(r.Body, &list) != nil || len(list.Messages) == 0 {
		return "", errors.New("no messages")
	}
	// The message id carries angle brackets and an @, so it has to be escaped
	// into the path. Unescaped it produces a 404 that reads like an empty
	// inbox, which would have this function report "no mail" for a message
	// that had already arrived.
	mid := url.PathEscape(list.Messages[0].MessageID)
	r = m.api.Client.Do(ctx, "GET",
		m.api.base()+"/v0/inboxes/"+url.PathEscape(m.id)+"/messages/"+mid, nil, m.api.auth())
	if r.Err != nil || r.Status != 200 {
		return "", errors.New("reading message")
	}
	var msg struct {
		Text string `json:"text"`
		HTML string `json:"html"`
	}
	if json.Unmarshal(r.Body, &msg) != nil {
		return "", errors.New("decoding message")
	}
	if l := FirstLink(msg.Text); l != "" {
		return l, nil
	}
	return FirstLink(msg.HTML), nil
}

func (m *agentMailbox) Close(ctx context.Context) error {
	r := m.api.Client.Do(ctx, "DELETE",
		m.api.base()+"/v0/inboxes/"+url.PathEscape(m.id), nil, m.api.auth())
	if r.Err != nil {
		return fmt.Errorf("deleting inbox %s: %w", m.addr, r.Err)
	}
	// 202 is what the service returns for an accepted deletion.
	if r.Status < 200 || r.Status >= 300 {
		return fmt.Errorf("deleting inbox %s: HTTP %d", m.addr, r.Status)
	}
	return nil
}
