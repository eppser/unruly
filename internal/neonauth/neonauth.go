// Package neonauth obtains a Neon Data API JWT from Neon Auth.
//
// Neon's Data API validates JWTs against keys held in neon_auth.jwks, so a
// token has to come from the Neon Auth service; there is no way to mint one.
// Getting it right took three corrections, each of which fails quietly rather
// than loudly, and each of which is pinned by a test here:
//
//   - sign-up needs an Origin header. Without it the service answers
//     MISSING_ORIGIN and creates nothing.
//   - the session arrives as a COOKIE. Presenting it as a bearer to /token
//     answers 401.
//   - a duplicate sign-up is not a failure; it means sign in instead.
//
// The scan path never calls this. Authentication is for establishing ground
// truth against an owned lab and for recording transcripts -- a posture scan
// of somebody else's project observes what a stranger sees.
package neonauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// Client talks to one Neon Auth base URL.
type Client struct {
	Base   string // e.g. https://<ep>.neonauth.<region>.aws.neon.tech/<db>/auth
	Origin string // required by sign-up; the project's Allow Localhost permits localhost
	HTTP   *http.Client
}

// New returns a Client with a cookie jar, which the session depends on.
func New(base, origin string) *Client {
	jar, _ := cookiejar.New(nil)
	return &Client{
		Base:   base,
		Origin: origin,
		HTTP:   &http.Client{Jar: jar, Timeout: 30 * time.Second},
	}
}

// Token signs the account up if needed, signs it in, and exchanges the
// resulting session for a JWT.
func (c *Client) Token(ctx context.Context, email, password string) (string, error) {
	creds := map[string]string{"email": email, "password": password, "name": "unruly probe"}

	// A duplicate account is the expected steady state on a lab that has been
	// recorded before, so the status is not checked here -- sign-in decides.
	if _, _, err := c.post(ctx, "/sign-up/email", creds); err != nil {
		return "", fmt.Errorf("sign-up: %w", err)
	}

	status, body, err := c.post(ctx, "/sign-in/email", map[string]string{
		"email": email, "password": password,
	})
	if err != nil {
		return "", fmt.Errorf("sign-in: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("sign-in: %d: %s", status, trim(body))
	}

	status, body, err = c.get(ctx, "/token")
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("token exchange: %d: %s", status, trim(body))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("token exchange: decode: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("token exchange: 200 with no token in %s", trim(body))
	}
	return out.Token, nil
}

func (c *Client) post(ctx context.Context, path string, payload any) (int, []byte, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", c.Origin)
	return c.do(req)
}

func (c *Client) get(ctx context.Context, path string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Origin", c.Origin)
	return c.do(req)
}

func (c *Client) do(req *http.Request) (int, []byte, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, b, nil
}

func trim(b []byte) string {
	const max = 200
	if len(b) > max {
		return string(b[:max]) + "..."
	}
	return string(b)
}
