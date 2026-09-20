package neonauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Sign-up must carry an Origin header.
//
// Measured on the lab: without one, Neon Auth answers 400 MISSING_ORIGIN
// ("Origin header is required when callbackURL is not an absolute URL") and no
// account is created. Nothing in the request looks wrong, so a regression here
// would present as "the lab has no users" rather than as a client defect.
func TestSignUpSendsAnOrigin(t *testing.T) {
	var sawOrigin string
	srv := authServer(t, func(path string, r *http.Request) (int, string) {
		if path == "/sign-up/email" {
			sawOrigin = r.Header.Get("Origin")
		}
		return 200, `{"token":"sess","user":{"id":"u1"}}`
	})
	defer srv.Close()

	if _, err := New(srv.URL, "http://localhost:3000").Token(
		context.Background(), "a@example.com", "pw"); err != nil {
		t.Fatalf("token: %v", err)
	}
	if sawOrigin == "" {
		t.Error("sign-up went out with no Origin header; Neon Auth rejects that " +
			"with MISSING_ORIGIN and creates no account")
	}
}

// The token exchange must present the session COOKIE, not a bearer.
//
// Measured: GET /token with Authorization: Bearer <session> answers 401. The
// session is a cookie. Sending it the obvious way silently yields no JWT.
func TestTokenExchangeUsesTheCookieNotABearer(t *testing.T) {
	var tokenReq *http.Request
	srv := authServer(t, func(path string, r *http.Request) (int, string) {
		switch path {
		case "/sign-in/email":
			return 200, `{"token":"sess","user":{"id":"u1"}}`
		case "/token":
			tokenReq = r.Clone(r.Context())
			if c, err := r.Cookie("better-auth.session_token"); err != nil || c.Value == "" {
				return 401, `{"message":"Unauthorized","code":"UNAUTHORIZED"}`
			}
			return 200, `{"token":"the.jwt.value"}`
		}
		return 200, `{"token":"sess","user":{"id":"u1"}}`
	})
	defer srv.Close()

	got, err := New(srv.URL, "http://localhost:3000").Token(
		context.Background(), "a@example.com", "pw")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "the.jwt.value" {
		t.Errorf("got token %q, want the value the service returned", got)
	}
	if tokenReq == nil {
		t.Fatal("/token was never called")
	}
	if tokenReq.Header.Get("Authorization") != "" {
		t.Error("the token exchange sent an Authorization header; Neon Auth " +
			"answers 401 to that and the JWT never arrives")
	}
}

// An existing account must not be a failure.
//
// Re-running a recorder against a lab that already has the probe account is
// routine. Better Auth answers the duplicate sign-up with an error; the client
// signs in instead.
func TestAnExistingAccountStillYieldsAToken(t *testing.T) {
	srv := authServer(t, func(path string, r *http.Request) (int, string) {
		switch path {
		case "/sign-up/email":
			return 422, `{"code":"USER_ALREADY_EXISTS","message":"User already exists"}`
		case "/sign-in/email":
			return 200, `{"token":"sess","user":{"id":"u1"}}`
		case "/token":
			return 200, `{"token":"the.jwt.value"}`
		}
		return 404, ``
	})
	defer srv.Close()

	got, err := New(srv.URL, "http://localhost:3000").Token(
		context.Background(), "a@example.com", "pw")
	if err != nil {
		t.Fatalf("an already-registered probe account must still get a token: %v", err)
	}
	if got == "" {
		t.Error("no token returned")
	}
}

// A refusal must surface, not come back as an empty string.
func TestARefusedExchangeIsAnError(t *testing.T) {
	srv := authServer(t, func(path string, r *http.Request) (int, string) {
		if path == "/token" {
			return 401, `{"message":"Unauthorized","code":"UNAUTHORIZED"}`
		}
		return 200, `{"token":"sess","user":{"id":"u1"}}`
	})
	defer srv.Close()

	got, err := New(srv.URL, "http://localhost:3000").Token(
		context.Background(), "a@example.com", "pw")
	if err == nil {
		t.Fatalf("a 401 from the token exchange returned %q and no error; a caller "+
			"would then scan as anonymous while believing it was authenticated", got)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error %q does not mention the status that caused it", err)
	}
}

// authServer routes every Better Auth path through one handler and keeps a
// session cookie flowing the way the real service does.
func authServer(t *testing.T, h func(path string, r *http.Request) (int, string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, body := h(r.URL.Path, r)
		if strings.HasSuffix(r.URL.Path, "/sign-in/email") && status == 200 {
			http.SetCookie(w, &http.Cookie{Name: "better-auth.session_token", Value: "sess", Path: "/"})
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}
