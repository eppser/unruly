// Package application is a deliberately broken web application, used as the
// ground truth for the application-layer findings.
//
// It exists because docs/exploitability.md asks for an ANSWER KEY rather than a
// test, and the difference is not pedantry: a test written by the same person
// as the check can agree with it for the same wrong reason, which happened six
// times while these checks were being built.
//
// So the behaviour is DECLARED HERE, in one place, and transcribed by hand into
// answer-key.yaml. internal/exploit then demonstrates each entry against a
// running copy, importing nothing from internal/routes. Two implementations
// that never share a line, agreeing on what this application does.
//
// Unlike the other labs this one needs no external product and no network: it
// is a Go server, so the demonstrations run offline and deterministically, on
// anyone's machine, every time.
package application

import (
	"encoding/json"
	"net/http"
	"strings"
)

// The four behaviours, stated once. answer-key.yaml transcribes these.
const (
	// TokenA and TokenB are two different accounts. Neither is an admin.
	TokenA = "fixture-token-a"
	TokenB = "fixture-token-b"

	// RecordA is what /invoices/42 returns to ANY signed-in caller. It belongs
	// to account A, which is the bug: the endpoint checks for a session and
	// not for ownership.
	RecordA = `{"id":42,"customer":"acme","contact_email":"ap@acme.invalid"}`

	// PublicRecord is what /system/mode returns to ANYONE, including callers
	// with no credential at all. It carries an address, which is what raises
	// it above a status page.
	PublicRecord = `{"success":true,"data":{"mode":"maintenance",` +
		`"updated_by_email":"ops.lead@example.invalid","updated_at":"2025-03-04T09:14:00Z"}}`

	// BypassPath is refused to a plain request and served when a rewrite
	// header names it -- a proxy authorising the path it received and
	// forwarding the one the header names.
	BypassPath = "/admin/users"
	// BypassRecord is what that bypass yields.
	BypassRecord = `{"users":[{"role":"admin","contact_email":"root@example.invalid"}]}`
)

// Spec is the specification the API publishes to anyone.
//
// It names endpoints the front end never calls, which is the whole reason a
// specification is worth reading.
var Spec = map[string]any{
	"openapi": "3.0.0",
	"info":    map[string]any{"title": "fixture", "version": "1"},
	"paths": map[string]any{
		"/system/mode":   getOp("read system mode"),
		"/invoices/{id}": getOp("read one invoice"),
		"/admin/users":   getOp("list users"),
		"/crm/customers": getOp("list customers"),
		"/internal/logs": getOp("read internal logs"),
	},
}

func getOp(summary string) map[string]any {
	return map[string]any{"get": map[string]any{"summary": summary,
		"responses": map[string]any{"200": map[string]any{"description": "ok"}}}}
}

// API returns the backend handler.
//
// Every branch is one line in answer-key.yaml. Nothing here is incidental: the
// refusals are as much of the ground truth as the exposures, because a scanner
// that reports them is worse than one that misses the leak.
func API() http.Handler {
	spec, _ := json.Marshal(Spec)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")

		// The rewrite bypass, checked before routing: that is exactly the
		// mistake, a proxy honouring the header without re-applying the check.
		if r.Header.Get("X-Original-URL") == BypassPath {
			w.Write([]byte(BypassRecord))
			return
		}

		switch r.URL.Path {
		case "/":
			w.Write([]byte(`{"service":"fixture-api"}`))
		case "/openapi.json":
			w.Write(spec)
		case "/docs":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<title>docs</title><div id="swagger-ui"></div>`))
		case "/system/mode":
			// Open to everyone, and holding an address.
			w.Write([]byte(PublicRecord))
		case "/invoices/42":
			// Signed in is enough: the ownership check is missing.
			if auth != TokenA && auth != TokenB {
				refuse(w)
				return
			}
			w.Write([]byte(RecordA))
		case "/profile":
			// CORRECT: the row is selected for the caller. The control that
			// stops the cross-identity check reporting every good endpoint.
			if auth != TokenA && auth != TokenB {
				refuse(w)
				return
			}
			w.Write([]byte(`{"me":"` + auth + `"}`))
		case BypassPath, "/crm/customers", "/internal/logs":
			// Correctly protected against every plain request.
			refuse(w)
		default:
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"detail":"Not Found"}`))
		}
	})
}

func refuse(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"detail":"Not authenticated"}`))
}

// App returns the front end, which names the API by absolute URL.
func App(apiURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<!doctype html><script src="/assets/index-b71c.js"></script>`))
		case "/assets/index-b71c.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`const API_BASE="` + apiURL + `";` +
				`export const mode=()=>fetch(API_BASE+"/system/mode");` +
				`export const invoice=(id)=>fetch(API_BASE+"/invoices/{id}");` +
				`export const me=()=>fetch(API_BASE+"/profile");`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}
