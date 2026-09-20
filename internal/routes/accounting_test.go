package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eppser/unruly/internal/client"
)

func TestProbedRoutesExcludeWorkTheCircuitBreakerDidNotSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	web := client.NewApplication(client.AppOptions{Site: srv.URL, Retries: 0})
	for i := 0; i < 40 && !web.GaveUp(); i++ {
		web.Do(context.Background(), http.MethodGet, srv.URL+"/refusal", nil, nil)
	}
	if !web.GaveUp() {
		t.Fatal("fixture never opened the circuit breaker")
	}

	result := Result{}
	run := runner{web: web, res: &result}
	route := Route{Base: srv.URL, Path: "/api/item"}
	route.GET, route.Snippet, route.Size, route.GETAttempted =
		run.probe(context.Background(), http.MethodGet, srv.URL+route.Path)
	result.Routes = []Route{route}
	if got := result.ProbedRoutes(); got != 0 {
		t.Fatalf("%d routes counted as probed after the breaker refused to send them", got)
	}
}

func TestRouteRequestCountIsTheSentCounterDelta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`const route = "/api/item";`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	web := client.NewApplication(client.AppOptions{Site: srv.URL, Retries: 0})
	web.Do(context.Background(), http.MethodGet, srv.URL+"/before-stage", nil, nil)
	before, _ := web.Stats()
	result := Run(context.Background(), Options{
		Site: srv.URL, Web: web, Concurrency: 1, MaxRoutes: 5, MaxBypassRoutes: 1,
	})
	after, _ := web.Stats()
	if result.Requests != after-before {
		t.Fatalf("route stage reports %d requests; shared client sent %d during the stage",
			result.Requests, after-before)
	}
	if result.Requests == 0 {
		t.Fatal("fixture measured no route traffic")
	}
}
