package neon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eppser/unruly/internal/client"
	"github.com/eppser/unruly/scan"
)

func TestEnumeratedNamesAreProbedInTheSamePipeline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		w.Header().Set("Content-Type", "application/json")
		switch name {
		case "widget":
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"code":"PGRST205","hint":"Perhaps you meant the table 'public.widgets'"}`)
		case "widgets":
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"message":"missing authentication credentials"}`)
				return
			}
			fmt.Fprint(w, `[{"id":1,"owner_id":"other"}]`)
		default:
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"code":"PGRST205","hint":null}`)
		}
	}))
	defer srv.Close()
	c := client.New(client.Options{BaseURL: srv.URL, RestPrefix: "/", Retries: 0})
	st := &scan.State{Target: srv.URL}
	stages := []scan.Stage{
		EnumerateStage{Base: srv.URL, Seeds: []string{"widget"}, Token: "token", Client: c},
		EscalationStage{Base: srv.URL, Tables: []string{"widget"}, Token: "token", Client: c},
	}
	if err := scan.Validate(stages); err != nil {
		t.Fatal(err)
	}
	if _, err := scan.Pipeline(stages).Run(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	for _, f := range st.Findings() {
		if f.ID == "neon-authenticated-read-unrestricted" && f.Resource == "widgets" {
			return
		}
	}
	t.Fatalf("the hinted relation was reported but not assessed in the same run: %+v", st.Findings())
}
