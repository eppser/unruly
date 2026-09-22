package semantic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MinParameters is the size below which this readout stops working.
//
// Measured on 550 cases across 22 data classes: a 4B model reaches 86.7%
// recall at 16% false positives, a 3B reaches 4.4% at 89%. The failure is not
// gradual -- what disappears first is the ability to answer "none", and a 2B
// tagged 499 of 500 ordinary columns as sensitive. Used only to order
// candidates and skip the hopeless ones, never to choose between them.
const MinParameters = 4.0

// maxCandidates bounds what calibration costs. Six probes each, and a slow
// model answers in about two seconds, so three candidates is roughly thirty
// seconds in the worst case and usually far less.
const maxCandidates = 3

// PickModel chooses a model by MEASURING it, not by guessing.
//
// Two earlier versions guessed and both were wrong. "Largest wins" chose a
// 27.9B fine-tune that scored 0% recall over a 4.7B model that scored 100% --
// six times the parameters, none of the capability, six times slower. An
// allowlist of families was worse: overfit to one laptop, useless on a machine
// running mistral or llama, and stale the moment a better model ships.
//
// So each candidate answers six probes with known answers, three of which
// should come back as "none". Both halves are required: a model that says
// "none" to everything passes a positives-only check and is useless, and one
// that says "pii" to everything passes a negatives-only check and is worse.
//
// Costs a few seconds once, works for any model on any machine, and needs no
// list to stay current. -classifier-model skips it entirely.
func PickModel(host string, timeout time.Duration) (model, warning string) {
	endpoint := host
	host = strings.TrimSuffix(host, "/")
	for _, p := range []string{"/api/generate", "/v1/completions", "/completion"} {
		host = strings.TrimSuffix(host, p)
	}
	if endpoint == host {
		endpoint = host + "/api/generate"
	}
	c := &http.Client{Timeout: timeout}

	names := candidates(c, host, timeout)
	if len(names) == 0 {
		return "", "-classifier auto found a server but could not list its models. " +
			"If it needs one named, pass -classifier-model."
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(len(probes)*maxCandidates+2))
	defer cancel()

	best, bestScore := "", 0
	var tried []string
	for i, n := range names {
		if i >= maxCandidates {
			break
		}
		tried = append(tried, n)
		if s := calibrate(ctx, endpoint, n, timeout); s > bestScore {
			best, bestScore = n, s
			if s == len(probes) {
				break // perfect; nothing left to beat it
			}
		}
	}
	if best == "" || bestScore < len(probes)/2 {
		return best, fmt.Sprintf(
			"-classifier auto tried %s and none could classify a plain English street "+
				"address or decline an order-reference column. Classification will come "+
				"back empty. Install a model known to work (ollama pull qwen3.5:4b) or "+
				"name one with -classifier-model.", strings.Join(tried, ", "))
	}
	if bestScore < len(probes) {
		return best, fmt.Sprintf(
			"-classifier auto chose %s, which answered %d of %d calibration probes. "+
				"Expect classification to miss things a better model would catch.",
			best, bestScore, len(probes))
	}
	return best, ""
}

// candidates lists installed models in the order worth trying them.
//
// Smallest ABOVE the floor first, then anything whose size the server did not
// report, and models below the floor last. Size orders the search and never
// decides it -- the probes do that.
//
// Smallest-first because the cost is in the wrong place otherwise. Measured on
// the machine this was written on, largest-first spent 54 seconds calibrating,
// most of it loading a 17GB model, and selected one that runs at 2712ms per
// column against 332ms for a 4.7B scoring the same. Calibration is paid once;
// per-column latency is paid for every column of every scan.
func candidates(c *http.Client, host string, timeout time.Duration) []string {
	if names, ok := listFromOllama(c, host, timeout); ok {
		return names
	}
	if names, ok := listFromOpenAI(c, host, timeout); ok {
		return names
	}
	return nil
}

func listFromOllama(c *http.Client, host string, timeout time.Duration) ([]string, bool) {
	var out struct {
		Models []struct {
			Name    string `json:"name"`
			Details struct {
				ParameterSize string `json:"parameter_size"`
			} `json:"details"`
		} `json:"models"`
	}
	if !getJSON(c, host+"/api/tags", timeout, &out) || len(out.Models) == 0 {
		return nil, false
	}
	type cand struct {
		name string
		size float64
	}
	cs := make([]cand, 0, len(out.Models))
	for _, m := range out.Models {
		cs = append(cs, cand{m.Name, parseParams(m.Details.ParameterSize)})
	}
	// Three tiers: usable and cheap, unknown size, then too small to work.
	// Name is the tiebreak so the order is identical on every run and on every
	// machine with the same models installed.
	tier := func(c cand) int {
		switch {
		case c.size >= MinParameters:
			return 0
		case c.size < 0:
			return 1 // the server did not say; worth a probe
		default:
			return 2 // under the floor, cannot decline, tried last
		}
	}
	sort.Slice(cs, func(i, j int) bool {
		ti, tj := tier(cs[i]), tier(cs[j])
		if ti != tj {
			return ti < tj
		}
		if ti == 0 && cs[i].size != cs[j].size {
			return cs[i].size < cs[j].size // smallest that clears the floor
		}
		return cs[i].name < cs[j].name
	})
	names := make([]string, 0, len(cs))
	for _, x := range cs {
		names = append(names, x.name)
	}
	return names, true
}

func listFromOpenAI(c *http.Client, host string, timeout time.Duration) ([]string, bool) {
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if !getJSON(c, host+"/v1/models", timeout, &out) || len(out.Data) == 0 {
		return nil, false
	}
	names := make([]string, 0, len(out.Data))
	for _, d := range out.Data {
		names = append(names, d.ID)
	}
	sort.Strings(names)
	return names, true
}

// parseParams reads "4.7B" or "770M". Returns -1 when the server did not say,
// which sorts below any model that did rather than winning by default.
func parseParams(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return -1
	}
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "B"), strings.HasSuffix(s, "b"):
		s = s[:len(s)-1]
	case strings.HasSuffix(s, "M"), strings.HasSuffix(s, "m"):
		s, mult = s[:len(s)-1], 1.0/1000
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return -1
	}
	return v * mult
}

func getJSON(c *http.Client, url string, timeout time.Duration, into any) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return json.NewDecoder(resp.Body).Decode(into) == nil
}
