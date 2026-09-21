package semantic

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// FromSample adapts what a probe holds into what Augment needs.
//
// A relation carries sampled rows and the rules' "column:class" pairs. The
// conversion is separated out because getting it wrong is silent: a pair
// dropped here means a column the rules already proved gets sent to the model
// anyway, which breaks the precedence this package exists to guarantee, and
// nothing downstream would notice.
//
// Columns come back sorted so the request sequence is the same on every run.
func FromSample(sample []map[string]any, sensitivePairs []string) (
	columns []string, values map[string][]string, ruleClasses map[string][]string) {

	values = map[string][]string{}
	seen := map[string]bool{}
	for _, row := range sample {
		for col, v := range row {
			seen[col] = true
			// nil is skipped rather than rendered: "<nil>" describes the
			// encoding, not the data, and asking a model to classify it wastes
			// a request on a column that showed nothing.
			if v == nil {
				continue
			}
			values[col] = append(values[col], render(v))
		}
	}
	for col := range seen {
		columns = append(columns, col)
	}
	sort.Strings(columns)

	ruleClasses = map[string][]string{}
	for _, p := range sensitivePairs {
		i := strings.LastIndex(p, ":")
		// A pair with no separator is ignored rather than guessed at. Reading
		// a malformed pair as a bare column name would silently strip its
		// class and send a proven column to the model.
		if i <= 0 || i == len(p)-1 {
			continue
		}
		ruleClasses[p[:i]] = append(ruleClasses[p[:i]], p[i+1:])
	}
	if len(ruleClasses) == 0 {
		ruleClasses = nil
	}
	return columns, values, ruleClasses
}

// render turns a sampled value into the text the model sees. Nested values
// become their JSON, for the same reason internal/classify flattens them: the
// sensitive thing is often inside the object, where no column name reaches.
func render(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case map[string]any, []any:
		if b, err := json.Marshal(t); err == nil {
			return string(b)
		}
		return ""
	default:
		return fmt.Sprint(t)
	}
}
