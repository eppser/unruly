package finding

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestPublishedAgentSchemaMatchesTheGoContract(t *testing.T) {
	b, err := os.ReadFile("../../docs/schema/unruly-agent-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatalf("published agent schema is invalid JSON: %v", err)
	}
	fields := map[string]bool{}
	typ := reflect.TypeOf(AgentRecord{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			fields[name] = true
		}
	}
	for name := range fields {
		if _, ok := schema.Properties[name]; !ok {
			t.Errorf("AgentRecord field %q is absent from the published schema", name)
		}
	}
	for name := range schema.Properties {
		if !fields[name] {
			t.Errorf("published schema field %q has no AgentRecord field", name)
		}
	}
	required := map[string]bool{}
	for _, name := range schema.Required {
		required[name] = true
	}
	for _, name := range []string{"schema", "type", "fingerprint", "id", "severity", "protocol", "target"} {
		if !required[name] {
			t.Errorf("wire-required AgentRecord field %q is optional in the published schema", name)
		}
	}
}
