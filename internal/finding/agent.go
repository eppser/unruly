package finding

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
)

// AgentSchema is the compact streaming contract. It is versioned separately
// from the human JSONL Finding shape so either can evolve without silently
// changing the other.
const AgentSchema = "unruly.agent/v1"

type AgentRecord struct {
	Schema      string        `json:"schema"`
	Type        string        `json:"type"`
	Fingerprint string        `json:"fingerprint"`
	ID          string        `json:"id"`
	Severity    Severity      `json:"severity"`
	Protocol    string        `json:"protocol"`
	Target      string        `json:"target"`
	Resource    string        `json:"resource,omitempty"`
	FixKind     FixKind       `json:"fix_kind,omitempty"`
	Observed    AgentEvidence `json:"observed,omitempty"`
	Replay      *AgentReplay  `json:"replay,omitempty"`
}

type AgentEvidence struct {
	Status  int      `json:"status,omitempty"`
	Rows    int      `json:"rows,omitempty"`
	Classes []string `json:"classes,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

type AgentReplay struct {
	Command   string `json:"command"`
	Performed bool   `json:"performed"`
}

func (f Finding) agentRecord() AgentRecord {
	r := AgentRecord{
		Schema: AgentSchema, Type: agentType(f.ID), Fingerprint: f.Fingerprint(),
		ID: f.ID, Severity: f.Severity, Protocol: f.Protocol,
		Target: f.Matched, Resource: f.Resource, FixKind: f.FixKind,
		Observed: AgentEvidence{Status: f.Evidence.Status, Rows: f.Evidence.Rows,
			Classes: f.Evidence.Classes, Reason: truncate(f.Evidence.Reason, 320)},
	}
	if f.Evidence.Request != "" {
		r.Replay = &AgentReplay{Command: safeAgentReplay(f.Evidence.Request),
			Performed: !f.Evidence.Suggested}
	}
	return r
}

var agentReplayRedactions = []struct {
	re *regexp.Regexp
	to string
}{
	{regexp.MustCompile(`(?i)(-H\s+'(?:authorization|apikey|x-api-key):\s*)[^']*'`), `${1}<redacted>'`},
	{regexp.MustCompile(`(?i)(-H\s+"(?:authorization|apikey|x-api-key):\s*)[^"]*"`), `${1}<redacted>"`},
	{regexp.MustCompile(`(?i)([?&](?:key|apikey|access_token|auth_token|token)=)[^&'"\s]+`), `${1}<redacted>`},
	{regexp.MustCompile(`(?i)(\s(?:-d|--data(?:-raw|-binary)?)\s+)'[^']*'`), `${1}'<redacted>'`},
	{regexp.MustCompile(`(?i)(\s(?:-d|--data(?:-raw|-binary)?)\s+)"[^"]*"`), `${1}"<redacted>"`},
}

func safeAgentReplay(command string) string {
	for _, redaction := range agentReplayRedactions {
		command = redaction.re.ReplaceAllString(command, redaction.to)
	}
	return command
}

func agentType(id string) string {
	if strings.HasPrefix(id, "unruly-") && id != "unruly-intent-violation" {
		return "coverage"
	}
	return "finding"
}

func writeAgent(out io.Writer, f Finding) error {
	return json.NewEncoder(out).Encode(f.agentRecord())
}
