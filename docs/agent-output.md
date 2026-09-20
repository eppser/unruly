# Agent and CI output

`unruly -agent` writes one compact JSON object per line under the stable
`unruly.agent/v1` contract. The machine-readable definition is
[`unruly-agent-v1.schema.json`](schema/unruly-agent-v1.schema.json).

The stream is designed to minimize agent context without removing decision
data. It retains the canonical finding ID, stable fingerprint, severity,
protocol, target/resource, observed status/count/classes, coverage-vs-finding
type, remediation destination and a replay shape. It omits samples, target
response bodies, remediation prose and long human descriptions.

Replay commands are defensive artifacts: Authorization/API-key header values,
credential query parameters and request bodies are replaced with
`<redacted>`. `performed` distinguishes a request the scan observed from a
suggestion it deliberately did not execute.

```sh
# Save the compact stream. Exit 2 still means a confirmed high/critical result;
# exit 3 still means coverage is incomplete.
unruly -u https://app.example.com -agent -silent -o unruly.agent.jsonl

# Feed only actionable results to an agent.
jq -c 'select(.type == "finding" and
  (.severity == "high" or .severity == "critical"))' unruly.agent.jsonl

# Keep coverage gaps separate; never count them as passes.
jq -c 'select(.type == "coverage")' unruly.agent.jsonl

# Compare stable identities across two runs.
jq -r .fingerprint before.jsonl | sort > before.ids
jq -r .fingerprint after.jsonl  | sort > after.ids
diff -u before.ids after.ids
```

Consumers must reject an unknown `schema` value rather than partially reading
it. Additive or breaking wire changes require a new schema version and file;
the repository test ties every root Go field to the published v1 properties.

