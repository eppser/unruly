# Access intent

An outside scan proves what is reachable. It cannot infer whether a public
catalogue was meant to be public or whether a signed-in user should see only
their own invoices. `-intent` supplies that missing policy as data, then unruly
compares it with facts the scan actually measured.

```yaml
schema_version: 1
expect:
  - resource: public_catalogue
    operation: read
    subject: anonymous
    scope: all
    result: allow

  - resource: invoices
    operation: read
    subject: anonymous
    result: deny

  - resource: invoices
    operation: read
    subject: owner
    scope: own
    result: allow

  - resource: invoices
    operation: read
    subject: other_tenant
    result: deny
```

```console
unruly -u https://app.example -intent access.yaml
```

Subjects are `anonymous`, `authenticated`, `owner`, `other_tenant`, and
`admin`. Operations are `read`, `insert`, `update`, and `delete`. Scope is
`own` or `all` and applies only to allowed access.

Every expectation becomes `matched`, `violated`, or `unverified`. Unverified
is never a pass: it means the selected probes did not establish that fact. For
example, an empty PostgREST result can mean an empty table or rows filtered by
RLS, so it cannot prove an intended denial. Owner/other-tenant expectations
require suitable identities and record identifiers; until those observations
are wired into a provider, they remain visibly unverified.

The parser rejects unknown schema versions, fields, subjects, operations and
scopes rather than silently dropping policy.
