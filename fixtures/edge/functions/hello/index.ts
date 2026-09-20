// A benign function. Reachable without a JWT, which is the finding.
Deno.serve(() =>
  new Response(JSON.stringify({ ok: true, from: 'hello' }), {
    headers: { 'content-type': 'application/json' },
  })
)
