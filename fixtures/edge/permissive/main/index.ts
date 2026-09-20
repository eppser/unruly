// A deployment that answers 200 to every name, including ones that do not
// exist. Real deployments do this when a catch-all router or a CDN sits in
// front of the function host.
//
// This is the case that makes Edge Function detection unsound if taken at face
// value: probe any name, get 200, conclude a function exists, and report every
// candidate in the wordlist. unruly-control-function-absent exists to
// notice it -- the scanner probes a name that cannot exist, and if THAT is
// accepted too, the oracle carries no information and no function findings may
// be derived from it.
Deno.serve(() =>
  new Response(JSON.stringify({ ok: true, note: 'this host answers to any name' }), {
    headers: { 'content-type': 'application/json' },
  })
)
