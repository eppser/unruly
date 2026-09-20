// A function whose NAME implies it does something on invocation. The scanner
// treats probing these as opt-in behind -invoke for exactly this reason: to
// learn whether it is callable you have to call it, and calling it sends the
// invoice. This fixture only records that it ran.
Deno.serve(() =>
  new Response(JSON.stringify({ sent: true, note: 'fixture: nothing was actually sent' }), {
    headers: { 'content-type': 'application/json' },
  })
)
