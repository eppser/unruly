// Dispatcher for the local edge-runtime fixture.
//
// The managed product puts Kong in front of edge-runtime, which is what maps
// /functions/v1/<name> to a worker and what enforces the JWT when a function
// declares verify_jwt. This fixture has no Kong, which is deliberate: it models
// a project whose functions are invokable without a JWT, the exact condition
// supabase-edge-function-no-jwt exists to report.
//
// Unknown names must answer 404, the way the managed product does. Letting a
// missing worker surface as a 500 would mean the scanner's control probe was
// being graded against this file's error handling rather than against the
// runtime's real behaviour.
Deno.serve(async (req: Request) => {
  const parts = new URL(req.url).pathname.split('/').filter(Boolean)
  const name = parts[parts.length - 1] ?? ''
  if (!name) {
    return new Response(JSON.stringify({ msg: 'missing function name' }), { status: 400 })
  }
  const servicePath = `/home/deno/functions/${name}`
  try {
    const st = await Deno.stat(servicePath)
    if (!st.isDirectory) throw new Deno.errors.NotFound()
  } catch {
    return new Response(JSON.stringify({ error: 'Function not found' }), {
      status: 404, headers: { 'content-type': 'application/json' },
    })
  }
  try {
    const worker = await EdgeRuntime.userWorkers.create({
      servicePath,
      memoryLimitMb: 150,
      workerTimeoutMs: 60_000,
      noModuleCache: false,
      importMapPath: null,
      envVars: Object.entries(Deno.env.toObject()),
    })
    return await worker.fetch(req)
  } catch (e) {
    return new Response(JSON.stringify({ msg: String(e) }), { status: 500 })
  }
})
