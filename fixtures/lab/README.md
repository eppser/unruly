# Local eval fixture

> The fixtures bind fixed host ports (54321, 54331, 54341) and use explicit
> compose project names. Only one checkout of this repository can run them at a
> time. On macOS, the checkout must also sit under a path Docker Desktop shares
> — a clone under `/private/tmp` mounts the schema directory as EMPTY, and
> Postgres then starts with no tables and logs
> `ignoring /docker-entrypoint-initdb.d/*` rather than failing.

A minimal PostgREST + Postgres stack whose security posture is known by
construction. The cloud target checks realism; this checks coverage.

```sh
docker compose up -d
python3 mint-jwt.py > anon.jwt          # anon token for PGRST_JWT_SECRET
export UNRULY_FIXTURE_KEY=$(cat anon.jwt)
UNRULY_LIVE=1 go test ./internal/eval -run Fixture -v
```

The full `supabase start` stack is deliberately not used: it pulls ~8GB for
Studio, Logflare, edge-runtime and imgproxy, none of which the graded
dimensions touch.

Scan it directly with:

```sh
unruly -base-url http://127.0.0.1:54321 -rest-prefix / \
            -k "$(cat anon.jwt)" -w -yes-i-own-this -fix
```
