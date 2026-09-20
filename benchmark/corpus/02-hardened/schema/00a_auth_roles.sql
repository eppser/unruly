-- Roles, schema and helper GoTrue and the RLS policies both need.
--
-- Named 00a_ so it sorts after lib/00_roles.sql (which creates anon,
-- authenticated and authenticator) and before 01_schema.sql. The auth admin
-- has to exist before the auth container starts, or GoTrue's migrations fail
-- and the container restarts forever with nothing in the log naming the cause.
CREATE ROLE supabase_auth_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION
  PASSWORD 'fixture';
CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION supabase_auth_admin;
GRANT CREATE ON DATABASE fixture TO supabase_auth_admin;
ALTER USER supabase_auth_admin SET search_path = 'auth';

-- auth.request_sub(): the per-user policy helper, and NOT called auth.uid().
--
-- The name matters, and the reason was measured rather than reasoned about.
-- GoTrue v2.151 creates auth.uid() ITSELF during migration, owned by
-- supabase_auth_admin. Defining auth.uid() here first puts a function owned by
-- `postgres` in its way, GoTrue's CREATE OR REPLACE then fails with
--
--   running db migrations: ... ERROR: must be owner of function uid
--   (SQLSTATE 42501)
--
-- and the auth container exits. Which in turn takes the GATEWAY down, because
-- nginx resolves a literal proxy_pass upstream at config-load time: the whole
-- stack presented as "host not found in upstream auth", a message that names
-- neither Postgres nor ownership.
--
-- So the helper gets its own name and GoTrue's auth.uid() is left alone.
--
-- The two functions do not have the same body, which the answer key asserts.
-- GoTrue's final auth.uid() reads
--   coalesce(nullif(current_setting('request.jwt.claim.sub', true), ''),
--            nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
-- -- the LEGACY GUC name first, with the modern one as a fallback. That
-- fallback is what makes it work under PGRST_DB_USE_LEGACY_GUCS=false; the
-- first migration that creates it has only the legacy branch, so a stack that
-- stopped part way through the migration chain would have policies that deny
-- their own owners. Ours does not, and the answer key measures the owner's
-- read rather than assuming it.
--
-- It lives in the `auth` schema and not in `public` on purpose: PostgREST is
-- configured with PGRST_DB_SCHEMAS=public, so a function in `public` would be
-- an RPC endpoint at /rest/v1/rpc/<name> and would add a routine to this
-- project's attack surface. The answer key claims `routines: []`, and that
-- claim should be true because there are none, not because the ones that exist
-- happen to be harmless.
--
-- The second argument to current_setting is missing_ok. Without it an
-- anonymous request -- which sets no claims GUC at all -- raises 42704 instead
-- of returning NULL, and every policy below answers 500 rather than deny.
CREATE OR REPLACE FUNCTION auth.request_sub() RETURNS uuid
  LANGUAGE sql STABLE
  AS $$
    SELECT nullif(current_setting('request.jwt.claims', true)::json ->> 'sub', '')::uuid
  $$;

GRANT USAGE ON SCHEMA auth TO anon, authenticated;
GRANT EXECUTE ON FUNCTION auth.request_sub() TO anon, authenticated;
