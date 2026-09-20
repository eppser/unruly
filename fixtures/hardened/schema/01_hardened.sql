-- unruly eval fixture: a CORRECTLY configured project.
--
-- The vulnerable fixture measures recall. This one measures precision, which
-- is the harder property and the one a scanner is likelier to get wrong in a
-- way that destroys trust. A tool that flags every relation scores perfect
-- recall and is useless; the only way to prove unruly is not that tool is
-- to point it at a project with nothing wrong and require silence.
--
-- Expected result: nothing above LOW.
--
-- Not zero, and the difference is the honest part. PostgREST builds its
-- fuzzy-match hint from the schema cache, which knows nothing about
-- privileges, so internal_recalculate_ledger's NAME leaks to an anonymous
-- caller even though EXECUTE is revoked from PUBLIC below. No database
-- configuration suppresses that; the fix is to move the routine to a schema
-- PostgREST does not expose. The scanner reports it at low -- a real
-- disclosure, not a demonstrated exposure, because callability was never
-- established. Claiming ZERO here would have meant either hiding a true
-- finding or writing an eval that never asked, and this fixture had the
-- second: its routine assertion ran with no seeds at all.
--
-- Every relation here holds real data and is reachable by PostgREST, so the
-- scanner has something to find if its logic is wrong. Each is protected the
-- way Supabase documents: RLS enabled, policies scoped to the owning user
-- rather than to a role, and no policy that grants blanket access.

CREATE TABLE customers (
  id          bigserial PRIMARY KEY,
  owner_id    uuid NOT NULL DEFAULT gen_random_uuid(),
  email       text NOT NULL,
  full_name   text NOT NULL
);
INSERT INTO customers (email, full_name)
SELECT 'customer' || g || '@example.invalid', 'Customer ' || g FROM generate_series(1, 20) g;
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
CREATE POLICY customers_own_rows ON customers
  FOR SELECT TO authenticated
  USING (owner_id::text = current_setting('request.jwt.claims', true)::json->>'sub');

-- Credentials, deliberately: if the classifier ever fires on a relation the
-- role cannot actually read, this is where it would show up.
CREATE TABLE api_credentials (
  id            bigserial PRIMARY KEY,
  owner_id      uuid NOT NULL DEFAULT gen_random_uuid(),
  api_key       text NOT NULL,
  password_hash text NOT NULL
);
INSERT INTO api_credentials (api_key, password_hash)
SELECT 'sk_live_' || md5(g::text), md5('pw' || g) FROM generate_series(1, 10) g;
ALTER TABLE api_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY api_credentials_own_rows ON api_credentials
  FOR SELECT TO authenticated
  USING (owner_id::text = current_setting('request.jwt.claims', true)::json->>'sub');

-- A public submission form done correctly: anonymous INSERT is intended, but
-- constrained by WITH CHECK, and reads stay closed. unruly SHOULD report
-- the write as reachable here, because it genuinely is — so this relation is
-- declared as expected-writable in the answer key rather than as a false
-- positive. Being right about an intended exposure still requires reporting it.
CREATE TABLE contact_requests (
  id      bigserial PRIMARY KEY,
  message text NOT NULL,
  status  text NOT NULL DEFAULT 'new' CHECK (status = 'new')
);
ALTER TABLE contact_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY contact_requests_public_insert ON contact_requests
  FOR INSERT TO anon WITH CHECK (status = 'new');

-- Fully internal: RLS on, no policy for any client role at all.
CREATE TABLE internal_ledger (
  id     bigserial PRIMARY KEY,
  amount numeric NOT NULL
);
INSERT INTO internal_ledger (amount) SELECT g * 100 FROM generate_series(1, 15) g;
ALTER TABLE internal_ledger ENABLE ROW LEVEL SECURITY;

-- A SECURITY DEFINER routine that is NOT reachable by clients. The hint oracle
-- should not surface it, because EXECUTE is revoked below.
CREATE OR REPLACE FUNCTION internal_recalculate_ledger()
RETURNS integer LANGUAGE sql SECURITY DEFINER
SET search_path = public, pg_temp
AS $$ SELECT count(*)::integer FROM internal_ledger $$;

-- Supabase's documented posture: grant the API roles table access and let RLS
-- decide, but never hand them routine execution by default.
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO anon, authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
REVOKE ALL ON FUNCTION internal_recalculate_ledger() FROM PUBLIC, anon, authenticated;
