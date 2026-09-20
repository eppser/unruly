-- unruly eval fixture: a schema whose security posture is known by
-- construction rather than by observation.
--
-- The reference target (the reference target) is a real application and its ground
-- truth had to be measured. That makes it a good realism check but a poor
-- coverage check: it only contains the states that application happens to be
-- in. This fixture deliberately covers the states it does NOT, including two
-- code paths that have never executed against a real target.
--
-- Every relation is named for its expected verdict so a mismatch is obvious in
-- eval output.

-- ═══════════════════════════════════════════════════════════════════════
-- CASE 1 — RLS never enabled.
-- The single most common Supabase mistake, and the one the dashboard emails
-- about. Both read and write are wide open.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE open_no_rls (
  id          bigserial PRIMARY KEY,
  label       text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO open_no_rls (label)
SELECT 'row-' || g FROM generate_series(1, 12) g;

-- ═══════════════════════════════════════════════════════════════════════
-- CASE 2 — RLS enabled, no policy at all.
-- Correctly protected: SELECT returns 200 with an empty range, INSERT is
-- refused with 42501. This is the precision case — flagging it is a false
-- positive.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE protected_rls_no_policy (
  id      bigserial PRIMARY KEY,
  secret  text NOT NULL
);
INSERT INTO protected_rls_no_policy (secret)
SELECT 'classified-' || g FROM generate_series(1, 7) g;
ALTER TABLE protected_rls_no_policy ENABLE ROW LEVEL SECURITY;

-- ═══════════════════════════════════════════════════════════════════════
-- CASE 3 — readable but not writable.
-- A permissive SELECT policy with no INSERT policy. Separates the read and
-- write dimensions: a scanner that conflates them fails here.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE read_only_policy (
  id     bigserial PRIMARY KEY,
  title  text NOT NULL
);
INSERT INTO read_only_policy (title)
SELECT 'public-' || g FROM generate_series(1, 5) g;
ALTER TABLE read_only_policy ENABLE ROW LEVEL SECURITY;
CREATE POLICY read_only_public_select ON read_only_policy
  FOR SELECT TO anon USING (true);

-- ═══════════════════════════════════════════════════════════════════════
-- CASE 4 — writable but not readable.
-- The inverse: an INSERT policy with no SELECT policy, the shape a "public
-- submission form" produces. Reads return empty while writes are accepted, so
-- a read-only scanner reports this table as safe. Every surveyed tool misses
-- it entirely.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE write_only_policy (
  id       bigserial PRIMARY KEY,
  message  text NOT NULL,
  status   text NOT NULL DEFAULT 'pending'
);
INSERT INTO write_only_policy (message)
SELECT 'submission-' || g FROM generate_series(1, 3) g;
ALTER TABLE write_only_policy ENABLE ROW LEVEL SECURITY;
CREATE POLICY write_only_public_insert ON write_only_policy
  FOR INSERT TO anon WITH CHECK (true);

-- ═══════════════════════════════════════════════════════════════════════
-- CASE 5 — every column nullable or defaulted, RLS off.
-- An empty INSERT actually SUCCEEDS here and lands a row. This is the probe's
-- cleanup path, which has never executed against a real target: unruly
-- must create the row, delete it again, and leave the row count unchanged.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE all_defaults_insertable (
  id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  note    text DEFAULT 'unset',
  amount  integer DEFAULT 0
);
INSERT INTO all_defaults_insertable (note) VALUES ('seed-a'), ('seed-b');

-- ═══════════════════════════════════════════════════════════════════════
-- CASE 6 — exposed credentials and PII.
-- Drives the sensitive-column classifier and the severity bump from high to
-- critical.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE leaky_credentials (
  id             bigserial PRIMARY KEY,
  email          text NOT NULL,
  api_key        text NOT NULL,
  password_hash  text NOT NULL,
  phone_number   text
);
INSERT INTO leaky_credentials (email, api_key, password_hash, phone_number)
SELECT 'user' || g || '@example.invalid',
       'sk_test_' || md5(g::text),
       md5('password' || g),
       '+1555000' || lpad(g::text, 4, '0')
FROM generate_series(1, 4) g;

-- ═══════════════════════════════════════════════════════════════════════
-- CASE 7 — a relation whose name appears nowhere in the application.
-- Tests whether enumeration depends on harvested vocabulary alone. The hint
-- oracle should still reach it from a near-miss of a name that IS in the app.
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE open_no_rls_archive (
  id     bigserial PRIMARY KEY,
  label  text NOT NULL
);
INSERT INTO open_no_rls_archive (label) VALUES ('archived-1'), ('archived-2');

-- ═══════════════════════════════════════════════════════════════════════
-- CASE 8 — a SECURITY DEFINER routine gated only by a literal token.
-- Mirrors the pattern found on the reference target. Runs with the owner's
-- rights, so its own argument check is the only control.
-- ═══════════════════════════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION admin_purge_submissions(p_token text)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE removed integer;
BEGIN
  IF p_token <> 'fixture-token-do-not-use' THEN
    RAISE EXCEPTION 'invalid token';
  END IF;
  DELETE FROM write_only_policy WHERE status = 'rejected';
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END;
$$;

-- A harmless routine, to confirm privilege classification keys on the name
-- rather than flagging every routine it finds.
CREATE OR REPLACE FUNCTION public_stats_summary()
RETURNS integer LANGUAGE sql STABLE
AS $$ SELECT count(*)::integer FROM read_only_policy $$;

-- PostgREST only exposes what anon is granted. Supabase grants these by
-- default in the public schema; stated explicitly so the fixture does not
-- depend on platform defaults.
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO anon, authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated;

-- Supabase's own auth column names, exposed.
--
-- Named "tokens" because that name is IN the pinned generic wordlist. The
-- first version called it auth_recovery, which nothing in the vocabulary
-- reaches, so the scan could not discover it and the eval correctly reported a
-- recall miss -- a fixture testing the classifier that the scanner could never
-- get to. The hint oracle only matches near-misses of the FULL name, so a
-- fixture meant to exercise a downstream rule has to be reachable by
-- construction.
--
-- The sensitive-column classifier decides whether a read exposure is high or
-- CRITICAL, and its token rule used to be a fixed prefix list
-- (access|refresh|api|auth|bearer|session|csrf). That missed every token
-- Supabase itself uses -- confirmation_token, recovery_token,
-- email_change_token -- so a table full of password-reset credentials was
-- reported one severity too low, which is harder to notice than missing it
-- outright.
CREATE TABLE tokens (
  id                 bigserial PRIMARY KEY,
  user_email         text NOT NULL,
  confirmation_token text NOT NULL,
  recovery_token     text NOT NULL,
  -- A count, not a secret. If the classifier ever widens to "contains token"
  -- this column turns every usage table into a critical.
  tokens_used        integer NOT NULL DEFAULT 0
);
INSERT INTO tokens (user_email, confirmation_token, recovery_token, tokens_used)
SELECT 'user' || g || '@example.invalid', md5('c' || g), md5('r' || g), g
FROM generate_series(1, 6) g;

-- Granted explicitly. The GRANT ... ON ALL TABLES above ran before this table
-- existed, so appending a table after it leaves the table unreachable and the
-- answer key wrong -- which is how this fixture first reported a recall miss
-- against a scanner that was behaving correctly.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tokens TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE tokens_id_seq TO anon, authenticated;
