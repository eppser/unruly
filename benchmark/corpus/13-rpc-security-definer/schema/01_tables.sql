-- Project 13, part 1 of 2: the tables, which are all correctly protected.
--
-- Read this file on its own and the target is clean. `customers` has RLS
-- enabled with a policy that scopes rows to the requesting user's email claim,
-- which no token this corpus mints carries, so it returns an empty array to
-- everybody. `api_keys` and `audit_events` hold no privilege for anon at all,
-- so Postgres refuses with 42501 and PostgREST answers 401.
--
-- That is the whole point. The relations are not the way in; 02_routines.sql
-- is. A scanner that enumerates relations and stops reports this project as
-- correctly configured, and it is not.

-- ---------------------------------------------------------------------------
-- customers: RLS on, with a real policy rather than the empty-policy-set shape
-- project 03 measures. The policy is satisfiable — a token carrying the right
-- email claim would see its own row — which is what makes it a plausible
-- configuration rather than a deny-all.
-- ---------------------------------------------------------------------------
CREATE TABLE public.customers (
  id            bigserial PRIMARY KEY,
  full_name     text NOT NULL,
  email         text NOT NULL,
  phone_number  text NOT NULL,
  country       text NOT NULL,
  owner_email   text NOT NULL
);

INSERT INTO public.customers (full_name, email, phone_number, country, owner_email)
SELECT
  (ARRAY['Dana Whitfield','Marcus Oyelaran','Priya Raghunathan','Tomas Berg',
         'Elena Marchetti','Kwame Asante','Sofia Lindqvist','Yuki Tanaka'])[1 + (i % 8)] || ' ' || i,
  'customer' || i || '@example.invalid',
  '+1-555-02' || lpad(i::text, 2, '0'),
  (ARRAY['GB','SE','IN','BR','JP','DE'])[1 + (i % 6)],
  'owner' || (1 + (i % 4)) || '@example.invalid'
FROM generate_series(1, 20) AS i;

ALTER TABLE public.customers ENABLE ROW LEVEL SECURITY;

-- The row is yours if the JWT's `email` claim matches owner_email. The corpus
-- minter emits role, iss, iat, exp and sub and NO email claim, so
-- current_setting returns NULL, the comparison is NULL, and no row qualifies
-- for anon or for authenticated. Measured, not assumed.
CREATE POLICY customers_owner_read ON public.customers
  FOR SELECT
  USING (owner_email = current_setting('request.jwt.claims', true)::jsonb ->> 'email');

GRANT SELECT ON public.customers TO anon, authenticated;

-- ---------------------------------------------------------------------------
-- api_keys: no grant for anyone. Postgres answers 42501 before RLS is even
-- consulted, so this one presents as 401 rather than as an empty array.
--
-- The key hashes are fixed strings, not derived from anything, and the prefix
-- is there so that a value-reading scanner has something to recognise once it
-- gets in — which it can, through the routine in the next file.
-- ---------------------------------------------------------------------------
CREATE TABLE public.api_keys (
  id          bigserial PRIMARY KEY,
  label       text NOT NULL,
  key_hash    text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.api_keys (label, key_hash) VALUES
  ('production web',      'sk_live_meridian_0000000000000001'),
  ('production mobile',   'sk_live_meridian_0000000000000002'),
  ('nightly export job',  'sk_live_meridian_0000000000000003'),
  ('partner sandbox',     'sk_test_meridian_0000000000000004'),
  ('retired 2024 key',    'sk_live_meridian_0000000000000005');

-- ---------------------------------------------------------------------------
-- audit_events: also no grant for anyone. This is the table the SECURITY
-- DEFINER *write* routine inserts into, so it is the proof that a locked table
-- can still be written to by a stranger.
--
-- Five seeded rows, plus ONE probe row. The probe row exists so that the
-- verifier's psql check is idempotent: that check deletes rows belonging to
-- the probe actor and asserts it deleted exactly one, which on the first run
-- removes this seed and on every subsequent run removes the row the PREVIOUS
-- run's RPC wrote. From run two onwards it is therefore a genuine psql-side
-- proof that the anonymous write landed and persisted.
-- ---------------------------------------------------------------------------
CREATE TABLE public.audit_events (
  id           bigserial PRIMARY KEY,
  actor        text NOT NULL,
  action       text NOT NULL,
  detail       text NOT NULL,
  occurred_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.audit_events (actor, action, detail) VALUES
  ('dana@example.invalid',   'login',        'password, from 198.51.100.7'),
  ('marcus@example.invalid', 'key_rotate',   'rotated production web'),
  ('priya@example.invalid',  'policy_edit',  'customers_owner_read created'),
  ('tomas@example.invalid',  'export',       '20 customer rows to CSV'),
  ('elena@example.invalid',  'login',        'password, from 203.0.113.42'),
  ('rpc-probe@example.invalid', 'contact_request', 'seeded so the verifier is idempotent');

-- No GRANT on api_keys or audit_events. Postgres grants nothing on a new
-- table, so there is nothing to REVOKE; the absence is the configuration.
GRANT USAGE ON SCHEMA public TO anon, authenticated;
