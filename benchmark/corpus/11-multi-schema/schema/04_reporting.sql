-- Project 11, schema 4 of 4: `reporting`, exposed but entirely REVOKE-protected.
--
-- Every relation here is served by PostgREST (the schema is in
-- PGRST_DB_SCHEMAS) and none of them carries a single privilege for `anon`.
-- Over HTTP the schema therefore presents as empty: every request answers 401
-- with SQLSTATE 42501.
--
-- That 401 is the point. It is not silence. Postgres names the relation in the
-- error body — "permission denied for table revenue_by_month" — so a 401 is
-- POSITIVE evidence that the relation exists. There is a known real bug class
-- here: a scanner that treats 401 as "says nothing" concludes that no relation
-- in `reporting` exists and reports an entire schema of real tables as absent.
-- The answer key asserts both halves: psql sees the tables and their rows, and
-- HTTP answers 401 while naming each one.
--
-- USAGE on the schema IS granted. Without it PostgREST cannot resolve the
-- relation at all and the answer changes shape; granting USAGE and nothing
-- else is what produces the informative 401.

CREATE SCHEMA reporting;

-- The fourth `users`. Same name as public.users, api.users and legacy.users,
-- and a fourth distinct verdict: not empty, not readable, not absent.
CREATE TABLE reporting.users (
  id             bigserial PRIMARY KEY,
  email          text NOT NULL,
  lifetime_value numeric(10,2) NOT NULL,
  segment        text NOT NULL
);

INSERT INTO reporting.users (email, lifetime_value, segment)
SELECT 'user' || i || '@example.invalid', (i * 137.5)::numeric(10,2),
       (ARRAY['smb','enterprise','trial'])[1 + (i % 3)]
FROM generate_series(1, 9) AS i;

-- ---------------------------------------------------------------------------
-- revenue_by_month and churn_cohorts: exist ONLY in `reporting`.
-- ---------------------------------------------------------------------------
CREATE TABLE reporting.revenue_by_month (
  month        date PRIMARY KEY,
  mrr_cents    bigint NOT NULL,
  new_accounts integer NOT NULL
);

INSERT INTO reporting.revenue_by_month (month, mrr_cents, new_accounts)
SELECT (date '2025-01-01' + (i || ' month')::interval)::date,
       4200000 + i * 130000, 40 + i * 3
FROM generate_series(0, 13) AS i;

CREATE TABLE reporting.churn_cohorts (
  cohort_month date NOT NULL,
  months_since integer NOT NULL,
  retained     integer NOT NULL,
  PRIMARY KEY (cohort_month, months_since)
);

INSERT INTO reporting.churn_cohorts (cohort_month, months_since, retained)
SELECT (date '2025-01-01' + (m || ' month')::interval)::date, s, 100 - (s * 7)
FROM generate_series(0, 3) AS m, generate_series(0, 5) AS s;

GRANT USAGE ON SCHEMA reporting TO anon, authenticated;
-- Deliberately no table grants. Postgres grants nothing on a new table, so
-- there is nothing to REVOKE; the absence below is the configuration.
