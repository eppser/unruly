-- A second exposed schema.
--
-- Supabase projects routinely expose more than the default: the reference
-- target exposes three. A scanner that probes only the default schema cannot
-- see anything here, reports nothing, and nothing is what a clean project
-- looks like -- the same false-negative shape as depending on the OpenAPI root.
--
-- The names here are deliberately reachable from this fixture's vocabulary.
-- That is the point: an unreachable name proves only that the scan said
-- "not assessed", which is honest but does not demonstrate the capability.
-- The cloud lab carries the adversarial case separately.
CREATE SCHEMA reporting;
GRANT USAGE ON SCHEMA reporting TO anon, authenticated;

-- Readable by anon: the finding this fixture exists to produce, and it must be
-- reported as reporting.daily_revenue rather than daily_revenue, or it is
-- indistinguishable from a relation in the default schema.
CREATE TABLE reporting.daily_revenue (
  id            bigserial PRIMARY KEY,
  customer_email text NOT NULL,
  revenue_cents  bigint NOT NULL
);
INSERT INTO reporting.daily_revenue (customer_email, revenue_cents)
SELECT 'customer' || g || '@example.invalid', g * 1000 FROM generate_series(1, 14) g;
GRANT SELECT ON reporting.daily_revenue TO anon, authenticated;

-- Protected by REVOKE rather than by RLS. PostgREST answers 401 with SQLSTATE
-- 42501 and names the table, which proves it EXISTS -- a distinction the
-- enumerator missed until it was measured against a real project, reporting
-- zero relations for a schema whose names its own oracle was returning.
CREATE TABLE reporting.revenue_secrets (
  id     bigserial PRIMARY KEY,
  secret text NOT NULL
);
INSERT INTO reporting.revenue_secrets (secret) VALUES ('do-not-leak');
REVOKE ALL ON reporting.revenue_secrets FROM anon, authenticated, PUBLIC;

-- A SECURITY DEFINER routine in the non-default schema.
--
-- This is the shape worth catching: anon may EXECUTE it, it runs with the
-- owner's rights, and it returns rows from revenue_secrets -- a table anon
-- cannot read directly. A scanner that probes routines only in the default
-- schema reports nothing here, and the direct read of revenue_secrets is
-- correctly refused, so both signals point at "protected" while the data is
-- one RPC call away.
CREATE OR REPLACE FUNCTION reporting.rebuild_daily_revenue()
  RETURNS SETOF reporting.revenue_secrets
  LANGUAGE sql
  STABLE
  SECURITY DEFINER
  AS $$ SELECT * FROM reporting.revenue_secrets $$;
GRANT EXECUTE ON FUNCTION reporting.rebuild_daily_revenue() TO anon, authenticated;

-- Readable by authenticated, not by anon, in the NON-DEFAULT schema.
--
-- The escalation pass compares what an elevated role can read against what
-- anon can, and it used to run only over the default schema -- narrower than
-- the anonymous pass, which is the wrong way round, since the point of the
-- pass is that the authenticated role sees MORE. Where signup is open anyone
-- can hold that role, so this data is effectively public while an anonymous
-- scan records the relation as protected.
CREATE TABLE reporting.member_invoices (
  id       bigserial PRIMARY KEY,
  member_email text NOT NULL,
  amount_cents bigint NOT NULL
);
INSERT INTO reporting.member_invoices (member_email, amount_cents)
SELECT 'member' || g || '@example.invalid', g * 500 FROM generate_series(1, 9) g;
REVOKE ALL ON reporting.member_invoices FROM anon, PUBLIC;
GRANT SELECT ON reporting.member_invoices TO authenticated;
