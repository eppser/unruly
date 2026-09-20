-- A view that hands out the rows its base table refuses.
--
-- Postgres views run with the DEFINER's privileges unless security_invoker is
-- set, and that option defaults to FALSE. So a table can be correctly
-- protected by row-level security and a view over it can still return every
-- row to anon -- the policy is evaluated as the view's owner, not as the
-- caller. It is one of the most common accidental bypasses in a Supabase
-- project, because creating a view feels like creating a shortcut rather than
-- a new grant.
--
-- It is here for TWO reasons, and the second is the one that bit us.
--
-- Detection already worked: PostgREST exposes a view as a relation like any
-- other, so the hint oracle finds it and the read probe reports it.
--
-- REMEDIATION did not. The fix plan emits, for every exposed relation:
--
--   ALTER TABLE <name> ENABLE ROW LEVEL SECURITY;
--
-- and on a view that is not a no-op, it is an error. Measured on PostgreSQL
-- 16.14:
--
--   ERROR: ALTER action ENABLE ROW SECURITY cannot be performed on
--          relation "view_leak"
--   DETAIL: This operation is not supported for views.
--
-- An operator piping the plan into psql gets a failure part-way through a
-- script this project advertises as its strongest output. REVOKE is fine on a
-- view; only the row-level-security statement had to change.
CREATE TABLE view_base (
  id     serial PRIMARY KEY,
  holder text,
  secret text
);
ALTER TABLE view_base ENABLE ROW LEVEL SECURITY;
-- No policy: the table itself gives anon nothing.
INSERT INTO view_base (holder, secret) VALUES
  ('alice', 'alice-private'),
  ('bob',   'bob-private');
GRANT SELECT ON view_base TO anon;

-- The bypass. security_invoker is left at its default of false ON PURPOSE.
CREATE VIEW view_leak AS SELECT id, holder, secret FROM view_base;
GRANT SELECT ON view_leak TO anon;
