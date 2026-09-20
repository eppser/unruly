-- Project 11, schema 2 of 4: `api`, the schema an application is meant to use.
--
-- api.users is a VIEW, and it is the CORRECT design: the base table keeps its
-- email addresses, the view projects only id and display_name, and the
-- application is pointed at the view. Reporting this as a leak is a false
-- positive, and it is a false positive that only a scanner reading COLUMNS
-- rather than names can avoid.
--
-- Note what the view does to RLS. In PostgreSQL 15 and later a view has a
-- `security_invoker` option that defaults to FALSE, so the view executes with
-- the privileges of its OWNER (postgres, the owner of public.users) and RLS on
-- the base table does not apply to the table's owner. The rows public.users
-- refuses to hand out come straight through this view. That is not a bug in
-- the fixture, it is the documented behaviour, and it is why "users returns
-- an empty array" is not a statement about the data.

CREATE SCHEMA api;

CREATE VIEW api.users AS
  SELECT id, display_name FROM public.users;

-- ---------------------------------------------------------------------------
-- service_status: exists ONLY in `api`.
-- ---------------------------------------------------------------------------
CREATE TABLE api.service_status (
  component   text PRIMARY KEY,
  state       text NOT NULL,
  checked_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO api.service_status (component, state) VALUES
  ('rest', 'operational'),
  ('auth', 'operational'),
  ('storage', 'degraded'),
  ('realtime', 'operational');

GRANT USAGE ON SCHEMA api TO anon, authenticated;
GRANT SELECT ON api.users          TO anon, authenticated;
GRANT SELECT ON api.service_status TO anon, authenticated;
