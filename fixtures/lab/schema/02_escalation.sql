-- CASE 9 — visible to `authenticated` but not to `anon`.
--
-- This is the privilege boundary a scan that only tests the anonymous role
-- cannot see. Where signup is open, anyone can mint an `authenticated` JWT,
-- so a policy written TO authenticated is effectively public — but an
-- anon-only scan reports the relation as protected.
CREATE TABLE authenticated_only (
  id       bigserial PRIMARY KEY,
  owner_id uuid,
  secret   text NOT NULL
);
INSERT INTO authenticated_only (secret)
SELECT 'members-only-' || g FROM generate_series(1, 6) g;
ALTER TABLE authenticated_only ENABLE ROW LEVEL SECURITY;
CREATE POLICY authenticated_can_read ON authenticated_only
  FOR SELECT TO authenticated USING (true);

-- Correctly scoped for comparison: authenticated users see only their OWN
-- rows, so escalation gains nothing. Must NOT be reported as an escalation.
CREATE TABLE owner_scoped (
  id       bigserial PRIMARY KEY,
  owner_id uuid NOT NULL DEFAULT gen_random_uuid(),
  note     text NOT NULL
);
INSERT INTO owner_scoped (note) SELECT 'private-' || g FROM generate_series(1, 4) g;
ALTER TABLE owner_scoped ENABLE ROW LEVEL SECURITY;
CREATE POLICY owner_scoped_own_rows ON owner_scoped
  FOR SELECT TO authenticated
  USING (owner_id::text = current_setting('request.jwt.claims', true)::json->>'sub');

GRANT SELECT, INSERT, UPDATE, DELETE ON authenticated_only, owner_scoped TO anon, authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
