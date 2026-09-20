-- Corpus project 15: RLS state held constant, the GRANTs vary.
--
-- This is the exact inverse of project 03, which holds GRANTs constant and
-- varies the policy. Neither is redundant: a scanner can pass one and fail the
-- other, and the failure this project catches is the one a major vendor's own
-- console makes.
--
-- Row-Level Security is only half of the permission. A table with RLS switched
-- OFF is wide open ONLY IF a role also holds a GRANT on it. With no GRANT,
-- PostgreSQL refuses with 42501 before RLS is ever consulted -- so "RLS is
-- disabled" is not a finding, it is one input to a finding.

-- == RLS OFF, GRANTED: genuinely exposed =============================
CREATE TABLE rls_off_granted (id serial PRIMARY KEY, owner text, card_last4 text);
INSERT INTO rls_off_granted (owner, card_last4)
  VALUES ('alpha','0000'), ('beta','1111'), ('gamma','2222');
GRANT SELECT ON rls_off_granted TO anon, authenticated;

-- == RLS OFF, NOT GRANTED: the false positive =========================
-- The headline of this project. RLS is disabled here exactly as above, and
-- the table is NOT reachable: no role holds a GRANT, so every request answers
-- 42501. A scanner that reads relrowsecurity and stops reports this table.
-- Neon's console does precisely that, warning that "all authenticated users
-- can view all rows" of a table that answers 403 to every caller.
CREATE TABLE rls_off_ungranted (id serial PRIMARY KEY, secret text);
INSERT INTO rls_off_ungranted (secret) VALUES ('must-never-be-read');

-- == RLS ON, GRANTED, NO POLICY: deny-all ============================
-- Answers 200 with an empty array, which is indistinguishable from an empty
-- table on a single observation.
CREATE TABLE rls_on_nopolicy (id serial PRIMARY KEY, note text);
INSERT INTO rls_on_nopolicy (note) VALUES ('hidden-by-rls');
ALTER TABLE rls_on_nopolicy ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON rls_on_nopolicy TO anon, authenticated;

-- == RLS ON, GRANTED, PERMISSIVE POLICY: exposed again ================
-- RLS being ENABLED is not protection either. The mirror image of the false
-- positive above, and it catches the opposite error: a scanner that treats
-- relrowsecurity = true as safe misses this one.
CREATE TABLE rls_on_permissive (id serial PRIMARY KEY, email text);
INSERT INTO rls_on_permissive (email) VALUES ('alpha@example.invalid'), ('beta@example.invalid');
ALTER TABLE rls_on_permissive ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON rls_on_permissive TO anon, authenticated;
CREATE POLICY everyone ON rls_on_permissive FOR SELECT TO anon, authenticated USING (true);
