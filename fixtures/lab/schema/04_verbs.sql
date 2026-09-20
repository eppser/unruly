-- UPDATE and DELETE controls.
--
-- The rest of this fixture varies SELECT and INSERT. Nothing here varied the
-- other two verbs, so when a sound UPDATE probe was designed there was no
-- relation on which its NEGATIVE answer could be checked -- only that it fired
-- when access was open, which is half a test. A probe verified in one direction
-- is how a false-positive design ships.
--
-- Every table here is readable by anon, because both probes need a row to aim
-- at. What varies is which of UPDATE and DELETE the policy grants.
--
-- Keys are bigserial, not GENERATED ALWAYS AS IDENTITY. That distinction is not
-- cosmetic: PostgreSQL refuses to update an identity column at all (428C9),
-- during statement rewriting and before any policy is consulted, so an identity
-- key makes the collision variant of the probe inconclusive no matter what the
-- policy says. verb_identity_key exists to pin exactly that.

-- 1. UPDATE open, DELETE closed. The positive control for UPDATE and the
--    negative control for DELETE, in one table.
CREATE TABLE verb_update_open (
  id    bigserial PRIMARY KEY,
  label text NOT NULL,
  note  text
);
INSERT INTO verb_update_open (label, note) VALUES ('alpha', 'first'), ('beta', 'second');
ALTER TABLE verb_update_open ENABLE ROW LEVEL SECURITY;
CREATE POLICY verb_update_open_sel ON verb_update_open FOR SELECT TO anon USING (true);
CREATE POLICY verb_update_open_upd ON verb_update_open FOR UPDATE TO anon USING (true) WITH CHECK (true);

-- 2. Readable only. The negative control for BOTH verbs: a scanner that reports
--    UPDATE or DELETE here is producing false positives, which is what the
--    zero-match PATCH probe does on every table it sees.
CREATE TABLE verb_read_only (
  id    bigserial PRIMARY KEY,
  label text NOT NULL,
  note  text
);
INSERT INTO verb_read_only (label, note) VALUES ('gamma', 'third'), ('delta', 'fourth');
ALTER TABLE verb_read_only ENABLE ROW LEVEL SECURITY;
CREATE POLICY verb_read_only_sel ON verb_read_only FOR SELECT TO anon USING (true);

-- 3. INSERT and DELETE open, UPDATE closed. DELETE is provable here because the
--    scan can create a row of its own to delete; the row it removes is never
--    the fixture's.
CREATE TABLE verb_delete_open (
  id    bigserial PRIMARY KEY,
  label text,
  note  text
);
INSERT INTO verb_delete_open (label, note) VALUES ('epsilon', 'fifth'), ('zeta', 'sixth');
ALTER TABLE verb_delete_open ENABLE ROW LEVEL SECURITY;
CREATE POLICY verb_delete_open_sel ON verb_delete_open FOR SELECT TO anon USING (true);
CREATE POLICY verb_delete_open_ins ON verb_delete_open FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY verb_delete_open_del ON verb_delete_open FOR DELETE TO anon USING (true);

-- 4. FOR ALL. One policy, all four verbs -- the single most common way a table
--    ends up deletable by strangers, because FOR ALL reads like "for all rows".
CREATE TABLE verb_all_open (
  id    bigserial PRIMARY KEY,
  label text,
  note  text
);
INSERT INTO verb_all_open (label, note) VALUES ('eta', 'seventh'), ('theta', 'eighth');
ALTER TABLE verb_all_open ENABLE ROW LEVEL SECURITY;
CREATE POLICY verb_all_open_all ON verb_all_open FOR ALL TO anon USING (true) WITH CHECK (true);

-- 5. UPDATE open, INSERT closed. Forces the probe down the path where no row of
--    its own can be created, so UPDATE must be established against a row that
--    belongs to the target -- without altering it.
CREATE TABLE verb_update_noinsert (
  id    bigserial PRIMARY KEY,
  label text NOT NULL,
  note  text
);
INSERT INTO verb_update_noinsert (label, note) VALUES ('iota', 'ninth'), ('kappa', 'tenth');
ALTER TABLE verb_update_noinsert ENABLE ROW LEVEL SECURITY;
CREATE POLICY verb_update_noinsert_sel ON verb_update_noinsert FOR SELECT TO anon USING (true);
CREATE POLICY verb_update_noinsert_upd ON verb_update_noinsert FOR UPDATE TO anon USING (true) WITH CHECK (true);

-- 6. Identity key, UPDATE open. The collision variant CANNOT answer here: the
--    key is GENERATED ALWAYS, so PostgreSQL rejects the statement before any
--    policy runs. The correct verdict is inconclusive, not "protected" -- this
--    table is in fact wide open to UPDATE, and calling it clean would be the
--    false negative this scanner exists to prevent.
CREATE TABLE verb_identity_key (
  id    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  label text NOT NULL
);
INSERT INTO verb_identity_key (label) VALUES ('lambda'), ('mu');
ALTER TABLE verb_identity_key ENABLE ROW LEVEL SECURITY;
CREATE POLICY verb_identity_key_sel ON verb_identity_key FOR SELECT TO anon USING (true);
CREATE POLICY verb_identity_key_upd ON verb_identity_key FOR UPDATE TO anon USING (true) WITH CHECK (true);

GRANT SELECT, INSERT, UPDATE, DELETE ON
  verb_update_open, verb_read_only, verb_delete_open, verb_all_open,
  verb_update_noinsert, verb_identity_key TO anon;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon;
