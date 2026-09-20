-- A relation anyone may write to and nobody may read.
--
-- This is not exotic: it is every "submit a form, you cannot see other
-- people's submissions" table -- contact forms, waitlists, feedback, abuse
-- reports. The grant shape is INSERT without SELECT.
--
-- It is here because the scanner got it WRONG, and the error was in the
-- direction that matters. The INSERT probe asks for the row back
-- (Prefer: return=representation) so a landed row can be deleted again.
-- Building that response needs SELECT, so PostgREST answers 401 with SQLSTATE
-- 42501 -- the code this scanner maps to "row-level security blocked it".
--
-- Measured against this table on PostgREST v14.3:
--
--   Prefer: return=representation  ->  401 42501, 0 rows created
--   Prefer: return=minimal         ->  201,       1 row  created
--
-- So the relation IS writable by anon, and the scan reported it protected. A
-- false negative on a table that accepts anonymous writes is the exact failure
-- this project exists to refuse.
CREATE TABLE insert_no_select (
  id   serial PRIMARY KEY,
  note text
);
ALTER TABLE insert_no_select ENABLE ROW LEVEL SECURITY;
CREATE POLICY ins ON insert_no_select FOR INSERT TO anon WITH CHECK (true);
-- INSERT only. No SELECT, at either the privilege or the policy level.
GRANT INSERT ON insert_no_select TO anon;
GRANT USAGE, SELECT ON SEQUENCE insert_no_select_id_seq TO anon;
