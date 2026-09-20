-- A routine that runs caller-supplied SQL.
--
-- This is the shape behind "can an anonymous user drop my database". DDL is not
-- expressible through PostgREST -- there is no endpoint for DROP -- so the only
-- route to it is a function that takes SQL as an argument and executes it. They
-- exist in real projects: people add exec_sql, run_sql or query helpers for a
-- migration or an admin page, mark them SECURITY DEFINER so they work, and
-- grant EXECUTE to anon because that is what makes the call succeed from the
-- browser.
--
-- SECURITY DEFINER means it runs as the OWNER. Whatever the owner may do, the
-- caller may now do, which on a Supabase project includes DROP TABLE and
-- DROP DATABASE.
--
-- The scanner must never send DDL to establish this. It sends SELECT 1 over
-- GET, which PostgREST runs inside a read-only transaction, so even a
-- destructive argument could not commit. Executing SELECT 1 as the owner is
-- already the whole finding: what follows is the caller's choice, not a
-- capability question.

CREATE OR REPLACE FUNCTION exec_sql(query text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  result jsonb;
BEGIN
  EXECUTE 'SELECT coalesce(jsonb_agg(t), ''[]''::jsonb) FROM (' || query || ') t'
    INTO result;
  RETURN result;
END;
$$;
GRANT EXECUTE ON FUNCTION exec_sql(text) TO anon;

-- The negative control: same shape, same name family, but EXECUTE was never
-- granted to anon. A scanner that reports this one is guessing from the name.
CREATE OR REPLACE FUNCTION run_sql(query text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN to_jsonb(query);
END;
$$;
REVOKE ALL ON FUNCTION run_sql(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION run_sql(text) FROM anon;
