-- The role a leaked service_role key actually becomes.
--
-- The site fixture ships a service_role JWT to the browser, which is the
-- worst real-world Supabase misconfiguration and this tool's clearest
-- critical. Until now the fixture modelled only half of it: the key existed
-- and the scanner reported it by decoding the role claim in its payload --
-- which says what the credential CLAIMS to be, not what it opens. PostgREST
-- answered a request carrying it with
--
--   {"code":"22023","message":"role \"service_role\" does not exist"}
--
-- so the one thing the finding asserts -- that a stranger who takes this key
-- out of the page can read everything -- could not be demonstrated here.
--
-- BYPASSRLS is what the managed product gives this role, and it is the whole
-- point: no policy applies to it, so remediating a table does nothing about a
-- key that has already been published. That is why the finding's remediation
-- says rotate rather than fix.
CREATE ROLE service_role NOLOGIN BYPASSRLS;
GRANT service_role TO authenticator;

GRANT USAGE ON SCHEMA public, reporting TO service_role;
GRANT ALL ON ALL TABLES IN SCHEMA public, reporting TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public, reporting TO service_role;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public, reporting TO service_role;
