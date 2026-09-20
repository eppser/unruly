-- Roles and schema GoTrue expects to exist before its own migrations run.
--
-- Named 00_ so it runs first: PostgREST's roles are created later and the auth
-- admin has to exist before the auth container starts, or its migrations fail
-- and the container restarts forever with nothing in the log that names the
-- cause.
CREATE ROLE supabase_auth_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION
  PASSWORD 'fixture';
CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION supabase_auth_admin;
GRANT CREATE ON DATABASE fixture TO supabase_auth_admin;
ALTER USER supabase_auth_admin SET search_path = 'auth';
