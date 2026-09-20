-- PostgREST role model, shared by every corpus project that runs a database.
--
-- Mounted read-only into each stack's initdb directory rather than copied, so
-- the projects cannot drift apart on the one thing they must agree on:
-- `authenticator` logs in and SET ROLEs to `anon` or `authenticated` per
-- request, exactly as the managed product does.
--
-- NOINHERIT matters. Without it `authenticator` would hold the union of both
-- roles' privileges directly and every project in the corpus would read as
-- more exposed than its DDL says.
CREATE ROLE anon NOLOGIN NOINHERIT;
CREATE ROLE authenticated NOLOGIN NOINHERIT;
CREATE ROLE authenticator LOGIN NOINHERIT PASSWORD 'fixture';
GRANT anon, authenticated TO authenticator;
