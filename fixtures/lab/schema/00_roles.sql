-- PostgREST role model, mirroring the managed product: `authenticator` logs in
-- and switches to `anon` or `authenticated` per request.
CREATE ROLE anon NOLOGIN NOINHERIT;
CREATE ROLE authenticated NOLOGIN NOINHERIT;
CREATE ROLE authenticator LOGIN NOINHERIT PASSWORD 'fixture';
GRANT anon, authenticated TO authenticator;
