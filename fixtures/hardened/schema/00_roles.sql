CREATE ROLE anon NOLOGIN NOINHERIT;
CREATE ROLE authenticated NOLOGIN NOINHERIT;
CREATE ROLE authenticator LOGIN NOINHERIT PASSWORD 'fixture';
GRANT anon, authenticated TO authenticator;
