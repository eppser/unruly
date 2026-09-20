-- Project 11, schema 3 of 4: `legacy`, the schema nobody remembered to remove.
--
-- This is the finding. legacy.users is the pre-migration copy of the user
-- table: RLS never enabled, full CRUD granted to anon, and it still holds the
-- bcrypt hashes and email addresses that public.users was reshaped to protect.
-- It is reachable at exactly the same URL as the safe one — GET /users — and
-- differs only by the header `Accept-Profile: legacy`.
--
-- The hashes are bcrypt-shaped but hash the string 'not-a-real-password' and
-- are not usable anywhere. The reset tokens are fixed hex strings.

CREATE SCHEMA legacy;

CREATE TABLE legacy.users (
  id             bigserial PRIMARY KEY,
  email          text NOT NULL,
  password_hash  text NOT NULL,
  reset_token    text,
  is_admin       boolean NOT NULL DEFAULT false
);

INSERT INTO legacy.users (email, password_hash, reset_token, is_admin) VALUES
  ('dana@example.invalid',   '$2b$12$K8h5vQZ0000000000000uOe1JmQ0000000000000000000000', 'a1b2c3d4e5f60718', false),
  ('marcus@example.invalid', '$2b$12$L9i6wR1A111111111111vPf2KnR1111111111111111111111', 'b2c3d4e5f6071829', false),
  ('priya@example.invalid',  '$2b$12$M0j7xS2B222222222222wQg3LoS2222222222222222222222', NULL, false),
  ('tomas@example.invalid',  '$2b$12$N1k8yT3C333333333333xRh4MpT3333333333333333333333', NULL, false),
  ('elena@example.invalid',  '$2b$12$O2l9zU4D444444444444ySi5NqU4444444444444444444444', 'c3d4e5f607182930', false),
  ('root@example.invalid',   '$2b$12$P3m0aV5E555555555555zTj6OrV5555555555555555555555', NULL, true);

-- ---------------------------------------------------------------------------
-- sessions: exists ONLY in `legacy`.
-- ---------------------------------------------------------------------------
CREATE TABLE legacy.sessions (
  id           bigserial PRIMARY KEY,
  user_email   text NOT NULL,
  session_token text NOT NULL,
  expires_at   timestamptz NOT NULL
);

INSERT INTO legacy.sessions (user_email, session_token, expires_at) VALUES
  ('dana@example.invalid',   'sess_00000000000000000000000001', now() + interval '7 days'),
  ('marcus@example.invalid', 'sess_00000000000000000000000002', now() + interval '7 days'),
  ('root@example.invalid',   'sess_00000000000000000000000003', now() + interval '7 days');

GRANT USAGE ON SCHEMA legacy TO anon, authenticated;
-- Full CRUD, because the retired application's service account was `anon` and
-- nobody narrowed it when the schema was renamed out of the way.
GRANT SELECT, INSERT, UPDATE, DELETE ON legacy.users    TO anon, authenticated;
GRANT SELECT                         ON legacy.sessions TO anon, authenticated;
-- Sequence usage, or an INSERT relying on the bigserial default fails with
-- 42501 on the SEQUENCE rather than the table, which looks identical from the
-- outside and would make the answer key wrong for a reason no HTTP response
-- explains.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA legacy TO anon, authenticated;
