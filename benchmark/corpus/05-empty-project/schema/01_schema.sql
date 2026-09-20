-- Project 05: a project with nothing in it.
--
-- The exposed schema (`public`) contains ZERO relations. Not zero readable
-- relations -- zero relations. `anon` holds USAGE on the schema and nothing
-- else, because a schema with no USAGE would be a different target: PostgREST
-- would fail to introspect and the host would answer 500, which is
-- "unmeasurable", not "empty". Empty and reachable is the case being modelled.
--
-- The second half of the project is the schema `internal`. It exists, it holds
-- three tables with the most guessable names in the corpus (`users`,
-- `profiles`, `payments`), and it is NOT in PGRST_DB_SCHEMAS. So the data is
-- in Postgres and psql can count it, and there is no request an outside caller
-- can make that reaches it.
--
-- The privileges on `internal` are deliberately GENEROUS: `anon` holds USAGE
-- on the schema and SELECT on all three tables. That is the sharp version of
-- the claim. Unreachability here comes from ONE line of PostgREST
-- configuration, not from any GRANT. A scanner that reasons about exposure
-- from catalog privileges -- which is what an operator with database access
-- would naturally do -- gets three findings that are all false from outside.

-- ---------------------------------------------------------------------------
-- public: the exposed schema. USAGE and nothing in it.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO anon, authenticated;

-- ---------------------------------------------------------------------------
-- internal: real tables, real rows, not exposed.
-- ---------------------------------------------------------------------------
CREATE SCHEMA internal;

CREATE TABLE internal.users (
  id        bigserial PRIMARY KEY,
  email     text NOT NULL,
  full_name text NOT NULL
);

INSERT INTO internal.users (email, full_name)
SELECT 'user' || i || '@example.invalid', 'Internal User ' || i
FROM generate_series(1, 14) AS i;

CREATE TABLE internal.profiles (
  id       bigserial PRIMARY KEY,
  user_id  bigint REFERENCES internal.users(id),
  bio      text,
  phone    text
);

INSERT INTO internal.profiles (user_id, bio, phone)
SELECT i, 'profile blurb ' || i, '+1-555-02' || lpad(i::text, 2, '0')
FROM generate_series(1, 9) AS i;

CREATE TABLE internal.payments (
  id            bigserial PRIMARY KEY,
  user_id       bigint REFERENCES internal.users(id),
  amount_cents  bigint NOT NULL,
  card_last4    text
);

INSERT INTO internal.payments (user_id, amount_cents, card_last4)
SELECT i, i * 1250, lpad(((i * 7) % 10000)::text, 4, '0')
FROM generate_series(1, 7) AS i;

-- Generous on purpose. See the header: the ONLY thing keeping these tables
-- off the API is PGRST_DB_SCHEMAS.
GRANT USAGE ON SCHEMA internal TO anon, authenticated;
GRANT SELECT ON ALL TABLES IN SCHEMA internal TO anon, authenticated;
