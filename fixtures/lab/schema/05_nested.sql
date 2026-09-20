-- Personal data inside a json/jsonb column.
--
-- This is how most Supabase applications actually store it. The column is
-- called app_state, preferences, payload or metadata -- names the developer
-- chose, none of them sensitive -- and the framework fills it with a session
-- object carrying an email and an access token.
--
-- The classifier graded only top-level column names, so a table like this was
-- reported HIGH ("a relation is readable") when it should be CRITICAL ("a
-- readable relation carries credentials"). The outer name is chosen by the
-- developer and the sensitive part by the framework, so grading the outer name
-- grades the wrong half.
--
-- Readable by anon on purpose: the point of the fixture is what the classifier
-- makes of rows it can see.

CREATE TABLE nested_payloads (
  id        bigserial PRIMARY KEY,
  label     text NOT NULL,
  -- jsonb: nothing in the name suggests credentials.
  app_state jsonb,
  -- text holding JSON, which is the same disclosure with none of the typing.
  raw       text
);

INSERT INTO nested_payloads (label, app_state, raw) VALUES
  ('session',
   '{"user":{"email":"person@example.invalid","access_token":"sk_live_deadbeefcafe"},"theme":"dark"}',
   '{"payment":{"card_number":"4111111111111111"}}'),
  ('profile',
   '{"user":{"email":"other@example.invalid","access_token":"sk_live_0123456789ab"},"theme":"light"}',
   '{"payment":{"card_number":"4222222222222"}}');

ALTER TABLE nested_payloads ENABLE ROW LEVEL SECURITY;
CREATE POLICY nested_payloads_sel ON nested_payloads FOR SELECT TO anon USING (true);
GRANT SELECT ON nested_payloads TO anon;
