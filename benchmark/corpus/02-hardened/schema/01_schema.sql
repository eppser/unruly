-- Project 02: the precision anchor. Everything here is configured correctly.
--
-- The correct scan result for this target is NOTHING, and the target still has
-- to be worth scanning -- five relations, a REST mount, an auth service and a
-- storage mount, all reachable, all answering. A precision control made of an
-- empty database would measure nothing: any scanner reports nothing about a
-- target with no tables.
--
-- So each relation below is locked by a DIFFERENT mechanism, because the ways
-- a scanner can be wrong about "protected" are not interchangeable:
--
--   member_notes     RLS + a correct per-user policy      -> anon 0 rows,
--                                                            owner sees own
--   support_tickets  RLS + per-user policy on all verbs   -> anon 0 rows
--   rls_locked       RLS enabled, no policy at all        -> anon 0 rows
--   billing_internal REVOKE -- no grant for anon at all   -> anon 401 42501
--   public_pages     public BY DESIGN                     -> anon reads it,
--                                                            and that is right
--
-- public_pages is the trap. It is world-readable, it is meant to be, and its
-- content is marketing copy. Reporting it is a false positive, and it is the
-- one relation here a naive "anon can read this table" rule will fire on.

-- ---------------------------------------------------------------------------
-- member_notes: RLS with a correct per-user policy.
--
-- Rows are seeded for the corpus's first authenticated identity (2222...) and
-- for two identities no token in the corpus carries. The first identity's
-- token therefore returns exactly its own two rows and nothing else, which is
-- the behaviour a scanner must NOT call an escalation: the account gained
-- access to its own data, which is what an account is for.
-- ---------------------------------------------------------------------------
CREATE TABLE public.member_notes (
  id         bigserial PRIMARY KEY,
  owner_id   uuid NOT NULL DEFAULT auth.request_sub(),
  title      text NOT NULL,
  body       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.member_notes (owner_id, title, body) VALUES
  ('22222222-2222-2222-2222-222222222222', 'Renewal reminder', 'Plan renews in March.'),
  ('22222222-2222-2222-2222-222222222222', 'Shipping address', '12 Fictional Street, Nowhere.'),
  ('55555555-5555-5555-5555-555555555555', 'Card on file',     'Ends 4444, expires 04/28.'),
  ('55555555-5555-5555-5555-555555555555', 'Support thread',   'Refund issued 2026-02-11.'),
  ('66666666-6666-6666-6666-666666666666', 'Password reset',   'Reset link sent 2026-01-30.');
ALTER TABLE public.member_notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY member_notes_own_rows ON public.member_notes
  FOR ALL TO authenticated
  USING (owner_id = auth.request_sub())
  WITH CHECK (owner_id = auth.request_sub());

-- ---------------------------------------------------------------------------
-- support_tickets: the same shape, applied to a table users are meant to WRITE
-- to. The WITH CHECK is what stops an authenticated caller from filing a
-- ticket in somebody else's name, and it is the half people leave off.
-- ---------------------------------------------------------------------------
CREATE TABLE public.support_tickets (
  id         bigserial PRIMARY KEY,
  owner_id   uuid NOT NULL DEFAULT auth.request_sub(),
  subject    text NOT NULL,
  status     text NOT NULL DEFAULT 'open',
  opened_at  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.support_tickets (owner_id, subject, status) VALUES
  ('22222222-2222-2222-2222-222222222222', 'Cannot export data', 'open'),
  ('55555555-5555-5555-5555-555555555555', 'Duplicate charge',   'closed'),
  ('66666666-6666-6666-6666-666666666666', 'Login loop',         'open');
ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;
CREATE POLICY support_tickets_own_rows ON public.support_tickets
  FOR ALL TO authenticated
  USING (owner_id = auth.request_sub())
  WITH CHECK (owner_id = auth.request_sub());

-- ---------------------------------------------------------------------------
-- rls_locked: RLS enabled and no policy at all. Postgres's default is
-- deny-all, so this answers 200 with an empty array rather than an error.
--
-- Holding secrets deliberately. A scanner that ranks by content wants to
-- report this; nothing is reachable through any verb by any role in this
-- project.
-- ---------------------------------------------------------------------------
CREATE TABLE public.rls_locked (
  id     bigserial PRIMARY KEY,
  name   text NOT NULL,
  value  text NOT NULL
);
INSERT INTO public.rls_locked (name, value) VALUES
  ('stripe_secret_key', 'sk_test_00000000000000000000000000'),
  ('smtp_password',     'not-a-real-password'),
  ('webhook_signing',   'whsec_0000000000000000000000000000');
ALTER TABLE public.rls_locked ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- billing_internal: protected by REVOKE. No grant for anon or authenticated,
-- so Postgres refuses at the privilege layer and PostgREST turns 42501 into
-- 401. RLS is not enabled on it, which is the point: a scanner reasoning
-- "RLS disabled means exposed" reports this table, and it is not exposed.
--
-- It is also the one relation in this project that is DISCOVERABLE but not
-- readable -- the 401 body names it while the OpenAPI document omits it.
-- ---------------------------------------------------------------------------
CREATE TABLE public.billing_internal (
  id            bigserial PRIMARY KEY,
  customer      text NOT NULL,
  card_number   text NOT NULL,
  iban          text,
  amount_cents  bigint NOT NULL
);
INSERT INTO public.billing_internal (customer, card_number, iban, amount_cents) VALUES
  ('customer1@example.invalid', '4111111111111111', 'DE89370400440532013000', 4900),
  ('customer2@example.invalid', '5555555555554444', 'GB82WEST12345698765432', 9900),
  ('customer3@example.invalid', '378282246310005',  'NL91ABNA0417164300',    19900);

-- ---------------------------------------------------------------------------
-- public_pages: PUBLIC ON PURPOSE. This is the trap.
--
-- Marketing copy for a website that renders it client-side straight out of
-- PostgREST. It is world-readable by design, RLS is enabled and carries an
-- explicit `FOR SELECT USING (true)` so the intent is written down rather than
-- implied, and only SELECT is granted so nobody can edit the site.
--
-- Column names and content are unambiguously non-sensitive: slug, headline,
-- body_markdown, published_at. No email, no name, no identifier, nothing that
-- would let a content-based heuristic call this a leak.
--
-- A scanner that reports this relation has produced a false positive, and it
-- is the single most likely false positive in the corpus, because the crude
-- rule "anon received rows from a table" fires on it.
-- ---------------------------------------------------------------------------
CREATE TABLE public.public_pages (
  id            bigserial PRIMARY KEY,
  slug          text NOT NULL UNIQUE,
  headline      text NOT NULL,
  body_markdown text NOT NULL,
  published_at  date NOT NULL
);
INSERT INTO public.public_pages (slug, headline, body_markdown, published_at) VALUES
  ('pricing',  'Simple pricing that scales with you',
   'Three plans. No setup fee. Cancel at any time.', '2026-01-05'),
  ('security', 'How we think about security',
   'Encryption in transit and at rest. Annual third-party review.', '2026-01-19'),
  ('changelog', 'What shipped in February',
   'Faster exports, a dark theme, and two fewer clicks to invite a teammate.', '2026-03-02'),
  ('about',    'Why we built this',
   'We were tired of spreadsheets. So were our first ten customers.', '2025-11-11');
ALTER TABLE public.public_pages ENABLE ROW LEVEL SECURITY;
CREATE POLICY public_pages_readable ON public.public_pages
  FOR SELECT USING (true);

-- ---------------------------------------------------------------------------
-- Privileges.
--
-- USAGE on the schema first, or nothing else matters. Then the grants that
-- make the policies above the thing that decides, rather than the privilege
-- layer accidentally doing the work -- a locked table that is locked twice
-- would not test the policy at all.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO anon, authenticated;

-- Full CRUD grants on the RLS-protected tables, so that the POLICY is the only
-- thing standing between anon and the rows. If these were revoked as well, the
-- policies below would never be reached and this project would prove nothing
-- about them.
GRANT SELECT, INSERT, UPDATE, DELETE ON public.member_notes    TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.support_tickets TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.rls_locked      TO anon, authenticated;

-- Read only, and world-readable by design.
GRANT SELECT ON public.public_pages TO anon, authenticated;

-- billing_internal: intentionally nothing. Not to anon, not to authenticated.

GRANT USAGE, SELECT ON SEQUENCE public.member_notes_id_seq    TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE public.support_tickets_id_seq TO anon, authenticated;
GRANT USAGE, SELECT ON SEQUENCE public.rls_locked_id_seq      TO anon, authenticated;
-- Deliberately NOT public_pages_id_seq or billing_internal_id_seq: no role is
-- meant to insert into either, and a sequence grant is a quiet way to make an
-- INSERT refusal come from the wrong layer.
