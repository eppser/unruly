-- Project 03: every table has RLS ENABLED. Only the POLICY differs.
--
-- The experimental design is the point of the file. Project 01 holds RLS off
-- and varies GRANTs. This one holds the GRANTs constant --
-- SELECT, INSERT, UPDATE, DELETE to both anon and authenticated on every
-- table, applied once at the bottom -- and enables RLS on every table, so any
-- difference in outcome between two relations here is attributable to the
-- policy and to nothing else. There is no privilege confound to argue about.
--
-- The claim this project tests is that `relrowsecurity = true` carries almost
-- no information. Eight tables below all report RLS enabled. One is wide open
-- to all four verbs, one is readable only, one is writable only, one is
-- erasable only, one is invisible to anon and public to any account, and two
-- are genuinely closed. A scanner whose RLS check is "is the bit set" scores
-- the same on all eight.
--
-- Sensitive-looking content is deliberately spread across BOTH the exposed and
-- the closed tables, so content cannot be used as a shortcut for exposure.

-- ---------------------------------------------------------------------------
-- 1. rls_no_policy -- RLS on, zero policies.
--
-- The precision case. Postgres's default with RLS enabled and no policy is
-- deny-all, so a SELECT returns zero rows rather than an error: HTTP 200 and
-- an empty array. Reporting this table is a false positive.
--
-- Note what this does to a DELETE probe that sends a filter matching nothing:
-- this table answers 204 for the same reason a wide-open one does. That is why
-- every write claim in the answer key is measured against a marker row that
-- provably exists.
-- ---------------------------------------------------------------------------
CREATE TABLE public.rls_no_policy (
  id            bigserial PRIMARY KEY,
  account_email text NOT NULL,
  api_key       text NOT NULL
);
INSERT INTO public.rls_no_policy (account_email, api_key)
SELECT 'locked' || i || '@example.invalid', 'sk_live_locked_' || lpad(i::text, 4, '0')
FROM generate_series(1, 5) AS i;
ALTER TABLE public.rls_no_policy ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- 2. policy_for_all_true -- FOR ALL USING (true) WITH CHECK (true).
--
-- The configured-looking, completely open case, and the most common way a
-- table ends up public while its owner believes it is protected. `FOR ALL`
-- reads in English as "for all rows"; in Postgres it means for all four
-- commands. One policy line hands out SELECT, INSERT, UPDATE and DELETE.
--
-- USING (true) supplies the read/modify predicate, WITH CHECK (true) the
-- write predicate. Both are spelled out here: with USING alone, Postgres
-- copies the USING expression into the WITH CHECK slot, which is another way
-- the same surprise arrives.
-- ---------------------------------------------------------------------------
CREATE TABLE public.policy_for_all_true (
  id           bigserial PRIMARY KEY,
  full_name    text NOT NULL,
  email        text NOT NULL,
  phone_number text
);
INSERT INTO public.policy_for_all_true (full_name, email, phone_number)
SELECT 'Open Record ' || i, 'open' || i || '@example.invalid',
       '+1-555-02' || lpad(i::text, 2, '0')
FROM generate_series(1, 7) AS i;
ALTER TABLE public.policy_for_all_true ENABLE ROW LEVEL SECURITY;
CREATE POLICY for_all_true ON public.policy_for_all_true
  FOR ALL USING (true) WITH CHECK (true);

-- ---------------------------------------------------------------------------
-- 3. policy_select_true_only -- FOR SELECT USING (true), and nothing else.
--
-- Paired with the table above, this is what proves a scanner is reading more
-- than `relrowsecurity`. Both tables have RLS enabled and identical GRANTs;
-- this one is readable and refuses all three write verbs, and the difference
-- is one keyword.
-- ---------------------------------------------------------------------------
CREATE TABLE public.policy_select_true_only (
  id       bigserial PRIMARY KEY,
  email    text NOT NULL,
  iban     text
);
INSERT INTO public.policy_select_true_only (email, iban) VALUES
  ('reader1@example.invalid', 'DE89370400440532013000'),
  ('reader2@example.invalid', 'GB82WEST12345698765432'),
  ('reader3@example.invalid', 'FR1420041010050500013M02606'),
  ('reader4@example.invalid', 'NL91ABNA0417164300'),
  ('reader5@example.invalid', NULL);
ALTER TABLE public.policy_select_true_only ENABLE ROW LEVEL SECURITY;
CREATE POLICY select_true ON public.policy_select_true_only
  FOR SELECT USING (true);

-- ---------------------------------------------------------------------------
-- 4. policy_insert_only -- FOR INSERT WITH CHECK (true), and nothing else.
--
-- The public submission form: a contact form, a waitlist, a bug report. Reads
-- return an empty array, so a read-only scanner records the table as safe,
-- while an anonymous caller can append rows without limit.
--
-- is_admin exists to make the second half of that concrete. Nothing in the
-- policy constrains WHICH columns an anonymous INSERT may set, so a stranger
-- can post {"message":"x","is_admin":true} and the row lands with the flag on.
-- A WITH CHECK of (true) is a check on nothing.
-- ---------------------------------------------------------------------------
CREATE TABLE public.policy_insert_only (
  id           bigserial PRIMARY KEY,
  submitted_by text,
  message      text NOT NULL,
  is_admin     boolean NOT NULL DEFAULT false,
  created_at   timestamptz NOT NULL DEFAULT now()
);
INSERT INTO public.policy_insert_only (submitted_by, message) VALUES
  ('seed1@example.invalid', 'seeded submission 1'),
  ('seed2@example.invalid', 'seeded submission 2'),
  ('seed3@example.invalid', 'seeded submission 3');
ALTER TABLE public.policy_insert_only ENABLE ROW LEVEL SECURITY;
CREATE POLICY insert_only ON public.policy_insert_only
  FOR INSERT WITH CHECK (true);

-- ---------------------------------------------------------------------------
-- 5. policy_delete_only -- FOR DELETE USING (true), and nothing else.
--
-- Erasable by a stranger and invisible to every read probe. This is the shape
-- with the worst ratio of impact to detectability in the corpus: a scanner
-- that will not send a destructive verb cannot see it at all, and the only
-- non-destructive evidence is the policy catalogue, which requires the
-- database rather than the API.
-- ---------------------------------------------------------------------------
CREATE TABLE public.policy_delete_only (
  id           bigserial PRIMARY KEY,
  invoice_no   text NOT NULL,
  amount_cents bigint NOT NULL
);
INSERT INTO public.policy_delete_only (invoice_no, amount_cents)
SELECT 'INV-2026-' || lpad(i::text, 4, '0'), i * 1000
FROM generate_series(1, 6) AS i;
ALTER TABLE public.policy_delete_only ENABLE ROW LEVEL SECURITY;
CREATE POLICY delete_only ON public.policy_delete_only
  FOR DELETE USING (true);

-- ---------------------------------------------------------------------------
-- 6. policy_authenticated_true -- FOR SELECT TO authenticated USING (true).
--
-- Invisible to anon, fully readable by ANY logged-in user -- not by the user
-- the row belongs to, by anybody holding a token with role=authenticated. Its
-- real exposure therefore depends on a setting that lives in GoTrue and not in
-- Postgres, which is why project 04 exists.
--
-- Seeded with content worth reading, so that "anon sees nothing" is not
-- mistaken for "nothing to see".
-- ---------------------------------------------------------------------------
CREATE TABLE public.policy_authenticated_true (
  id            bigserial PRIMARY KEY,
  full_name     text NOT NULL,
  home_address  text NOT NULL,
  phone_number  text NOT NULL,
  date_of_birth date
);
INSERT INTO public.policy_authenticated_true (full_name, home_address, phone_number, date_of_birth) VALUES
  ('Dana Whitfield',    '12 Fictional Street, Nowhere',  '+1-555-0301', '1984-03-11'),
  ('Marcus Oyelaran',   '48 Invented Road, Nowhere',     '+1-555-0302', '1979-11-02'),
  ('Priya Raghunathan', '3 Imaginary Lane, Nowhere',     '+1-555-0303', '1991-06-27'),
  ('Tomas Berg',        '77 Notional Avenue, Nowhere',   '+1-555-0304', '1988-01-19');
ALTER TABLE public.policy_authenticated_true ENABLE ROW LEVEL SECURITY;
CREATE POLICY authenticated_true ON public.policy_authenticated_true
  FOR SELECT TO authenticated USING (true);

-- ---------------------------------------------------------------------------
-- 7. policy_owner_scoped -- the correct per-user policy.
--
-- The control that keeps table 6's finding from being vacuous. Same TO
-- authenticated, same RLS bit, same GRANTs; the USING clause compares the row
-- owner against the `sub` claim, so a logged-in user sees only their own rows
-- and elevating from anon to a fresh account gains an attacker nothing.
--
-- Rows are seeded for THREE owners: the corpus's first authenticated identity
-- (2222...), its second (3333...), and a third that no token in the corpus
-- carries. The same request therefore returns a different row count depending
-- only on which token is presented, which is the property being asserted.
--
-- current_setting(..., true) -- the second argument is missing_ok. Without it,
-- an anon request (which sets no claims GUC at all) raises 42704 rather than
-- returning NULL, and the table answers 500 instead of an empty array.
-- ---------------------------------------------------------------------------
CREATE TABLE public.policy_owner_scoped (
  id       bigserial PRIMARY KEY,
  owner_id uuid NOT NULL,
  note     text NOT NULL
);
INSERT INTO public.policy_owner_scoped (owner_id, note) VALUES
  ('22222222-2222-2222-2222-222222222222', 'identity A note 1'),
  ('22222222-2222-2222-2222-222222222222', 'identity A note 2'),
  ('22222222-2222-2222-2222-222222222222', 'identity A note 3'),
  ('33333333-3333-3333-3333-333333333333', 'identity B note 1'),
  ('44444444-4444-4444-4444-444444444444', 'identity C note 1'),
  ('44444444-4444-4444-4444-444444444444', 'identity C note 2');
ALTER TABLE public.policy_owner_scoped ENABLE ROW LEVEL SECURITY;
CREATE POLICY owner_scoped ON public.policy_owner_scoped
  FOR SELECT TO authenticated
  USING (owner_id::text = current_setting('request.jwt.claims', true)::json->>'sub');

-- ---------------------------------------------------------------------------
-- 8. policy_restrictive_mix -- one PERMISSIVE policy AND one RESTRICTIVE one.
--
-- The case where reading each policy on its own gives the wrong answer.
-- Permissive policies are OR-ed together; restrictive policies are AND-ed over
-- the result. So `FOR SELECT USING (true)` read alone says "world readable",
-- and the restrictive policy beside it -- which compares the row's tenant
-- against a `tenant` claim that no token in this corpus carries, yielding NULL
-- and therefore not-true -- turns the conjunction into deny-all.
--
-- Both anon and authenticated see zero rows. Reporting this table because one
-- of its policies is USING (true) is a false positive.
-- ---------------------------------------------------------------------------
CREATE TABLE public.policy_restrictive_mix (
  id          bigserial PRIMARY KEY,
  tenant_id   int NOT NULL,
  customer    text NOT NULL,
  card_number text
);
INSERT INTO public.policy_restrictive_mix (tenant_id, customer, card_number) VALUES
  (1, 'tenant1@example.invalid',  '4111111111111111'),
  (1, 'tenant1b@example.invalid', '5555555555554444'),
  (2, 'tenant2@example.invalid',  '378282246310005'),
  (3, 'tenant3@example.invalid',  '6011111111111117');
ALTER TABLE public.policy_restrictive_mix ENABLE ROW LEVEL SECURITY;
CREATE POLICY permissive_all ON public.policy_restrictive_mix
  AS PERMISSIVE FOR SELECT USING (true);
CREATE POLICY restrictive_tenant ON public.policy_restrictive_mix
  AS RESTRICTIVE FOR SELECT
  USING (tenant_id::text = current_setting('request.jwt.claims', true)::json->>'tenant');

-- ---------------------------------------------------------------------------
-- Privileges, applied ONCE and identically to every table above.
--
-- This is the experimental control. If any table held a different grant from
-- any other, no difference in outcome could be attributed to the policy.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO anon, authenticated;
-- Sequences too, or an INSERT that relies on a bigserial default fails with
-- 42501 on the SEQUENCE rather than on the table. From outside the two are
-- indistinguishable, and the answer key would be wrong for a reason no HTTP
-- response explains.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
