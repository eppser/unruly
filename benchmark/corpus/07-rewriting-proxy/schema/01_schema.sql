-- Project 07: a real database behind a proxy that destroys PostgREST's error
-- semantics.
--
-- The database itself is ordinary and carries all four cases a scanner has to
-- tell apart:
--
--   readable          GRANT SELECT to anon. 200/206 with rows.
--   REVOKE-protected  no grant at all. PostgREST would answer 401/42501.
--   RLS on, no policy GRANT SELECT, RLS enabled, zero policies. PostgREST
--                     answers 200 with an EMPTY array.
--   nonexistent       PostgREST would answer 404/PGRST205.
--
-- Through the proxy, cases 2 and 4 become the same 403. Case 3 does not,
-- because it is a 2xx and the proxy only rewrites 4xx. That asymmetry is the
-- measurement, and it is the reason all three protected shapes are present
-- rather than just one.

-- ---------------------------------------------------------------------------
-- press_releases: readable, dull. The baseline that proves reads work at all
-- through the prefix, so a failure elsewhere cannot be blamed on the proxy.
-- ---------------------------------------------------------------------------
CREATE TABLE public.press_releases (
  id           bigserial PRIMARY KEY,
  headline     text NOT NULL,
  published_on date NOT NULL,
  body         text
);

INSERT INTO public.press_releases (headline, published_on, body)
SELECT 'Quarterly update ' || i,
       DATE '2025-01-01' + (i * 17),
       'Boilerplate paragraph ' || i || '. Nothing confidential here.'
FROM generate_series(1, 12) AS i;

-- ---------------------------------------------------------------------------
-- support_tickets: readable, and worth finding.
--
-- The point of putting real content behind the rewriting proxy is that the
-- readable half of the target is NOT degraded by it. 200s pass through
-- untouched, so everything an operator would want reported is still fully
-- reportable; only the negative space is destroyed. A scanner that gives up on
-- this target because the error codes are gone misses 18 rows of reporter
-- email addresses, phone numbers and internal notes that are one anonymous GET
-- away.
-- ---------------------------------------------------------------------------
CREATE TABLE public.support_tickets (
  id             bigserial PRIMARY KEY,
  reporter_email text NOT NULL,
  reporter_phone text,
  subject        text NOT NULL,
  body           text,
  internal_note  text
);

INSERT INTO public.support_tickets (reporter_email, reporter_phone, subject, body, internal_note)
SELECT 'reporter' || i || '@example.invalid',
       '+1-555-03' || lpad(i::text, 2, '0'),
       (ARRAY['cannot log in','refund request','data export','account merge',
              'password reset','billing dispute'])[1 + (i % 6)],
       'Customer reports the issue recurring since last week. Ticket ' || i || '.',
       'Escalated. Customer is on the legacy plan, do not quote the new price.'
FROM generate_series(1, 18) AS i;

-- ---------------------------------------------------------------------------
-- billing_accounts: no grants at all.
--
-- Behind a bare PostgREST this answers 401 with SQLSTATE 42501 and NAMES
-- itself in the message, which is what makes it discoverable in project 01.
-- Behind this proxy it answers 403 with a fixed body that names nothing.
-- ---------------------------------------------------------------------------
CREATE TABLE public.billing_accounts (
  id            bigserial PRIMARY KEY,
  account_email text NOT NULL,
  plan          text NOT NULL,
  card_last4    text,
  balance_cents bigint NOT NULL DEFAULT 0
);

INSERT INTO public.billing_accounts (account_email, plan, card_last4, balance_cents) VALUES
  ('acct1@example.invalid', 'legacy',     '4242', 129900),
  ('acct2@example.invalid', 'enterprise', '4444',  50000),
  ('acct3@example.invalid', 'starter',    '0005',      0),
  ('acct4@example.invalid', 'enterprise', '1117', 998700),
  ('acct5@example.invalid', 'legacy',     '3007',  20450);

-- ---------------------------------------------------------------------------
-- session_tokens: RLS enabled, zero policies, SELECT granted.
--
-- The third shape, and the one the proxy cannot hide. Postgres does not
-- refuse: it filters, so the query succeeds and returns no rows, PostgREST
-- answers 2xx, and a proxy configured to rewrite 4xx never sees it. The
-- relation therefore stays DISCOVERABLE through the proxy while the
-- REVOKE-protected one does not.
-- ---------------------------------------------------------------------------
CREATE TABLE public.session_tokens (
  id          bigserial PRIMARY KEY,
  user_id     bigint NOT NULL,
  token       text NOT NULL,
  expires_at  timestamptz NOT NULL
);

INSERT INTO public.session_tokens (user_id, token, expires_at)
SELECT i, 'sess_' || lpad(i::text, 6, '0') || '_not_a_real_token', now() + (i || ' hours')::interval
FROM generate_series(1, 8) AS i;

ALTER TABLE public.session_tokens ENABLE ROW LEVEL SECURITY;
-- No policy. Deliberately: with RLS on and no policy, every row is filtered
-- out for a non-owner role, which is a SUCCESSFUL query returning zero rows.

-- ---------------------------------------------------------------------------
-- Privileges.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO anon, authenticated;

GRANT SELECT ON public.press_releases  TO anon, authenticated;
GRANT SELECT ON public.support_tickets TO anon, authenticated;
GRANT SELECT ON public.session_tokens  TO anon, authenticated;
-- billing_accounts: intentionally nothing.
