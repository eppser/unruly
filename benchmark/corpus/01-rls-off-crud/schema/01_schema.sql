-- Project 01: RLS never enabled, exposure decided entirely by GRANTs.
--
-- The reason this project exists is the VERB SPLIT. Almost every fixture in
-- this repository and almost every scanner in the wild treats "writable" as
-- one bit, measured with an INSERT. Postgres does not: SELECT, INSERT, UPDATE
-- and DELETE are four independent privileges, and the most damaging of them —
-- DELETE — is the one nobody probes for, because probing it means destroying
-- data on a target you do not own.
--
-- So this schema hands out FOUR different verb combinations with RLS off
-- throughout, and the answer key records each verb separately. A scanner that
-- reports one "write_exposed" bit cannot score better than 50% here, and that
-- is the measurement.
--
-- No RLS is enabled anywhere in this file. That is deliberate: it isolates the
-- privilege axis. Policy shapes are project 03's job.

-- ---------------------------------------------------------------------------
-- customers: the full-CRUD case. SELECT, INSERT, UPDATE and DELETE all open.
-- ---------------------------------------------------------------------------
CREATE TABLE public.customers (
  id            bigserial PRIMARY KEY,
  full_name     text NOT NULL,
  email         text NOT NULL,
  phone_number  text,
  address_line  text,
  signed_up_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.customers (full_name, email, phone_number, address_line)
SELECT
  (ARRAY['Dana Whitfield','Marcus Oyelaran','Priya Raghunathan','Tomas Berg',
         'Elena Marchetti'])[1 + (i % 5)] || ' ' || i,
  'customer' || i || '@example.invalid',
  '+1-555-01' || lpad(i::text, 2, '0'),
  i || ' Fictional Street, Nowhere'
FROM generate_series(1, 25) AS i;

-- ---------------------------------------------------------------------------
-- user_credentials: same privileges, but the CONTENT raises the stakes.
-- Password hashes and API keys, so a scanner that ranks findings by data kind
-- has something to rank. The hashes are bcrypt-shaped but hash the string
-- 'not-a-real-password'; they are not usable anywhere.
-- ---------------------------------------------------------------------------
CREATE TABLE public.user_credentials (
  id             bigserial PRIMARY KEY,
  email          text NOT NULL,
  password_hash  text NOT NULL,
  api_key        text NOT NULL,
  totp_secret    text,
  last_login_at  timestamptz
);

INSERT INTO public.user_credentials (email, password_hash, api_key, totp_secret) VALUES
  ('dana@example.invalid',   '$2b$12$K8h5vQZ0000000000000uOe1JmQ0000000000000000000000', 'sk_live_4f8a2b1c9d0e7f6a5b4c3d2e', 'JBSWY3DPEHPK3PXP'),
  ('marcus@example.invalid', '$2b$12$L9i6wR1A111111111111vPf2KnR1111111111111111111111', 'sk_live_1a2b3c4d5e6f7a8b9c0d1e2f', 'KRSXG5CTMVRXEZLU'),
  ('priya@example.invalid',  '$2b$12$M0j7xS2B222222222222wQg3LoS2222222222222222222222', 'sk_live_9f8e7d6c5b4a3f2e1d0c9b8a', 'MZXW6YTBOI======'),
  ('tomas@example.invalid',  '$2b$12$N1k8yT3C333333333333xRh4MpT3333333333333333333333', 'sk_live_0e1d2c3b4a5f6e7d8c9b0a1f', NULL),
  ('elena@example.invalid',  '$2b$12$O2l9zU4D444444444444ySi5NqU4444444444444444444444', 'sk_live_7c6b5a4f3e2d1c0b9a8f7e6d', NULL),
  ('ops@example.invalid',    '$2b$12$P3m0aV5E555555555555zTj6OrV5555555555555555555555', 'sk_live_2d3e4f5a6b7c8d9e0f1a2b3c', NULL);

-- ---------------------------------------------------------------------------
-- audit_log: SELECT and DELETE, but NOT insert and NOT update.
--
-- This is the shape that motivates the whole project. It is a real pattern —
-- an append-only-by-the-app table whose retention job runs as `anon` because
-- the developer used the anon key in a cron script — and it is invisible to a
-- scanner that measures writability with an INSERT. INSERT is refused here.
-- DELETE wipes the table.
-- ---------------------------------------------------------------------------
CREATE TABLE public.audit_log (
  id          bigserial PRIMARY KEY,
  actor       text NOT NULL,
  action      text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.audit_log (actor, action)
SELECT 'user' || i || '@example.invalid', (ARRAY['login','export','delete','grant'])[1 + (i % 4)]
FROM generate_series(1, 10) AS i;

-- ---------------------------------------------------------------------------
-- payment_methods: SELECT only. Read exposed, every write refused.
--
-- The card numbers are the published test PANs (Visa 4111…, Mastercard 5555…)
-- and the IBANs are the ECBS test values. Nothing here belongs to anybody.
-- ---------------------------------------------------------------------------
CREATE TABLE public.payment_methods (
  id             bigserial PRIMARY KEY,
  customer_id    bigint REFERENCES public.customers(id),
  card_number    text,
  card_expiry    text,
  iban           text,
  billing_email  text
);

INSERT INTO public.payment_methods (customer_id, card_number, card_expiry, iban, billing_email) VALUES
  (1, '4111111111111111', '11/29', 'DE89370400440532013000', 'customer1@example.invalid'),
  (2, '5555555555554444', '04/28', 'GB82WEST12345698765432', 'customer2@example.invalid'),
  (3, '378282246310005',  '09/27', 'FR1420041010050500013M02606', 'customer3@example.invalid'),
  (4, '6011111111111117', '01/30', 'NL91ABNA0417164300', 'customer4@example.invalid');

-- ---------------------------------------------------------------------------
-- internal_settings: no grants at all.
--
-- The precision control. RLS is off here too, so a scanner reasoning from
-- "RLS disabled == exposed" will report it. It is not exposed: `anon` holds no
-- privilege, so Postgres answers 42501 and PostgREST turns that into 401. The
-- table must be DISCOVERED (the 401 names it) and must NOT be reported as
-- readable or writable.
-- ---------------------------------------------------------------------------
CREATE TABLE public.internal_settings (
  key    text PRIMARY KEY,
  value  text NOT NULL
);

INSERT INTO public.internal_settings (key, value) VALUES
  ('stripe_secret_key', 'sk_test_00000000000000000000000000'),
  ('smtp_password', 'not-a-real-password'),
  ('feature_flags', '{"beta":true}');

-- ---------------------------------------------------------------------------
-- Privileges. USAGE on the schema first, or nothing else matters.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO anon, authenticated;

GRANT SELECT, INSERT, UPDATE, DELETE ON public.customers        TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.user_credentials TO anon, authenticated;
GRANT SELECT, DELETE                 ON public.audit_log        TO anon, authenticated;
GRANT SELECT                         ON public.payment_methods  TO anon, authenticated;
-- internal_settings: intentionally nothing.

-- Sequences, so an INSERT that relies on the bigserial default can actually
-- run. Without this an INSERT fails with 42501 on the SEQUENCE rather than the
-- table, which looks identical from the outside and would make the answer key
-- wrong for a reason no HTTP response explains.
-- internal_settings has no sequence: its primary key is text, so there is
-- nothing to revoke here and no way for a sequence grant to soften it.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
