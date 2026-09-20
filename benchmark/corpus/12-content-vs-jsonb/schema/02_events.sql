-- Project 12, part 2 of 2: the two relations that DO matter.
--
-- Neither of them has a suspicious name and neither has a suspicious column.
-- `events` is id / kind / created_at / payload. `settings` is key / value.
-- Every column-name heuristic in existence walks straight past both, and
-- correctly: there is nothing in the identifiers to react to.
--
-- The data is a different matter. Six of the 200 event payloads are the
-- residue of a debug logger that was left serialising whole request bodies,
-- so they contain a bcrypt hash, a card number and a national ID number. One
-- of the fourteen settings rows holds live-shaped provider credentials.
--
-- Finding these requires reading VALUES, and reading enough of them. The first
-- sensitive event is at id 47, so a probe that samples one row — which is what
-- almost every scanner does, this corpus's own checker included — sees a page
-- view and moves on.
--
-- Every secret below is a published test value or a fixed pattern of zeros:
-- 4111111111111111 is the Visa test PAN, AKIAIOSFODNN7EXAMPLE and
-- wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY are AWS's own documentation
-- examples, and the bcrypt hashes hash the string 'not-a-real-password'.

CREATE TABLE public.events (
  id          bigserial PRIMARY KEY,
  kind        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  payload     jsonb NOT NULL
);

-- 200 rows of ordinary product telemetry. Nothing in here is sensitive and
-- nothing in here contains any of the strings the answer key searches for.
INSERT INTO public.events (kind, created_at, payload)
SELECT
  (ARRAY['page_view','click','session_start','api_call','feature_flag'])[1 + (i % 5)],
  timestamptz '2025-09-01 00:00:00+00' + (i || ' minutes')::interval,
  jsonb_build_object(
    'path',       (ARRAY['/','/pricing','/docs','/blog','/changelog'])[1 + (i % 5)],
    'referrer',   (ARRAY['direct','search','newsletter','social'])[1 + (i % 4)],
    'duration_ms', 40 + (i * 7) % 900,
    'variant',    (ARRAY['a','b'])[1 + (i % 2)],
    'seq',        i
  )
FROM generate_series(1, 200) AS i;

-- The six rows the debug logger poisoned. They are UPDATEs rather than a
-- separate INSERT so that the ids are fixed and the ORDER BY id positions in
-- the answer key are stable: 47, 63, 88, 119, 150 and 191 out of 200.
--
-- 47 is the number that matters. It is how many rows have to be read, in id
-- order, before anything sensitive appears at all.
UPDATE public.events SET kind = 'form_submit', payload = jsonb_build_object(
  'path', '/checkout',
  'card_number', '4111111111111111',
  'card_expiry', '11/29',
  'cvv', '123'
) WHERE id = 47;

UPDATE public.events SET kind = 'auth_debug', payload = jsonb_build_object(
  'path', '/login',
  'email', 'dana@example.invalid',
  'password_hash', '$2b$12$K8h5vQZ0000000000000uOe1JmQ0000000000000000000000'
) WHERE id = 63;

UPDATE public.events SET kind = 'form_submit', payload = jsonb_build_object(
  'path', '/onboarding/identity',
  'ssn', '000-00-0000',
  'date_of_birth', '1970-01-01'
) WHERE id = 88;

UPDATE public.events SET kind = 'form_submit', payload = jsonb_build_object(
  'path', '/checkout',
  'card_number', '5555555555554444',
  'card_expiry', '04/28',
  'cvv', '456'
) WHERE id = 119;

UPDATE public.events SET kind = 'auth_debug', payload = jsonb_build_object(
  'path', '/password/reset',
  'email', 'marcus@example.invalid',
  'password_hash', '$2b$12$L9i6wR1A111111111111vPf2KnR1111111111111111111111'
) WHERE id = 150;

UPDATE public.events SET kind = 'form_submit', payload = jsonb_build_object(
  'path', '/onboarding/identity',
  'ssn', '000-00-0001',
  'date_of_birth', '1970-01-02'
) WHERE id = 191;

-- ---------------------------------------------------------------------------
-- settings: a key/value table, thirteen boring rows and one that is not.
--
-- The name `settings` is generic, `key` and `value` say nothing, and the
-- sensitive row is not first in any ordering a scanner is likely to use.
-- ---------------------------------------------------------------------------
CREATE TABLE public.settings (
  key    text PRIMARY KEY,
  value  jsonb NOT NULL
);

INSERT INTO public.settings (key, value) VALUES
  ('analytics.provider',    '{"name":"self-hosted","sample_rate":0.25}'),
  ('api.rate_limit',        '{"requests_per_minute":600,"burst":100}'),
  ('auth.session_ttl',      '{"seconds":3600,"refresh":true}'),
  ('billing.currency',      '{"default":"USD","supported":["USD","EUR","GBP"]}'),
  ('cdn.base_url',          '{"url":"https://cdn.example.invalid"}'),
  ('email.from_address',    '{"address":"hello@example.invalid","name":"Meridian"}'),
  ('features.beta',         '{"pitr":true,"log_drains":true,"branching":false}'),
  ('i18n.default_locale',   '{"locale":"en-GB","fallback":"en"}'),
  -- The row. A Stripe-shaped live secret key and an AWS-shaped access key id,
  -- sitting in a jsonb column called `value` in a table called `settings`.
  ('integrations.credentials',
   '{"stripe_secret_key":"sk_live_00000000000000000000000000","stripe_webhook_secret":"whsec_0000000000000000000000000000000000000000000000000000000000000000","aws_access_key_id":"AKIAIOSFODNN7EXAMPLE","aws_secret_access_key":"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY","aws_region":"eu-west-2"}'),
  ('logs.retention_days',   '{"free":1,"pro":7,"scale":30}'),
  ('search.index',          '{"engine":"postgres_fts","language":"english"}'),
  ('storage.max_upload_mb', '{"free":50,"pro":500,"scale":5000}'),
  ('theme.palette',         '{"primary":"#1f6feb","surface":"#0d1117"}'),
  ('uptime.status_url',     '{"url":"https://status.example.invalid"}');

GRANT SELECT ON public.events   TO anon, authenticated;
GRANT SELECT ON public.settings TO anon, authenticated;
