-- Project 11, schema 1 of 4: `public`, the DEFAULT schema.
--
-- The whole project exists to break the assumption that a relation NAME has
-- one exposure verdict. A table called `users` exists in four schemas here,
-- with four different answers, and the schema is chosen by a request HEADER,
-- not by the URL path. `public` is the schema you get when you send no header
-- at all, so whatever it says is what a scanner that never learned about
-- Accept-Profile will report for `users`.
--
-- public.users is the SAFE one: RLS enabled with no policy at all. anon holds
-- SELECT, so the request is permitted; RLS then removes every row. HTTP 200,
-- body `[]`. A scanner that stops here reports this target as clean.

CREATE TABLE public.users (
  id            bigserial PRIMARY KEY,
  display_name  text NOT NULL,
  email         text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.users (display_name, email)
SELECT
  (ARRAY['Dana Whitfield','Marcus Oyelaran','Priya Raghunathan','Tomas Berg',
         'Elena Marchetti','Kwame Asante'])[1 + (i % 6)] || ' ' || i,
  'user' || i || '@example.invalid'
FROM generate_series(1, 12) AS i;

-- RLS on, and deliberately NO policy. This is the "deny by default" shape:
-- the grant lets the query run, the absence of a policy makes it return
-- nothing. It is distinguishable from a REVOKE only by the status code —
-- 200 with an empty body here, 401 with SQLSTATE 42501 in `reporting`.
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- announcements: exists ONLY in `public`.
--
-- Every schema in this project carries one relation that exists nowhere else,
-- so that SCHEMA enumeration is measurable separately from RELATION
-- enumeration. Finding `users` four times proves nothing about how many
-- schemas were reached; finding `announcements`, `service_status`, `sessions`
-- and `revenue_by_month` proves all four were.
-- ---------------------------------------------------------------------------
CREATE TABLE public.announcements (
  id         bigserial PRIMARY KEY,
  headline   text NOT NULL,
  body       text NOT NULL,
  posted_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO public.announcements (headline, body) VALUES
  ('Scheduled maintenance on 12 March', 'The API will be read-only from 02:00 to 04:00 UTC.'),
  ('Region eu-west-2 now available', 'Projects can be created in London from today.'),
  ('Deprecating API version 1', 'Version 1 endpoints stop responding on 30 June.');

GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT ON public.users         TO anon, authenticated;
GRANT SELECT ON public.announcements TO anon, authenticated;
