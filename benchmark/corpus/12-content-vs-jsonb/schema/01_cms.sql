-- Project 12, part 1 of 2: the marketing site's content tables.
--
-- Every table in this file is world-readable ON PURPOSE. It is the public
-- content of a public website: the same words that are already served as HTML
-- to anyone who loads the page. A publicly readable CMS table is not a
-- misconfiguration, and a scanner that reports one produces a finding whose
-- correct remediation is "do nothing".
--
-- Two of these tables carry a deliberate TRAP: a column literally named
-- `email`, and another named `author_email`, both holding addresses that are
-- printed on the website. A column name is not a data classification. Any
-- heuristic that reports a readable relation because it has a column called
-- `email` fires here, seven times, and every one of those is wrong.
--
-- The one real finding on this target is in 02_events.sql, where nothing in
-- any name says anything at all.

-- ---------------------------------------------------------------------------
-- site_sections: the copy blocks the homepage renders.
-- ---------------------------------------------------------------------------
CREATE TABLE public.site_sections (
  id        bigserial PRIMARY KEY,
  slug      text NOT NULL UNIQUE,
  heading   text NOT NULL,
  body      text NOT NULL,
  sort_order integer NOT NULL
);

INSERT INTO public.site_sections (slug, heading, body, sort_order) VALUES
  ('hero', 'Ship your backend on Friday',
   'Meridian gives your team a managed Postgres database, an auto-generated REST API and file storage behind one URL. No servers to patch, no connection pools to size.', 1),
  ('why', 'Why teams move to Meridian',
   'The average team we onboard deletes about 4,000 lines of glue code in the first month. Most of it was pagination, connection retries and a hand-rolled permissions layer.', 2),
  ('security', 'Security you configure once',
   'Row-level policies live next to the data, in SQL, and apply to every client that touches the database — your web app, your mobile app, and the analytics job you wrote at 2am.', 3),
  ('migration', 'Bring the database you already have',
   'Point our import tool at an existing Postgres instance and it will copy schema, data and extensions. A 40GB database typically finishes in under twenty minutes.', 4),
  ('support', 'Talk to people who run databases',
   'Every plan above Starter includes a shared Slack channel with the on-call engineers. Median first response last quarter was 11 minutes.', 5),
  ('cta', 'Start with the free tier',
   'Two projects, 500MB of storage and unlimited API requests. No card required, and nothing expires while you are still building.', 6);

-- ---------------------------------------------------------------------------
-- blog_posts: TRAP 1. `author_email` is a byline, printed under every post.
-- ---------------------------------------------------------------------------
CREATE TABLE public.blog_posts (
  id            bigserial PRIMARY KEY,
  slug          text NOT NULL UNIQUE,
  title         text NOT NULL,
  excerpt       text NOT NULL,
  body          text NOT NULL,
  author_name   text NOT NULL,
  author_email  text NOT NULL,
  published_at  date NOT NULL
);

INSERT INTO public.blog_posts (slug, title, excerpt, body, author_name, author_email, published_at) VALUES
  ('connection-pooling-explained', 'Connection pooling, explained without the folklore',
   'Why your 500-connection Postgres instance is slower than a 50-connection one.',
   'Every Postgres connection is an operating system process with its own memory. Past a few hundred of them the scheduler spends more time switching than working. A pooler in transaction mode lets 5,000 clients share 40 backends, and the only thing you give up is session state you probably were not using.',
   'Dana Whitfield', 'dana.writes@example.invalid', '2025-02-11'),
  ('rls-for-people-who-hate-rls', 'Row-level security for people who have been burned by it',
   'Four policy shapes that cover almost every application, and the one that quietly returns nothing.',
   'The failure everyone hits once is enabling row-level security and forgetting to write a policy. The table is not broken and the query is not refused — it simply returns zero rows, forever, and the bug report says "the app shows an empty list".',
   'Marcus Oyelaran', 'marcus.writes@example.invalid', '2025-03-04'),
  ('what-we-learned-from-1000-migrations', 'What we learned from running a thousand migrations',
   'The three that failed all failed the same way.',
   'Long-running migrations do not fail on the data. They fail on the lock: an ALTER TABLE that needs ACCESS EXCLUSIVE queues behind one open transaction and every subsequent query queues behind it. Set lock_timeout and retry.',
   'Priya Raghunathan', 'priya.writes@example.invalid', '2025-04-22'),
  ('storage-without-a-cdn-bill', 'Storage without a CDN bill you have to explain',
   'Signed URLs, cache headers, and where the money actually goes.',
   'Egress is the line item that surprises people. Serving a 2MB hero image to 100,000 visitors is 200GB of transfer; the same image at 180KB is 18GB. Most of the saving is in the encoder, not the CDN contract.',
   'Tomas Berg', 'tomas.writes@example.invalid', '2025-05-19'),
  ('postgres-16-in-production', 'Six months of Postgres 16 in production',
   'The upgrade was boring. Here is what changed anyway.',
   'Parallel hash joins got noticeably faster on our workload and logical replication finally handles the case we had a cron job working around. Nothing broke, which is the review a database version wants.',
   'Elena Marchetti', 'elena.writes@example.invalid', '2025-06-30');

-- ---------------------------------------------------------------------------
-- faq_entries
-- ---------------------------------------------------------------------------
CREATE TABLE public.faq_entries (
  id        bigserial PRIMARY KEY,
  question  text NOT NULL,
  answer    text NOT NULL,
  category  text NOT NULL
);

INSERT INTO public.faq_entries (question, answer, category) VALUES
  ('Where is my data stored?', 'In the region you pick at project creation. We do not move it, and we do not replicate it across regions unless you turn that on.', 'data'),
  ('Can I connect with psql?', 'Yes. Every project gets a normal Postgres connection string, and every Postgres tool works against it.', 'data'),
  ('What happens when I hit the free tier limit?', 'The API keeps serving reads and refuses writes. Nothing is deleted, and nothing is billed without you choosing a plan.', 'billing'),
  ('Do you take backups?', 'Daily on all paid plans, with 7-day retention on Pro and 30-day on Scale. Point-in-time recovery is available on Scale.', 'data'),
  ('Is there a self-hosted option?', 'Yes, and it is the same software. The docker-compose file in our repository is what we run, minus the control plane.', 'platform'),
  ('How do I rotate an API key?', 'From Settings, API. The old key stops working the moment you confirm, so roll it in your deploy first.', 'security'),
  ('Can I use my own domain?', 'On Pro and above. Add a CNAME, and we will provision the certificate within about ten minutes.', 'platform'),
  ('Do you have a status page?', 'At status.example.invalid, and it is hosted separately from everything it reports on.', 'platform');

-- ---------------------------------------------------------------------------
-- pricing_tiers
-- ---------------------------------------------------------------------------
CREATE TABLE public.pricing_tiers (
  id            bigserial PRIMARY KEY,
  name          text NOT NULL,
  monthly_cents integer NOT NULL,
  blurb         text NOT NULL,
  highlights    text NOT NULL
);

INSERT INTO public.pricing_tiers (name, monthly_cents, blurb, highlights) VALUES
  ('Free', 0, 'Everything you need to build the first version.', '2 projects, 500MB storage, community support'),
  ('Starter', 2500, 'For a side project that started making money.', '5 projects, 8GB storage, daily backups, email support'),
  ('Pro', 9900, 'For a team shipping every week.', 'Unlimited projects, 100GB storage, 7-day backups, shared Slack channel'),
  ('Scale', 49900, 'For when the database is the product.', 'Dedicated compute, point-in-time recovery, 30-day backups, 99.95% SLA');

-- ---------------------------------------------------------------------------
-- team_members: TRAP 2. The column is called `email` and holds published
-- contact addresses — the ones on the "contact us" page. Readable, and not a
-- leak. Reporting it is the false positive this project exists to catch.
-- ---------------------------------------------------------------------------
CREATE TABLE public.team_members (
  id         bigserial PRIMARY KEY,
  name       text NOT NULL,
  role       text NOT NULL,
  photo_url  text NOT NULL,
  email      text NOT NULL,
  bio        text NOT NULL
);

INSERT INTO public.team_members (name, role, photo_url, email, bio) VALUES
  ('Dana Whitfield', 'Chief Executive', 'https://cdn.example.invalid/team/dana.jpg', 'press@example.invalid',
   'Ran platform engineering at two payments companies before deciding the database should do more of the work.'),
  ('Marcus Oyelaran', 'Head of Engineering', 'https://cdn.example.invalid/team/marcus.jpg', 'press@example.invalid',
   'Spent nine years on Postgres internals and still reads the release notes for fun.'),
  ('Priya Raghunathan', 'Head of Security', 'https://cdn.example.invalid/team/priya.jpg', 'security@example.invalid',
   'Publishes our quarterly transparency report and answers the mail sent to the address in security.txt.'),
  ('Tomas Berg', 'Developer Relations', 'https://cdn.example.invalid/team/tomas.jpg', 'devrel@example.invalid',
   'Writes the sample apps and the migration guides, and reads every issue filed against them.'),
  ('Elena Marchetti', 'Head of Support', 'https://cdn.example.invalid/team/elena.jpg', 'support@example.invalid',
   'Built the shared-channel support model and still takes a shift on the on-call rota.');

-- ---------------------------------------------------------------------------
-- press_releases
-- ---------------------------------------------------------------------------
CREATE TABLE public.press_releases (
  id           bigserial PRIMARY KEY,
  headline     text NOT NULL,
  dateline     date NOT NULL,
  body         text NOT NULL,
  contact_email text NOT NULL
);

INSERT INTO public.press_releases (headline, dateline, body, contact_email) VALUES
  ('Meridian opens a London region', '2025-01-14',
   'Projects can now be created in eu-west-2. Existing projects can be migrated in place with no change to connection strings.', 'press@example.invalid'),
  ('Meridian raises a Series A', '2025-03-27',
   'The round will fund the point-in-time recovery work and a second support rota in European hours.', 'press@example.invalid'),
  ('SOC 2 Type II report available', '2025-07-08',
   'The report covers the twelve months to June and is available under NDA from the trust page.', 'press@example.invalid'),
  ('Meridian passes 20,000 projects', '2025-11-02',
   'Twenty thousand databases now run on the platform, a little over half of them on the free tier.', 'press@example.invalid');

-- ---------------------------------------------------------------------------
-- changelog
-- ---------------------------------------------------------------------------
CREATE TABLE public.changelog (
  id          bigserial PRIMARY KEY,
  released_at date NOT NULL,
  version     text NOT NULL,
  summary     text NOT NULL
);

INSERT INTO public.changelog (released_at, version, summary) VALUES
  ('2025-01-09', '3.1.0', 'Point-in-time recovery enters public beta on Scale plans.'),
  ('2025-02-20', '3.2.0', 'The SQL editor keeps query history per project instead of per browser.'),
  ('2025-04-02', '3.3.0', 'Storage buckets can be made public without a policy, with a confirmation step.'),
  ('2025-05-15', '3.4.0', 'Connection pooler upgraded; transaction mode is now the default for new projects.'),
  ('2025-07-30', '3.5.0', 'Postgres 16 becomes the default version for newly created projects.'),
  ('2025-09-11', '3.6.0', 'Log drains can be sent to any HTTPS endpoint, with retries and a dead-letter queue.'),
  ('2025-12-04', '3.7.0', 'Row-level policy templates in the dashboard, including the one everybody gets wrong.');

GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT ON public.site_sections  TO anon, authenticated;
GRANT SELECT ON public.blog_posts     TO anon, authenticated;
GRANT SELECT ON public.faq_entries    TO anon, authenticated;
GRANT SELECT ON public.pricing_tiers  TO anon, authenticated;
GRANT SELECT ON public.team_members   TO anon, authenticated;
GRANT SELECT ON public.press_releases TO anon, authenticated;
GRANT SELECT ON public.changelog      TO anon, authenticated;
