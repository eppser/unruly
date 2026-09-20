-- Site content, and the three shapes that must NOT be mistaken for it.
--
-- A relation readable by anonymous callers is not automatically a problem: a
-- site's copy, navigation and product blurbs are meant to be world-readable and
-- are rendered into the page anyway. Reporting those beside a table of password
-- hashes is how a report stops being read.
--
-- The demotion is deliberately hard to earn, because under-reporting a leak is
-- worse than over-reporting a page. Each table below pins one condition.

-- 1. The genuine article. Five columns, all presentation, nothing sensitive,
--    read-only. This is what may be rated medium.
CREATE TABLE public_site_content (
  id           bigserial PRIMARY KEY,
  slug         text NOT NULL,
  title        text NOT NULL,
  body         text,
  excerpt      text,
  image_url    text,
  published_at timestamptz DEFAULT now()
);
INSERT INTO public_site_content (slug, title, body, excerpt, image_url) VALUES
  ('about', 'About us', 'We make things.', 'We make things.', '/img/about.png'),
  ('pricing', 'Pricing', 'Three plans.', 'Three plans.', '/img/pricing.png');
ALTER TABLE public_site_content ENABLE ROW LEVEL SECURITY;
CREATE POLICY public_site_content_sel ON public_site_content FOR SELECT TO anon USING (true);
GRANT SELECT ON public_site_content TO anon;

-- 2. One content column is not enough. id + title describes a lookup table as
--    readily as an article, and demoting on it would demote half of every
--    schema. Must stay high.
CREATE TABLE content_one_column (
  id    bigserial PRIMARY KEY,
  title text NOT NULL,
  owner_id uuid,
  status   text,
  amount   numeric
);
INSERT INTO content_one_column (title, status, amount) VALUES ('row one', 'open', 10);
ALTER TABLE content_one_column ENABLE ROW LEVEL SECURITY;
CREATE POLICY content_one_column_sel ON content_one_column FOR SELECT TO anon USING (true);
GRANT SELECT ON content_one_column TO anon;

-- 3. Content-shaped AND world-writable. Being able to change what a site
--    displays is a finding whether or not the words were already public --
--    defacement, and a stored-XSS delivery mechanism. Must stay high.
CREATE TABLE content_but_writable (
  id        bigserial PRIMARY KEY,
  slug      text,
  title     text,
  body      text,
  image_url text
);
INSERT INTO content_but_writable (slug, title, body) VALUES ('home', 'Home', 'Welcome.');
ALTER TABLE content_but_writable ENABLE ROW LEVEL SECURITY;
CREATE POLICY content_but_writable_all ON content_but_writable
  FOR ALL TO anon USING (true) WITH CHECK (true);
GRANT SELECT, INSERT, UPDATE, DELETE ON content_but_writable TO anon;

-- 4. Content-shaped but carrying one sensitive column. A relation holding
--    anything the sensitive classifier recognises is never demoted, whatever
--    else it holds. Must stay critical.
CREATE TABLE content_with_pii (
  id            bigserial PRIMARY KEY,
  slug          text,
  title         text,
  body          text,
  author_email  text
);
INSERT INTO content_with_pii (slug, title, body, author_email) VALUES
  ('post', 'A post', 'Words.', 'writer@example.invalid');
ALTER TABLE content_with_pii ENABLE ROW LEVEL SECURITY;
CREATE POLICY content_with_pii_sel ON content_with_pii FOR SELECT TO anon USING (true);
GRANT SELECT ON content_with_pii TO anon;
