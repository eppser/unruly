-- Neon Data API ground-truth fixture for unruly.
-- SYNTHETIC DATA ONLY. Three tables are deliberately exploitable, three are
-- correctly protected. A scan that reports all six is as wrong as one that
-- reports none.

grant usage on schema public to anonymous, authenticated;

-- == EXPLOITABLE 1: anonymous read =====================================
-- The explicit GRANT is the mistake. Neon's anonymous role starts with no
-- permissions, so this only happens when someone grants it on purpose.
drop table if exists anon_readable cascade;
create table anon_readable (id serial primary key, owner_sub text, secret text);
insert into anon_readable (owner_sub, secret) values
  ('user-alpha', 'SYNTHETIC-anon-readable-row-1'),
  ('user-beta',  'SYNTHETIC-anon-readable-row-2');
grant select on anon_readable to anonymous;

-- == EXPLOITABLE 2: RLS never enabled ==================================
-- Neon's headline accident: any authenticated account reads every row.
drop table if exists rls_disabled cascade;
create table rls_disabled (id serial primary key, owner_sub text, card_last4 text);
insert into rls_disabled (owner_sub, card_last4) values
  ('user-alpha', '0000'), ('user-beta', '1111'), ('user-gamma', '2222');
grant select on rls_disabled to authenticated;
-- row level security deliberately NOT enabled

-- == EXPLOITABLE 3: anonymous write ====================================
drop table if exists open_guestbook cascade;
create table open_guestbook (id serial primary key, body text);
insert into open_guestbook (body) values ('SYNTHETIC-seed-entry');
grant select, insert on open_guestbook to anonymous, authenticated;
grant usage, select on sequence open_guestbook_id_seq to anonymous, authenticated;

-- == PROTECTED 1: no grants ============================================
drop table if exists owner_only cascade;
create table owner_only (id serial primary key, secret text);
insert into owner_only (secret) values ('SYNTHETIC-must-never-be-read');

-- == PROTECTED 2: RLS on, correct per-user policy ======================
drop table if exists rls_enforced cascade;
create table rls_enforced (id serial primary key, owner_sub text, note text);
insert into rls_enforced (owner_sub, note) values
  ('user-alpha', 'SYNTHETIC-alpha-note'), ('user-beta', 'SYNTHETIC-beta-note');
alter table rls_enforced enable row level security;
grant select on rls_enforced to authenticated;
create policy own_rows on rls_enforced for select to authenticated
  using (owner_sub = auth.user_id());

-- == PROTECTED 3: RLS on, granted, zero policies =======================
-- Deny-all. Answers 200 with an empty array -- indistinguishable from an
-- empty table without a second observation. This is the ambiguity case.
drop table if exists rls_no_policy cascade;
create table rls_no_policy (id serial primary key, note text);
insert into rls_no_policy (note) values ('SYNTHETIC-hidden-by-rls');
alter table rls_no_policy enable row level security;
grant select on rls_no_policy to anonymous, authenticated;
