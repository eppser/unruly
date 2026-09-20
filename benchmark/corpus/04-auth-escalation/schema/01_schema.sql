-- Project 04: the Postgres side is not misconfigured. GoTrue is.
--
-- Every table below has RLS enabled and a policy, every policy names a role,
-- every grant is deliberate. Read the DDL on its own and it looks careful:
-- `anon` gets nothing anywhere, and an anonymous scan reports the project
-- clean. The exposure is one setting in another service --
-- GOTRUE_DISABLE_SIGNUP=false with GOTRUE_MAILER_AUTOCONFIRM=true -- which
-- turns `TO authenticated` into `TO anyone who can send one HTTP request`.
--
-- Four tables are `FOR SELECT TO authenticated USING (true)`: salaries with
-- national-ID fragments and bank details, clinical notes, an internal
-- directory with home addresses, and a device inventory. One,
-- my_payslips, is correctly owner-scoped and gains an attacker NOTHING.
-- That last one is the control: a scanner that reports every
-- authenticated-visible relation as an escalation is wrong about it.

-- ---------------------------------------------------------------------------
-- employee_salaries -- FOR SELECT TO authenticated USING (true).
--
-- The USING clause is `true`, not a predicate about the caller. So the policy
-- means "any row, to any account", and the only thing standing between a
-- stranger and this table is whether the stranger can get an account.
-- ---------------------------------------------------------------------------
CREATE TABLE public.employee_salaries (
  id                  bigserial PRIMARY KEY,
  employee_email      text NOT NULL,
  full_name           text NOT NULL,
  job_title           text NOT NULL,
  annual_salary_cents bigint NOT NULL,
  bonus_cents         bigint NOT NULL DEFAULT 0,
  national_id_last4   text,
  bank_account_last4  text
);
INSERT INTO public.employee_salaries
  (employee_email, full_name, job_title, annual_salary_cents, bonus_cents, national_id_last4, bank_account_last4) VALUES
  ('dana@example.invalid',   'Dana Whitfield',    'VP Engineering',  24500000, 4000000, '4417', '9021'),
  ('marcus@example.invalid', 'Marcus Oyelaran',   'Staff Engineer',  19800000, 2200000, '8830', '4415'),
  ('priya@example.invalid',  'Priya Raghunathan', 'Head of Finance', 21200000, 3100000, '1176', '7783'),
  ('tomas@example.invalid',  'Tomas Berg',        'Support Lead',    11400000,  600000, '5502', '3348'),
  ('elena@example.invalid',  'Elena Marchetti',   'Designer',        13900000,  900000, '6694', '2210'),
  ('ops@example.invalid',    'Ops Shared Account','Service Account',        0,       0, NULL,   NULL);
ALTER TABLE public.employee_salaries ENABLE ROW LEVEL SECURITY;
CREATE POLICY employee_salaries_any_account ON public.employee_salaries
  FOR SELECT TO authenticated USING (true);

-- ---------------------------------------------------------------------------
-- health_notes -- the same policy shape, applied to clinical data.
--
-- Present because impact and exposure are separate axes and a corpus that only
-- varies exposure cannot show that. This table is exactly as reachable as the
-- device inventory below and is not remotely as bad to lose.
-- ---------------------------------------------------------------------------
CREATE TABLE public.health_notes (
  id            bigserial PRIMARY KEY,
  patient_email text NOT NULL,
  full_name     text NOT NULL,
  recorded_on   date NOT NULL,
  diagnosis     text NOT NULL,
  medication    text,
  clinician_note text
);
INSERT INTO public.health_notes (patient_email, full_name, recorded_on, diagnosis, medication, clinician_note) VALUES
  ('dana@example.invalid',   'Dana Whitfield',    '2026-02-03', 'Type 2 diabetes',      'Metformin 500mg',    'Review in six months.'),
  ('marcus@example.invalid', 'Marcus Oyelaran',   '2026-01-17', 'Generalised anxiety',  'Sertraline 50mg',    'Referred to counselling.'),
  ('priya@example.invalid',  'Priya Raghunathan', '2025-12-08', 'Hypertension',         'Amlodipine 5mg',     'Home monitoring advised.'),
  ('tomas@example.invalid',  'Tomas Berg',        '2026-03-11', 'Seasonal asthma',      'Salbutamol inhaler', 'No overnight symptoms.');
ALTER TABLE public.health_notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY health_notes_any_account ON public.health_notes
  FOR SELECT TO authenticated USING (true);

-- ---------------------------------------------------------------------------
-- internal_directory -- home addresses, personal phone numbers, next of kin.
--
-- The staff directory is the table people are least likely to think of as
-- sensitive and the one that most reliably turns up in a doxxing complaint.
-- ---------------------------------------------------------------------------
CREATE TABLE public.internal_directory (
  id                bigserial PRIMARY KEY,
  full_name         text NOT NULL,
  work_email        text NOT NULL,
  personal_email    text,
  home_address      text NOT NULL,
  mobile_number     text NOT NULL,
  emergency_contact text
);
INSERT INTO public.internal_directory (full_name, work_email, personal_email, home_address, mobile_number, emergency_contact) VALUES
  ('Dana Whitfield',    'dana@example.invalid',   'dana.personal@example.invalid',   '12 Fictional Street, Nowhere NW1 1AA', '+1-555-0401', 'R. Whitfield +1-555-0451'),
  ('Marcus Oyelaran',   'marcus@example.invalid', 'marcus.home@example.invalid',     '48 Invented Road, Nowhere NW2 2BB',    '+1-555-0402', 'A. Oyelaran +1-555-0452'),
  ('Priya Raghunathan', 'priya@example.invalid',  'priya.private@example.invalid',   '3 Imaginary Lane, Nowhere NW3 3CC',    '+1-555-0403', 'S. Raghunathan +1-555-0453'),
  ('Tomas Berg',        'tomas@example.invalid',  NULL,                              '77 Notional Avenue, Nowhere NW4 4DD',  '+1-555-0404', 'K. Berg +1-555-0454'),
  ('Elena Marchetti',   'elena@example.invalid',  'elena.m@example.invalid',         '9 Hypothetical Close, Nowhere NW5 5EE','+1-555-0405', 'G. Marchetti +1-555-0455');
ALTER TABLE public.internal_directory ENABLE ROW LEVEL SECURITY;
CREATE POLICY internal_directory_any_account ON public.internal_directory
  FOR SELECT TO authenticated USING (true);

-- ---------------------------------------------------------------------------
-- device_inventory -- the same exposure, low impact.
--
-- Here so that "everything authenticated-visible is a critical" is a claim the
-- corpus can falsify. Asset tags and serial numbers, no people in it.
-- ---------------------------------------------------------------------------
CREATE TABLE public.device_inventory (
  id           bigserial PRIMARY KEY,
  asset_tag    text NOT NULL,
  model        text NOT NULL,
  purchased_on date NOT NULL,
  location     text NOT NULL
);
INSERT INTO public.device_inventory (asset_tag, model, purchased_on, location) VALUES
  ('AST-0001', 'ThinkPad T14',   '2024-06-02', 'Floor 2 store'),
  ('AST-0002', 'ThinkPad T14',   '2024-06-02', 'Floor 2 store'),
  ('AST-0003', 'Dell U2723',     '2025-01-14', 'Meeting room A'),
  ('AST-0004', 'Ubiquiti AP-6',  '2025-03-30', 'Ceiling, floor 1'),
  ('AST-0005', 'Brother HL-L2',  '2023-11-09', 'Floor 1 print nook');
ALTER TABLE public.device_inventory ENABLE ROW LEVEL SECURITY;
CREATE POLICY device_inventory_any_account ON public.device_inventory
  FOR SELECT TO authenticated USING (true);

-- ---------------------------------------------------------------------------
-- my_payslips -- THE CONTROL. A correct per-user policy.
--
-- Same RLS bit, same TO authenticated, same grants as the four tables above.
-- The USING clause compares owner_id against the caller's `sub` claim, so the
-- answer depends on WHICH account asks.
--
-- Every row is seeded to an owner uuid that NO token in this corpus carries
-- and that no signup can produce: GoTrue assigns a fresh random uuid to each
-- new account, so an attacker who signs up gets zero rows here no matter how
-- many times they try. Escalating gains nothing, and a scanner that reports
-- this relation alongside the four above is wrong about it.
-- ---------------------------------------------------------------------------
CREATE TABLE public.my_payslips (
  id           bigserial PRIMARY KEY,
  owner_id     uuid NOT NULL,
  period       text NOT NULL,
  gross_cents  bigint NOT NULL,
  net_cents    bigint NOT NULL
);
INSERT INTO public.my_payslips (owner_id, period, gross_cents, net_cents) VALUES
  ('aaaaaaaa-0000-0000-0000-00000000000a', '2026-01', 2041666, 1387333),
  ('aaaaaaaa-0000-0000-0000-00000000000a', '2026-02', 2041666, 1387333),
  ('bbbbbbbb-0000-0000-0000-00000000000b', '2026-01', 1650000, 1122000),
  ('bbbbbbbb-0000-0000-0000-00000000000b', '2026-02', 1650000, 1122000),
  ('cccccccc-0000-0000-0000-00000000000c', '2026-01',  950000,  684000);
ALTER TABLE public.my_payslips ENABLE ROW LEVEL SECURITY;
CREATE POLICY my_payslips_own_rows ON public.my_payslips
  FOR SELECT TO authenticated
  USING (owner_id = auth.request_sub());

-- ---------------------------------------------------------------------------
-- Privileges.
--
-- Identical on every table, and full CRUD, so that the POLICY is the only
-- thing that decides. A revoked table would be locked twice and would measure
-- the privilege layer rather than the policy.
--
-- `anon` holds the same grants as `authenticated` and still sees nothing: no
-- policy names it, so RLS denies it everywhere. That is why an anon-only scan
-- reports this project clean.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO anon, authenticated;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
