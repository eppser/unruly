-- Corpus project 16: the CLASS of exposed data, across the whole vocabulary.
--
-- Every other project in this corpus asks WHETHER a relation is reachable.
-- This one holds that constant -- almost everything here is plainly readable --
-- and asks WHAT the report says is in it. That is a different question with a
-- different failure mode: a scanner can have perfect recall on reachability and
-- still tell an operator that a table of diagnoses and national identifiers
-- holds "data with nothing recognised in it", which is the answer that decides
-- whether anyone reads the finding at all.
--
-- Shaped as an HR and payroll platform because that is the shape that plausibly
-- holds every class at once: names and dates of birth, contact details, home
-- addresses, national identifiers, bank details, occupational-health records
-- and login credentials, in one product, in tables an ordinary developer would
-- name exactly like this.
--
-- ALL DATA IS SYNTHETIC. Addresses are documented example addresses, the domain
-- is .invalid (RFC 2606, guaranteed never to resolve), the IBAN is the standard
-- test IBAN from the ISO 13616 registry, and the identifiers are structurally
-- valid and issued to nobody.
--
-- The project has three parts:
--
--   1. Tables whose COLUMN NAMES declare the class. English, ordinary, the case
--      the name classifier exists for.
--   2. One table whose column names are GERMAN, so the name classifier is blind
--      by construction and only the sampled VALUES can carry the answer. This
--      is the cell that fails silently: a scanner with one classifier reports
--      the table as reachable and says nothing about what is in it.
--   3. Tables of LOOKALIKES, where the correct answer is that no class is
--      reported at all. Without these the project would reward a scanner that
--      labels everything, and "comprehensive" would mean "noisy".

-- =====================================================================
-- PART 1: the class is in the column name
-- =====================================================================

-- pii (names, date of birth), contact (email, phone), location (address,
-- postcode), government-id (national identifier). Four classes, one table,
-- which is also the ordinary case: personal data does not arrive sorted.
CREATE TABLE employees (
  id              serial PRIMARY KEY,
  employee_number text,
  first_name      text,
  last_name       text,
  date_of_birth   date,
  email           text,
  phone           text,
  home_address    text,
  postcode        text,
  national_id     text
);
INSERT INTO employees
  (employee_number, first_name, last_name, date_of_birth, email, phone, home_address, postcode, national_id)
VALUES
  ('E-0001', 'Ada',    'Lovelace', '1990-12-10', 'ada@example.invalid',    '+44 20 7946 0001', '1 Example Street, London',  'SW1A 1AA', 'AB-123456-C'),
  ('E-0002', 'Grace',  'Hopper',   '1985-06-02', 'grace@example.invalid',  '+44 20 7946 0002', '2 Example Street, London',  'SW1A 1AB', 'AB-234567-D'),
  ('E-0003', 'Katherine','Johnson', '1992-08-26','kj@example.invalid',     '+44 20 7946 0003', '3 Example Street, London',  'SW1A 1AC', 'AB-345678-E');
GRANT SELECT ON employees TO anon, authenticated;

-- financial (IBAN, bank account) and government-id (tax identifier).
CREATE TABLE payslips (
  id           serial PRIMARY KEY,
  employee_id  integer,
  period       text,
  gross_amount numeric,
  net_amount   numeric,
  iban         text,
  bank_account text,
  tax_id       text
);
INSERT INTO payslips (employee_id, period, gross_amount, net_amount, iban, bank_account, tax_id)
VALUES
  (1, '2026-07', 5200.00, 3910.55, 'GB82WEST12345698765432', '12345698765432', 'TAX-0001-AA'),
  (2, '2026-07', 4800.00, 3620.10, 'GB82WEST12345698765432', '12345698765433', 'TAX-0002-BB');
GRANT SELECT ON payslips TO anon, authenticated;

-- health. Occupational-health records are the reason an HR platform is a
-- plausible home for this class, and the class had no rule at all until
-- 2026-08-23 -- the renderer could print "health information" and nothing
-- could produce it.
CREATE TABLE absence_records (
  id          serial PRIMARY KEY,
  employee_id integer,
  diagnosis   text,
  medication  text,
  blood_type  text,
  allergies   text,
  days_off    integer
);
INSERT INTO absence_records (employee_id, diagnosis, medication, blood_type, allergies, days_off)
VALUES
  (1, 'lumbar strain',      'ibuprofen 400mg', 'O+',  'penicillin', 4),
  (3, 'seasonal rhinitis',  'cetirizine 10mg', 'A-',  'none known', 1);
GRANT SELECT ON absence_records TO anon, authenticated;

-- credential.
CREATE TABLE auth_users (
  id            serial PRIMARY KEY,
  username      text,
  password_hash text,
  recovery_code text,
  totp_secret   text
);
INSERT INTO auth_users (username, password_hash, recovery_code, totp_secret)
VALUES
  ('ada',   '$2b$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234', 'RC-1111-2222', 'JBSWY3DPEHPK3PXP'),
  ('grace', '$2b$12$bcdefghijklmnopqrstuvwBCDEFGHIJKLMNOPQRSTUVWXYZ012345', 'RC-3333-4444', 'KRSXG5CTMVRXEZLU');
GRANT SELECT ON auth_users TO anon, authenticated;

-- =====================================================================
-- PART 2: the column names say nothing, and the values say everything
-- =====================================================================

-- A legacy import table from the German-language predecessor product, which is
-- how tables like this actually come to exist. Not one column name matches an
-- English pattern, so a scanner with only a name classifier reports this
-- relation as readable and describes its contents as nothing in particular.
--
-- The values are unambiguous: a real test IBAN that satisfies mod-97, and an
-- email address. A classifier that reads sampled values reports financial and
-- contact here; one that does not, reports neither -- and the difference is
-- invisible unless a project deliberately removes the English crutch.
CREATE TABLE gehaltsdaten (
  id          serial PRIMARY KEY,
  personalnr  text,
  kontonummer text,
  anschrift   text,
  notiz       text
);
INSERT INTO gehaltsdaten (personalnr, kontonummer, anschrift, notiz)
VALUES
  ('P-0001', 'GB82WEST12345698765432', 'Musterstrasse 1, Berlin', 'Rueckfragen an lohn@example.invalid'),
  ('P-0002', 'GB82WEST12345698765432', 'Musterstrasse 2, Berlin', 'keine');
GRANT SELECT ON gehaltsdaten TO anon, authenticated;

-- =====================================================================
-- PART 3: lookalikes, where the correct answer is silence
-- =====================================================================

-- Every column here ends in a word that a careless rule treats as personal
-- data, and every one of them identifies a machine, a mailbox or a blockchain
-- account. All four were classified as personal data by this scanner until
-- 2026-08-23.
CREATE TABLE payout_methods (
  id               serial PRIMARY KEY,
  ip_address       text,
  mac_address      text,
  wallet_address   text,
  contract_address text
);
INSERT INTO payout_methods (ip_address, mac_address, wallet_address, contract_address)
VALUES
  ('198.51.100.7',  '00:00:5e:00:53:01', '0x0000000000000000000000000000000000000001', '0x00000000000000000000000000000000000000ff'),
  ('198.51.100.8',  '00:00:5e:00:53:02', '0x0000000000000000000000000000000000000002', '0x00000000000000000000000000000000000000fe');
GRANT SELECT ON payout_methods TO anon, authenticated;

-- Counts and labels that read like secrets and personal names. The token
-- columns are the shape this project's own reference target is full of, which
-- is why the credential rule is anchored on the SUFFIX; display_name and
-- file_name are why the name rule requires a QUALIFIED name and not a bare
-- "name"; condition and treatment_cost are ordinary business words that a
-- health rule must not swallow.
CREATE TABLE api_usage (
  id             serial PRIMARY KEY,
  display_name   text,
  file_name      text,
  max_tokens     integer,
  prompt_tokens  integer,
  token_count    integer,
  condition      text,
  treatment_cost numeric,
  status         text
);
INSERT INTO api_usage (display_name, file_name, max_tokens, prompt_tokens, token_count, condition, treatment_cost, status)
VALUES
  ('Monthly payroll export', 'payroll-2026-07.csv', 4096, 1200, 3400, 'active',   0.00, 'ok'),
  ('Absence summary',        'absence-2026-07.csv', 2048,  400, 1100, 'archived', 0.00, 'ok');
GRANT SELECT ON api_usage TO anon, authenticated;

-- =====================================================================
-- A protected control, so precision has a denominator
-- =====================================================================

-- RLS on, granted, no policy: answers 200 with an empty array. Present so that
-- "reported nothing about this table" is a scored outcome rather than an
-- absence, and so the project is not made entirely of tables that must be
-- reported.
CREATE TABLE salary_bands (
  id       serial PRIMARY KEY,
  band     text,
  min_gross numeric,
  max_gross numeric
);
INSERT INTO salary_bands (band, min_gross, max_gross)
VALUES ('junior', 3000, 4000), ('senior', 5000, 7000);
ALTER TABLE salary_bands ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON salary_bands TO anon, authenticated;
