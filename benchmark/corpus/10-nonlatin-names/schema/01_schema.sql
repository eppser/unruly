-- Project 10: every relation name is non-English, across four scripts.
--
-- The one property this target measures: identifiers that are not ASCII
-- English. Discovery, exposure and sensitive-data classification all have to
-- work on names a Latin-1 wordlist cannot express and a URL cannot carry
-- without percent-encoding.
--
-- WHY EVERYTHING IS DOUBLE-QUOTED
--
-- Postgres folds an UNQUOTED identifier to lower case. It does accept letters
-- with diacritics and non-Latin letters unquoted -- `CREATE TABLE 顧客` is
-- legal -- but `CREATE TABLE Ünïcödé` and `CREATE TABLE ünïcödé` would then be
-- the same table. This file needs both to exist separately, so every
-- identifier is quoted. That is also the honest way to write such a schema:
-- an application that quotes gets case-sensitive names, and the difference is
-- invisible in a URL.
--
-- THE NORMALISATION PAIR
--
-- `café_registro` appears twice: once composed (U+00E9) and once decomposed
-- (e + U+0301). Postgres does NOT Unicode-normalise identifiers, so these are
-- two different tables that render identically in every terminal and editor.
-- Both are written with the SQL-standard U&"..." escape rather than as literal
-- bytes, so that no editor, no `git` filter and no copy-paste through a
-- normalising clipboard can silently collapse them into one. If they ever do
-- collapse, this file stops loading with a duplicate-table error rather than
-- quietly halving the fixture.
--
-- THE NON-BMP NAME
--
-- `𝕂𝕒𝕣𝕥𝕖` (MATHEMATICAL DOUBLE-STRUCK, U+1D542 and friends) is outside the
-- Basic Multilingual Plane: four bytes per character in UTF-8, a surrogate
-- pair in UTF-16. Written with U&"\+01D542" style escapes for the same reason.

GRANT USAGE ON SCHEMA public TO anon, authenticated;

-- ---------------------------------------------------------------------------
-- German. Umlauts and compounds. `benutzer_zugangsdaten` is the credential
-- store; a classifier keyed on the English word "password" sees nothing in it.
-- ---------------------------------------------------------------------------
CREATE TABLE public."benutzer_zugangsdaten" (
  "kennung"          bigserial PRIMARY KEY,
  "benutzername"     text NOT NULL,
  "passwort_hash"    text NOT NULL,
  "api_schlüssel"    text NOT NULL,
  "letzte_anmeldung" timestamptz
);
INSERT INTO public."benutzer_zugangsdaten"
  ("benutzername", "passwort_hash", "api_schlüssel") VALUES
  ('dana',   '$2b$12$K8h5vQZ0000000000000uOe1JmQ0000000000000000000000', 'sk_test_4f8a2b1c9d0e7f6a5b4c3d2e'),
  ('marcus', '$2b$12$L9i6wR1A111111111111vPf2KnR1111111111111111111111', 'sk_test_1a2b3c4d5e6f7a8b9c0d1e2f'),
  ('priya',  '$2b$12$M0j7xS2B222222222222wQg3LoS2222222222222222222222', 'sk_test_9f8e7d6c5b4a3f2e1d0c9b8a'),
  ('tomas',  '$2b$12$N1k8yT3C333333333333xRh4MpT3333333333333333333333', 'sk_test_0e1d2c3b4a5f6e7d8c9b0a1f'),
  ('elena',  '$2b$12$O2l9zU4D444444444444ySi5NqU4444444444444444444444', 'sk_test_7c6b5a4f3e2d1c0b9a8f7e6d');

CREATE TABLE public."zahlungsempfänger" (
  "kennung"       bigserial PRIMARY KEY,
  "empfängername" text NOT NULL,
  "iban_nummer"   text NOT NULL,
  "kontoinhaber"  text,
  "betrag_cent"   bigint
);
INSERT INTO public."zahlungsempfänger"
  ("empfängername", "iban_nummer", "kontoinhaber", "betrag_cent") VALUES
  ('Stadtwerke München', 'DE89370400440532013000', 'Dana Whitfield',    12900),
  ('Westminster Ltd',    'GB82WEST12345698765432', 'Marcus Oyelaran',   48050),
  ('Banque Fictive',     'FR1420041010050500013M02606', 'Priya Raghunathan', 7325),
  ('ABN Voorbeeld',      'NL91ABNA0417164300',    'Tomas Berg',          990);

-- RLS on, no policy: readable privilege, zero rows, forever.
CREATE TABLE public."bestellübersicht" (
  "kennung"       bigserial PRIMARY KEY,
  "bestellnummer" text NOT NULL,
  "gesamtbetrag"  numeric(10,2) NOT NULL
);
INSERT INTO public."bestellübersicht" ("bestellnummer", "gesamtbetrag")
SELECT 'BST-' || lpad(i::text, 5, '0'), (i * 13.75)::numeric(10,2)
FROM generate_series(1, 7) i;

-- ---------------------------------------------------------------------------
-- Japanese. No Latin characters at all, so the percent-encoded path is the
-- only way to address these over HTTP.
-- ---------------------------------------------------------------------------
CREATE TABLE public."顧客" (
  "番号"           bigserial PRIMARY KEY,
  "氏名"           text NOT NULL,
  "メールアドレス" text NOT NULL,
  "電話番号"       text
);
INSERT INTO public."顧客" ("氏名", "メールアドレス", "電話番号")
SELECT (ARRAY['田中 太郎','鈴木 花子','佐藤 健','高橋 美咲','伊藤 大輔'])[1 + (i % 5)],
       'kokyaku' || i || '@example.invalid',
       '+81-3-5555-' || lpad(i::text, 4, '0')
FROM generate_series(1, 9) i;

-- No grant at all.
CREATE TABLE public."注文履歴" (
  "番号"     bigserial PRIMARY KEY,
  "注文番号" text NOT NULL,
  "金額"     numeric(10,2) NOT NULL
);
INSERT INTO public."注文履歴" ("注文番号", "金額")
SELECT 'JP-' || lpad(i::text, 6, '0'), (i * 1980)::numeric(10,2)
FROM generate_series(1, 6) i;

CREATE TABLE public."パスワード保管" (
  "番号"               bigserial PRIMARY KEY,
  "利用者名"           text NOT NULL,
  "パスワードハッシュ" text NOT NULL,
  "復旧コード"         text
);
INSERT INTO public."パスワード保管" ("利用者名", "パスワードハッシュ", "復旧コード") VALUES
  ('tanaka',   '$2b$12$P3m0aV5E555555555555zTj6OrV5555555555555555555555', 'JBSWY3DPEHPK3PXP'),
  ('suzuki',   '$2b$12$Q4n1bW6F666666666666aUk7PsW6666666666666666666666', 'KRSXG5CTMVRXEZLU'),
  ('sato',     '$2b$12$R5o2cX7G777777777777bVl8QtX7777777777777777777777', 'MZXW6YTBOI======'),
  ('takahashi','$2b$12$S6p3dY8H888888888888cWm9RuY8888888888888888888888', NULL);

-- ---------------------------------------------------------------------------
-- Spanish. An eñe in the relation name, accents in the columns.
-- ---------------------------------------------------------------------------
CREATE TABLE public."contraseñas" (
  "identificador"  bigserial PRIMARY KEY,
  "usuario"        text NOT NULL,
  "contraseña_hash" text NOT NULL,
  "clave_api"      text NOT NULL
);
INSERT INTO public."contraseñas" ("usuario", "contraseña_hash", "clave_api") VALUES
  ('elena',  '$2b$12$T7q4eZ9I999999999999dXn0SvZ9999999999999999999999', 'sk_test_2d3e4f5a6b7c8d9e0f1a2b3c'),
  ('mateo',  '$2b$12$U8r5fA0J000000000000eYo1TwA0000000000000000000000', 'sk_test_3e4f5a6b7c8d9e0f1a2b3c4d'),
  ('lucia',  '$2b$12$V9s6gB1K111111111111fZp2UxB1111111111111111111111', 'sk_test_4f5a6b7c8d9e0f1a2b3c4d5e');

-- No grant at all: card numbers behind a REVOKE.
CREATE TABLE public."información_personal" (
  "identificador"       bigserial PRIMARY KEY,
  "nombre_completo"     text NOT NULL,
  "número_de_tarjeta"   text NOT NULL,
  "correo_electrónico"  text NOT NULL,
  "número_de_documento" text
);
INSERT INTO public."información_personal"
  ("nombre_completo", "número_de_tarjeta", "correo_electrónico", "número_de_documento") VALUES
  ('Elena Marchetti', '4111111111111111', 'elena@example.invalid',  '00000000A'),
  ('Mateo Fernández', '5555555555554444', 'mateo@example.invalid',  '11111111B'),
  ('Lucía Rodríguez', '378282246310005',  'lucia@example.invalid',  '22222222C'),
  ('Íñigo Basterra',  '6011111111111117', 'inigo@example.invalid',  '33333333D');

-- ---------------------------------------------------------------------------
-- Cyrillic.
-- ---------------------------------------------------------------------------
CREATE TABLE public."пользователи" (
  "идентификатор"     bigserial PRIMARY KEY,
  "имя_пользователя"  text NOT NULL,
  "электронная_почта" text NOT NULL,
  "хеш_пароля"        text NOT NULL
);
INSERT INTO public."пользователи"
  ("имя_пользователя", "электронная_почта", "хеш_пароля")
SELECT (ARRAY['иванов','петров','сидоров','кузнецов','смирнов'])[1 + (i % 5)] || i,
       'polzovatel' || i || '@example.invalid',
       '$2b$12$' || lpad(i::text, 53, '0')
FROM generate_series(1, 8) i;

-- RLS on, no policy.
CREATE TABLE public."платежи" (
  "идентификатор" bigserial PRIMARY KEY,
  "номер_карты"   text NOT NULL,
  "сумма"         numeric(10,2) NOT NULL
);
INSERT INTO public."платежи" ("номер_карты", "сумма")
SELECT (ARRAY['4111111111111111','5555555555554444','378282246310005'])[1 + (i % 3)],
       (i * 250.50)::numeric(10,2)
FROM generate_series(1, 5) i;

-- ---------------------------------------------------------------------------
-- One identifier that mixes three scripts, which no per-language heuristic
-- will bucket correctly.
-- ---------------------------------------------------------------------------
CREATE TABLE public."benutzer_顧客_данные" (
  "идентификатор" bigserial PRIMARY KEY,
  "氏名"          text NOT NULL,
  "passwort_hash" text NOT NULL,
  "почта"         text NOT NULL
);
INSERT INTO public."benutzer_顧客_данные" ("氏名", "passwort_hash", "почта")
SELECT '混合' || i,
       '$2b$12$' || lpad(i::text, 53, '9'),
       'mixed' || i || '@example.invalid'
FROM generate_series(1, 4) i;

-- ---------------------------------------------------------------------------
-- Outside the BMP: MATHEMATICAL DOUBLE-STRUCK CAPITAL K + a, r, t, e.
-- Four UTF-8 bytes per character, a surrogate pair in UTF-16. Card data, so a
-- classifier that drops non-BMP names drops the worst table in the project.
-- ---------------------------------------------------------------------------
CREATE TABLE public.U&"\+01D542\+01D552\+01D563\+01D565\+01D556" (
  "идентификатор"     bigserial PRIMARY KEY,
  "número_de_tarjeta" text NOT NULL,
  "kartenprüfnummer"  text,
  "ablaufdatum"       text
);
INSERT INTO public.U&"\+01D542\+01D552\+01D563\+01D565\+01D556"
  ("número_de_tarjeta", "kartenprüfnummer", "ablaufdatum") VALUES
  ('4111111111111111', '123', '11/29'),
  ('5555555555554444', '456', '04/28'),
  ('378282246310005',  '7890','09/27');

-- ---------------------------------------------------------------------------
-- The case pair. Identical apart from the case of the first letter, and both
-- exist only because they are quoted. Ü is U+00DC, ü is U+00FC.
-- The upper-case one is readable; the lower-case one has RLS on and no policy.
-- A scanner that lower-cases relation names before deduplicating reports one
-- relation here instead of two, and gets its exposure state 50% right.
-- ---------------------------------------------------------------------------
CREATE TABLE public.U&"\00DCn\00EFc\00F6d\00E9" (
  "identificador" bigserial PRIMARY KEY,
  "clave_api"     text NOT NULL
);
INSERT INTO public.U&"\00DCn\00EFc\00F6d\00E9" ("clave_api") VALUES
  ('sk_test_upper_000000000000000001'),
  ('sk_test_upper_000000000000000002');

CREATE TABLE public.U&"\00FCn\00EFc\00F6d\00E9" (
  "identificador" bigserial PRIMARY KEY,
  "clave_api"     text NOT NULL
);
INSERT INTO public.U&"\00FCn\00EFc\00F6d\00E9" ("clave_api") VALUES
  ('sk_test_lower_000000000000000001'),
  ('sk_test_lower_000000000000000002'),
  ('sk_test_lower_000000000000000003');

-- ---------------------------------------------------------------------------
-- The normalisation pair. Both render as `café_registro`. The first is NFC
-- (U+00E9), the second is NFD (e + U+0301). Postgres does not normalise, so
-- these are two tables. Over HTTP they are two DIFFERENT percent-encoded
-- paths: caf%C3%A9_registro and cafe%CC%81_registro.
-- The NFC one is readable; the NFD one holds no grant.
-- ---------------------------------------------------------------------------
CREATE TABLE public.U&"caf\00E9_registro" (
  "identificador" bigserial PRIMARY KEY,
  "nota"          text NOT NULL
);
INSERT INTO public.U&"caf\00E9_registro" ("nota") VALUES
  ('forma compuesta NFC'), ('segunda fila');

CREATE TABLE public.U&"cafe\0301_registro" (
  "identificador" bigserial PRIMARY KEY,
  "nota"          text NOT NULL
);
INSERT INTO public.U&"cafe\0301_registro" ("nota") VALUES
  ('forma descompuesta NFD'), ('segunda fila'), ('tercera fila');

-- ---------------------------------------------------------------------------
-- Privileges.
--
-- `顧客` carries the full write set so that the percent-encoded path is
-- exercised for POST, PATCH and DELETE and not only for GET. Every other
-- relation is read-only or worse, which keeps the write axis (project 01) out
-- of this project's measurement.
-- ---------------------------------------------------------------------------
GRANT SELECT ON public."benutzer_zugangsdaten" TO anon, authenticated;
GRANT SELECT ON public."zahlungsempfänger"     TO anon, authenticated;
GRANT SELECT ON public."bestellübersicht"      TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public."顧客" TO anon, authenticated;
GRANT SELECT ON public."パスワード保管"        TO anon, authenticated;
GRANT SELECT ON public."contraseñas"           TO anon, authenticated;
GRANT SELECT ON public."пользователи"          TO anon, authenticated;
GRANT SELECT ON public."платежи"               TO anon, authenticated;
GRANT SELECT ON public."benutzer_顧客_данные"  TO anon, authenticated;
GRANT SELECT ON public.U&"\+01D542\+01D552\+01D563\+01D565\+01D556" TO anon, authenticated;
GRANT SELECT ON public.U&"\00DCn\00EFc\00F6d\00E9" TO anon, authenticated;
GRANT SELECT ON public.U&"\00FCn\00EFc\00F6d\00E9" TO anon, authenticated;
GRANT SELECT ON public.U&"caf\00E9_registro"   TO anon, authenticated;
-- 注文履歴, información_personal and the NFD café_registro: intentionally none.

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;

-- RLS with no policy attached: the request succeeds and returns [].
ALTER TABLE public."bestellübersicht" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."платежи"          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.U&"\00FCn\00EFc\00F6d\00E9" ENABLE ROW LEVEL SECURITY;
