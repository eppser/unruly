-- A relation no vocabulary reaches.
--
-- Every other table here is findable: the application names most of them, and
-- PostgREST's near-miss hint recovers the rest from a wordlist token that
-- resembles them -- open_no_rls_archive is documented as named nowhere and is
-- still recovered, because "archive" is a word. Measured after the schema-
-- qualified inventory fix, a scan with no -site and no supplied vocabulary
-- recovers 27 of 27 relations in this fixture. That is a good result and it
-- leaves nothing to demonstrate the case the vocabulary handoff exists for.
--
-- This name contains no word, no morpheme and nothing similar to any token in
-- any list unruly ships, so similarity cannot reach it and neither can the
-- application: the application does not know it exists. The only way it enters
-- a scan is for something OUTSIDE unruly to say the name -- an operator, or an
-- agent that read a document unruly never sees -- and hand it back through
-- -vocab. unruly then measures it exactly like any other candidate.
--
-- No grant to anon at all, which is also the interesting half: PostgREST
-- answers 42501 before RLS is consulted, so nothing about it leaks except the
-- confirmation that it is there.
CREATE TABLE zq9f_x4tm7 (
  id            bigserial PRIMARY KEY,
  holder_email  text NOT NULL,
  balance_cents bigint NOT NULL DEFAULT 0
);

INSERT INTO zq9f_x4tm7 (holder_email, balance_cents)
VALUES ('ledger1@example.invalid', 4200), ('ledger2@example.invalid', 900);

ALTER TABLE zq9f_x4tm7 ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE zq9f_x4tm7 FROM anon, authenticated;
