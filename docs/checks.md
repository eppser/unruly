# Checks

The `-html` report bundles a consolidated fix plan: one block per relation
combining every verb found, rather than one block per finding repeating the same
`ALTER TABLE`. Every check here has a row in [the threat model](threat-model.md) saying what an
attacker gains from it, and that mapping is enforced by a test rather than
maintained by hope.

Every finding unruly can emit, by canonical id. This file is not prose
about the tool — it is checked against the source, so a finding added without a
line here fails the build, and a line for a finding that no longer exists fails
too.

That rule exists because the alternative kept failing. The README's check list
drifted four separate times over this project's life: it described the tool as
it had been when somebody last remembered to edit it. Two criticals — a routine
returning rows, and an anonymously writable storage bucket — were absent from
it while shipping. For a document about a security tool that is the same class
of problem as a stale safety control.

## Findings about the target

| ID | Severity | What it means |
|---|---|---|
| `supabase-anon-read-exposed` | high; critical with sensitive columns OR sensitive VALUES; medium when the relation is read-only and looks like published site content | A relation returns rows to the anonymous role. Carries the row count and sampled rows. | Severity is refined from two independent signals: the column NAMES, and the VALUES in the sampled rows. The second exists because every name pattern is an English word, so a schema using `kreditkarte`, `passwort` or simply `notes` yields no tags at all while plainly holding card numbers — a severity systematically one step low outside the anglophone web. Value rules are structural rather than statistical: a card number must carry a real issuer prefix **and** pass Luhn (Luhn alone flags one in ten order numbers), an IBAN must satisfy mod-97, a JWT's header must decode to JSON naming an algorithm, and an email counts only when it is the WHOLE field — an address inside prose is a contact line on a marketing page, not a person's record. Reserved domains (`example.com`, `.invalid`) never count, because seed data uses them precisely because nobody owns them. Kinds are reported, never values. Under `-measure` the row count is established with `limit=0` and no rows are retrieved, so severity is refined by neither column name nor value. The **medium** case is earned, not assumed: it needs at least two columns naming presentation rather than people (`slug`, `title`, `body`, `image_url`, …), a clear majority of the non-structural columns, no column the sensitive classifier recognises, and no proven write access. It also requires that write probing actually RAN and refused: without `-write` nothing was asked, and demoting then would be demoting on ignorance. Any one of those vetoes the demotion, because under-reporting a leak is worse than over-reporting a page. The finding says why it was rated lower and invites the reader to overrule it.
| `supabase-anon-insert-allowed` | critical if the relation is also readable, otherwise high | An anonymous `INSERT` reaches the relation. Established with the sound discriminator: `42501` is refused, `23502`/`23505` passed the security layer and died on a column constraint. |
| `supabase-anon-update-allowed` | critical if the relation is also readable, otherwise high | An anonymous `UPDATE` was admitted by row-level security. Established without altering anything: the statement writes one column back with the value it already holds and asks for `Prefer: count=exact`, so `Content-Range: 0-0/1` means the rows were admitted and `*/0` means RLS filtered them. Under `-no-residue` the no-op is replaced by a key collision, which aborts before touching the row. |
| `supabase-anon-delete-allowed` | critical if the relation is also readable, otherwise high | An anonymous `DELETE` removed a row and it was verified gone. The row is one this scan created moments earlier via the `INSERT` probe, never one of the target's — which is why the verdict is only available on relations that also accept `INSERT`, and is reported as not assessed everywhere else. |
| `unruly-relations-protected` | info | Relations that were recovered by enumeration and returned nothing to the anonymous role. Not a problem — recorded because enumeration is what this scanner pays for, and dropping the protected names discards most of the result: on one target 50 relations were recovered and 7 leaked. One finding lists them all; the names are only useful together. |
| `firebase-firestore-anon-read` | high; critical when the collection NAME is sensitive | A Firestore collection returns documents to a caller holding only the web API key. Proven with `:runQuery` projecting `__name__`, so document identifiers are quoted and field values are never retrieved. Only readable collections are reported: Firestore answers `403` identically for a protected collection and one that does not exist, so "protected" is not a measurement and is never claimed. Severity is refined from the collection NAME using the same classifier that rates a Supabase relation's columns — a readable `user_passwords` is critical — while document identifiers are deliberately not classified, because they are generated and a UUID says nothing about what it points at. |
| `firebase-rtdb-anon-read` | critical at the root or when a key NAME is sensitive, otherwise high | A Realtime Database path returns data to a caller with no credential at all. Proven with `?shallow=true`, which returns key names and no values. A readable root is reported alone, because everything beneath it is implied. The key names `?shallow=true` already returns are classified by the same rules that rate a Supabase relation's columns, so a readable path whose keys include `api_key` is critical — no values are retrieved to establish that. |
| `firebase-firestore-authenticated-read` | high | A collection that refuses anonymous callers returns documents to an account created moments earlier with the public web API key. This is `allow read: if request.auth != null`, which reads as secured: where signup is open, the set it admits is everyone. Only the DELTA is reported — collections anonymous callers already read are not repeated, and one scoped to `request.auth.uid` gains nothing from a fresh account and is not reported at all. |
| `firebase-auth-open-signup` | medium | Anyone holding the web API key can mint an authenticated identity. Normal on its own; it is what decides whether `request.auth != null` is an authorisation check or a formality. |
| `firebase-auth-anonymous-signin` | medium | A caller with no credentials at all received a session token, so `request.auth != null` is satisfied by anybody, with no signup form to rate-limit and no record of who did it. |
| `firebase-function-public` | high | A Cloud Function answered an unauthenticated call, so its invoker binding includes allUsers. Gated behind `-invoke`, because establishing this means running the function — and for the same reason names are never guessed: candidates come only from the application's own bundles and from `-vocab`, which is why a function no page mentions is not probed at all. The call budget is 25 names across the regions tried; names you supply are called FIRST and the harvested remainder is sampled across the whole list, so a supplied name is never lost to the budget. When the budget cuts anything it says so, because a name nobody called produces no finding and neither does a function that is not deployed. Note that function names are case-sensitive: `publicEcho` and `publicecho` are different URLs. |
| `firebase-function-private` | info | A Cloud Function is deployed and refused an unauthenticated call. A positive result: an undeployed name answers 404. |
| `firebase-storage-anon-read` | high; critical when the object NAMES classify as sensitive; low when listing is permitted but the bucket is empty | A Cloud Storage bucket lists its contents to a caller holding only the public web API key. |
| `firebase-storage-protected` | info | The bucket exists and refused the anonymous caller. A positive result, and the one Firebase surface where it can be claimed: Storage answers 404 for a bucket that does not exist, so a refusal means something is there and is closed. |
| `firebase-storage-absent` | info | The application ships a config naming a bucket that does not exist. Nothing is exposed; bucket names are a global namespace, so a name an app points at is worth owning. |
| `firebase-remote-config-secret` | critical, or low | The Remote Config template carries a credential-shaped or internal-endpoint value. Fetchability is *not* the finding — the template answers anyone holding the web API key by design — so only recognised content is reported, by name, never by value. |
| `firebase-firestore-anon-write` | critical | A caller holding only the public web API key created a document in the collection and it was accepted, so the rule admits writes from anybody. Gated behind `-write -yes-i-own-this`, because establishing this means writing. Probed ONLY on collections already shown readable: Firestore creates a collection implicitly on first write, so probing a guessed name would not fail against a collection that is not there — it would MAKE the thing it was asking about. That is a recall bound, stated in the report: a collection that refuses reads and accepts writes is a real shape (a drop box) and is not measured. The document is removed again, and if the rules allow create while refusing delete the finding says the probe is still there and names the field that identifies it. |
| `firebase-rtdb-anon-write` | critical | A caller with no credential at all wrote a key under the path and it was accepted. Rules cascade, so this covers everything beneath. Established with a CHILD key that did not previously exist, never by writing at the path itself: a `PUT` to a node REPLACES it, so the obvious probe would be data loss caused by a scan. The root is skipped even when writable — the finding would name `/` and tell an operator nothing about where to look, and every named path beneath it carries its own probe. |
| `unruly-probe-document-left-behind` | **high** | This scan created a Firestore document or a Realtime Database key and the delete that should have followed was refused — a rule allowing create while refusing delete, which people write deliberately. It carries the field `unruly_write_probe` and nothing depends on it. A statement about this scan rather than about the target, and high because somebody has to act on it. |
| `firebase-auth-weak-password` | low | The project accepted `123456`, so no policy is enforced above Firebase's six-character floor. |
| `pocketbase-anon-read-exposed` | high | An anonymous request listed records from a collection, so its `listRule` currently permits the whole world. The rows quoted were actually returned, not inferred from a status code. |
| `pocketbase-authenticated-escalation` | high | Registration is open and a registered account reads a collection an anonymous caller cannot. The collection answers 200 with zero rows to a stranger, so it is indistinguishable from an empty one until an account exists — which is why this needs an account to find at all. The account is created by the scan and deleted afterwards. |
| `neon-authenticated-write-allowed` | high | An authenticated request added a row to a table on a Neon Data API and the API accepted it. Row-Level Security is what constrains an INSERT to rows the caller may create; with no policy, any account may add anything, and where sign-up is open that is anyone. Gated behind `-write -yes-i-own-this`, because establishing this means performing it, and the consent is checked before any request is built rather than before the result is reported. Reported ONLY on 201: a 403/42501 is a denial. The row is NOT removed -- deleting needs a permission the write does not imply, and a scan that assumed otherwise would leave rows behind while reporting it had cleaned up -- so the finding names the marker value it wrote. |
| `neon-relations-disclosed` | info | The Data API volunteered table names the scan did not ask for. PostgREST answers a near-miss name with PGRST205 and a hint naming the real table, and an unrelated name draws nothing -- which is what makes a hint evidence about THIS schema rather than noise. Measured against the reference project: three near-miss seeds recovered all six tables, three of which were never guessed at. Only names the SERVER volunteered are reported; a wordlist guess that happened to exist is reconnaissance rather than disclosure, and the oracle records which is which. Enumeration needs a credential, because a headerless request is refused before any name is consulted, so without `-user-jwt` the check reports itself unassessed rather than returning an empty list that reads like a project with no tables. A name is not data, hence info -- what it changes is that the scan is no longer limited to what the operator already knew to ask for. |
| `neon-authenticated-read-unrestricted` | high | An authenticated request returned rows from a table on a Neon Data API. Neon grants the `authenticated` role whatever the table's GRANTs allow, and Row-Level Security is what narrows that to the caller's own rows; with RLS off, every account sees every row, and where sign-up is open that means anyone. Reported ONLY for tables that actually returned rows: a 403/42501 is a denial and a 200 with an empty array is a filtered or deny-all result, and neither is an exposure. That distinction is the point — Neon's own console warns that any table with RLS disabled lets all authenticated users read every row, which is false for a table no role holds a GRANT on. Two observations per table, because rows to an account only mean escalation against what an unauthenticated caller gets. |
| `supabase-authenticated-escalation` | critical with sensitive columns OR sensitive values, otherwise high | A relation invisible to `anon` is readable by `authenticated` — a role open signup hands to anyone who asks. Where the project withholds the session until the address is confirmed, `-mailbox` receives that mail so the tier is measured rather than skipped; a confirmation requirement admits anyone willing to receive a message, which is not a smaller set than the public. Without `-mailbox` such a project is reported as unmeasured with the reason named — never as though signup had been refused. Rated by both signals, exactly as the anonymous read is: the column names, and the kinds of data in the sampled rows. A logged-in user is not a smaller audience than the public where signup is open, so the same rows earn the same severity on either path. |
| `supabase-rpc-discoverable` | info; low when the name implies privilege but callability could not be established; medium when the anonymous role is shown to be able to invoke it | A routine name leaked through the PostgREST hint oracle. |
| `supabase-extra-schema-exposed` | info | PostgREST serves a schema beyond `public` and `graphql_public`. Discovered from the PGRST106 refusal, which names every exposed schema. Relations there are scanned and reported as `schema.relation`. |
| `supabase-graphql-rls-bypass` | high; never observed against Supabase, where pg_graphql builds its schema per role from privileges AND enforces RLS, so it is equal or more restrictive than REST. Measured by `make eval-graphql`, which fails if that stops being true | A relation that returned no rows over the REST API returned rows over pg_graphql at `/graphql/v1`. Both run the same policies, so this is one interface enforcing what the other does not. |
| `supabase-graphql-anon-read` | info; medium when any relation is a bypass | pg_graphql is enabled and serves rows to the anonymous role. Evidence is the decoded `nodeId`, which is base64 of `["schema","table",primary key]`. |
| `supabase-anon-arbitrary-sql` | critical | A routine took a SQL statement as an argument and executed it. This is the only route from an anon key to DDL — PostgREST exposes no endpoint for `DROP` — so it is what answers "can a stranger drop my database": if the routine is `SECURITY DEFINER`, yes. Proven by sending `SELECT 6*7 AS unruly_probe` over **GET**, which PostgREST runs in a read-only transaction, and requiring the computed answer `42` in the response: a routine that merely echoes its argument returns the text instead. No DDL is ever sent. |
| `supabase-rpc-returns-data` | critical | A routine handed rows to an anonymous caller. Usually `SECURITY DEFINER` over a relation whose RLS has no policy, so the direct read is empty and the function returns everything. |
| `supabase-public-storage-bucket` | medium | A bucket serves objects by URL with no authentication. Found by name, because buckets cannot be listed anonymously. | Graded on the bucket NAME: conventional asset names (images, avatars) are info, names suggesting documents or backups are medium, anything else low. The object names in the evidence are the real signal.
| `supabase-storage-anon-write` | critical | An anonymous caller uploaded an object and fetched it back. Making the bucket private does not fix this. |
| `supabase-realtime-anon-delivery` | high, or critical when REST refuses the relation | A row change was delivered to an anonymous listener. Proven by causing the change, never by a subscription acknowledgement. |
| `supabase-realtime-anon-subscription` | medium, or high when REST refuses the relation | Subscription accepted. Currently unreachable against Supabase, which acknowledges subscriptions for relations that do not exist. |
| `supabase-anonymous-signin-enabled` | medium | The project issues an `authenticated` session to a caller supplying no credentials, so every policy written TO authenticated admits everyone, with no form to rate-limit and no record of who did it. |
| `supabase-weak-password-policy` | low | Signup accepted `password123`, so nothing is enforced above the six-character floor. |
| `supabase-open-signup` | low, or medium with auto-confirm | Anyone can mint an `authenticated` session. |
| `supabase-service-key-exposed` | critical | A `service_role` or `sb_secret_` key is served to browsers. |
| `supabase-management-token-exposed` | critical | A Supabase personal access token (`sbp_`) is served to browsers. Scoped to the ACCOUNT, not the project: it lists every project in the organisation, reads their keys and database passwords, rotates them, and deletes projects. |
| `supabase-db-connection-string-exposed` | critical | A Postgres URI carrying a password is served to browsers. Direct database access: it bypasses PostgREST, so RLS and every policy elsewhere in the report are irrelevant to whoever holds it. Template strings (`[YOUR-PASSWORD]`, `${DB_PASSWORD}`) are deliberately NOT reported — Supabase's own dashboard hands those out and applications ship them in comments. |
| `supabase-project-ref-disclosure` | info | A response header names the project, turning "find the database behind this site" into a lookup. |
| `supabase-edge-function-no-jwt` | medium, or high when the name implies privilege | An Edge Function ran without credentials. |
| `supabase-preview-deployment-key` | medium, or low when it is the same key production serves | A preview deployment (branch build, deploy preview) serves a Supabase credential. A different key is one rotating production would not have touched. |
| `supabase-historic-service-key-exposed` | critical | A `service_role` key is in a public web archive. | Also fires for a Management API token or a Postgres connection string preserved in an archive — an archive is where a secret that was 'removed' still works.
| `supabase-historic-key-not-rotated` | high | An archived key is still the live key. Removing a key from a build does not revoke it. |
| `supabase-historic-key-rotated` | info | An archived key no longer works. |
| `app-route-auth-inconsistency` | medium, or high under a privileged-looking prefix | A route answers anonymously while at least two siblings for the same HTTP method demand credentials. Origin and method are part of the family key, so a protected POST cannot hide an exposed GET and two hosts cannot manufacture one family. Conventional public leaves such as health, status, metrics, guide and docs do not support this heuristic by themselves; their bodies still pass through the standalone sensitive-data classifier, so naming a route "health" cannot hide an actual credential or personal-data response. `-no-routes` skips this check and the vocabulary crawl. |
| `app-public-record-exposure` | severity from the data classifier: critical for a credential, high for financial, government-id or health, medium for pii, low for contact or location | An application endpoint answers 200 to a caller with no credentials and the response holds data worth protecting. Distinct from `app-route-auth-inconsistency`, which fires only when related routes DISAGREE about authorisation. Inconsistency is a proxy for a missing auth check and a good one, but it assumes an endpoint answering anonymously is fine if its siblings do too -- so an API where EVERY route is open scores perfectly consistent and the worst case is the blind spot. Measured on a real target: one endpoint returned a live database-backed record containing an employee address to anyone who asked, and was alone in its family, so it was discovered, probed, 200, and silent. THE CLASSIFIER IS THE DISCRIMINATOR: /health, /version and a public price list also answer 200 to anyone, and reporting them would bury the finding that matters, so an endpoint whose body holds nothing worth protecting is not reported at all. The exposed VALUE is never repeated in the finding and the CLASS always is -- a report that copies the leaked address is a second copy of the leak, and one that omits the class says something was exposed without saying what. |
| `app-openapi-schema-exposed` | info | The API returns its own OpenAPI or Swagger specification to a caller with no credentials. This is inventory, not a vulnerability: many APIs publish it deliberately. Its security value is that the named endpoints are added to the probe list, where their actual authorization is tested. The document is parsed and discarded; only path names and a count survive. |
| `app-docs-exposed` | info | An interactive API console (Swagger UI, ReDoc, RapiDoc, Scalar) is served to anonymous callers. This is also inventory rather than a vulnerability unless the operator's intent says it should be private. It is reported separately because a mounted UI and a static specification have different controls. |
| `app-auth-bypass` | high | A request the server REFUSES is served when the same resource is asked for differently: a rewrite header (X-Original-URL, X-Rewrite-URL) naming the protected path, a trust header (X-Forwarded-For: 127.0.0.1, X-Forwarded-Host: localhost), a case or normalisation variant (/Admin, //admin, /admin/., trailing slash), or a method the rule did not cover (HEAD, OPTIONS). The authorisation decision is being made on the SHAPE of the request rather than on who is asking. THREE CONDITIONS, each of which exists because dropping it produces noise: the canonical request must have been refused (401, 403 or 404 — an API hiding a resource behind "not found" is making an authorisation decision); the variant must return a body that DIFFERS from the refusal, because plenty of servers answer 200 carrying an error; and a header variant must differ from ITS OWN CONTROL, the identical request without the header — the rewrite variants ask for "/" and "/" returns the homepage on every ordinary site, so without that control every site with a homepage reports a bypass on every refused endpoint. No variant writes: a POST where GET is refused is a real bypass shape and also a request that can create something, so it belongs behind write consent and is not in this list. |
| `app-cross-identity-read` | high, or higher when the data classifier finds something worse in the record | One account reads another account's record: the endpoint checks that somebody is signed in and not that the record belongs to them, which is the difference between a login and an authorisation. NEEDS THREE ANSWERS AND WILL NOT RUN WITH FEWER — an anonymous caller must be REFUSED (if a stranger can read it there is no ownership to break, and a product catalogue serves every id to everyone), identity A must RECEIVE the record, and identity B must receive THE SAME BODY (a different body is the endpoint scoping correctly, which is the design we want rather than the one we report). Two identities are required for exactly this reason: with one there is no third answer to compare against and the check cannot be made sound, which is why adjacent-id guessing was not shipped before this. An empty body shared by both is not a shared record — two callers receiving nothing is not two callers receiving the same thing. Supply identities with -principal a=<jwt> -principal b=<jwt>, and the resource identifiers with -route-param. |
| `unruly-intent-violation` | high when deployed access is more permissive than intended; medium when it is more restrictive | A measured access fact disagrees with the versioned manifest supplied through `-intent`. An own-row expectation is not satisfied by an unscoped or all-row allow. The target policy and manifest must be reconciled explicitly; the scanner does not guess which one is stale. |
| `unruly-intent-summary` | info | Counts every supplied policy expectation as matched, violated, or unverified. Unverified expectations are also emitted as `unruly-surface-not-assessed` and never counted as passes. |

## What kinds of data a finding can name

The `HOLDS` column of the summary table, and the "holds ..." line of `-plain`,
name the KINDS of sensitive data in a relation. Never the values: a finding
that says a table contains card numbers is evidence, and one that quotes the
number is a second copy of the leak. `-redact` removes the sample; it does not
need to remove the class.

Seven classes, and this list is the whole vocabulary — `classify.Vocabulary()`
is the authority, and a test fails the build if the renderer can print a phrase
for a class nothing produces, or if a classifier produces a class the renderer
has no phrase for. Both directions, because both had already happened:
`contact`, `location` and `health` were printable for months and no rule had
ever emitted one.

| class | reported as | recognised by |
|---|---|---|
| `credential` | passwords or access tokens | `password`, `*_token`, `*_hash`, `*_salt`, `api_key`, `totp_secret`, `recovery_code`, `private_key` — and, by value, every shape in `internal/creds`: JWTs whose header actually decodes, `sb_secret_*`, `sk_live_*`, AWS keys, PEM blocks, bcrypt/argon2 hashes |
| `financial` | card or payment details | `credit_card`, `card_number`, `iban`, `cvv`, `bank_account`, `routing_number`, `sort_code`, `swift_code` — and, by value, a card number passing **both** Luhn and a real issuer prefix, or an IBAN passing mod-97 |
| `government-id` | government identifiers like passport, tax or social security numbers | `ssn`, `social_security*`, `passport*`, `tax_id`, `national_id`, `drivers_licence` |
| `health` | health information | `diagnosis`, `icd10`, `medication`, `prescription`, `allergies`, `blood_type`, `medical_record*` |
| `pii` | personal names and dates of birth | `first_name`, `last_name`, `full_name`, `surname`, `maiden_name`, `date_of_birth`, `dob` |
| `contact` | email addresses or phone numbers | `email`, `email_address`, `phone`, `mobile`, `msisdn` — and, by value, a syntactically valid email outside the reserved domains |
| `location` | postal addresses or coordinates | `address`, `home_address`, `postcode`, `zip_code`, `latitude`, `longitude` |

### Two classifiers, and why both

**By column name.** Cheap — it needs no rows retrieved, which matters when
retrieving them would mean copying somebody's data to prove a point the column
names already prove. It is the only one that works under `-measure`. It is also
English, and that is a real limit: a schema written in German, or one using
`notes`, `payload`, `data`, yields nothing from it.

**By sampled value.** Language-independent, and it is what catches the
sensitive thing inside a generic column — including a JSONB column holding
`{"card": "4111..."}`, a shape no name rule can ever see. It only sees the
SAMPLE (`-sample`, default 3), so it is a lower bound, and it is empty under
`-measure` by construction.

Their results are **unioned**, not preferred. They were combined with an
"else if", so any relation with one recognisable column name discarded every
value finding: a table with an `email` column and a service_role key in a
`notes` column reported contact data and stayed silent about the credential.

### A third classifier, optional and separable

`-classifier` points at a LOCAL model server and asks it about columns the two
rules above left unclassified. Off by default, and everything it produces
lands in `model_classes`, never in `classes`.

The two lists are kept apart permanently because they carry different weight.
A class in `classes` was proven: a card number passed Luhn and an issuer-length
check, an IBAN satisfied mod-97, a JWT header decoded. A class in
`model_classes` is a model's opinion about a street address or a diagnosis --
text carrying nothing checkable. Measured across 500 ordinary columns, the
rules tagged 2 and the model tagged 80.

Three guarantees, each held by a test rather than by care:

  * A column the rules classified is never sent to the model. Not preferred
    over, not compared against -- never asked.
  * A class arrives only above `-classifier-threshold` (default 80).
  * `model_classes` is `omitempty`, so a scan without a model writes the bytes
    it always wrote.

**Measured**, on 550 positives and 500 negatives across 22 data classes and 25
languages, through this code path against Ollama:

| | recall | false positives |
|---|---:|---:|
| rules alone | 14.9% | 0.4% |
| rules + Qwen3.5-4B | **88.0%** | 16.4% |

**The model matters more than any other choice here.** The same benchmark with
`llama3.2:3b` returns 4.4% recall and tags 89% of ordinary columns -- it
contributes nothing and destroys precision. A 4B-class model is the floor:
below it, the ability to answer "none" disappears before accuracy does.

Two settings are load-bearing and are sent automatically. Reasoning must be
disabled, or a reasoning model emits a thinking block where the answer should
be and no class is readable at all. And the prompt demands a bare letter:
without that the model starts a sentence, the correct class ranks second, and
a right answer is discarded as unconfident.

### What precision costs, and what it is worth

Every rule here is structural rather than statistical, and rules that cannot be
checked that way are left out however tempting. Luhn alone is not enough — one
in ten random digit strings passes it, so a table of sixteen-digit order
numbers would report as financial roughly every tenth row. A bare `name` column
is not personal data: it is a product, a file, a table, a branch. `ip_address`,
`mac_address`, `wallet_address` and `contract_address` identify a machine, a
mailbox or a blockchain account, and are excluded by name.

The cost is recall, and it is stated rather than hidden: **a relation with no
class named is not a relation known to be harmless.** It is one where no rule
matched. `HOLDS` is empty far more often than a database is boring.

### Known gaps

- No rule reads free text for names, addresses or health terms. Detecting
  those reliably needs statistics, and a statistical rule here would produce
  exactly the false positives that make a severity column worthless.
- Non-English column names are only reached by the value classifier, so a
  German schema of `passwort` and `anschrift` is classified from its data or
  not at all — and not at all under `-measure`.
- The value classifier sees `-sample` rows. A card number in row 4,000 of a
  table sampled three rows deep is not found.

## Findings about the scan

These describe what the scan could not do. They are Info because severity ranks
how bad something is on the TARGET, and none of these say anything about it — a
reader filtering `severity >= medium` for things to fix must not be handed a
scanner diagnostic.

| ID | Severity | What it means |
|---|---|---|
| `unruly-capability-degraded` | info | An oracle the scan depends on did not behave as expected, so recall is reduced. |
| `unruly-surface-not-assessed` | info | A surface could not be reached, or could not be told apart from a catch-all. Also emitted with resource `application` when `-site` was supplied and could not be harvested: enumeration then runs on the pinned wordlist alone, so every relation count is a lower bound and the report is shorter for a reason it would otherwise not record. Also emitted with resource `write-verbs:unreadable-relations` when any relation returned no rows: UPDATE and DELETE cannot be established without a row to aim at, so on those relations they were never established at all — and the per-relation notes are deliberately gated on readability, because otherwise every correctly hardened table collects two coverage findings and exit 3 stops meaning anything. One statement per scan instead, naming the relations. The usual over-grant is a policy written FOR ALL, which grants SELECT as well and is therefore covered; a policy granting INSERT or UPDATE without SELECT is not. Also emitted with resource `firebase:no-credential` when no web API key was recovered from the application: Firestore, Auth and Remote Config each need one and each returns silently without it, so three surfaces would otherwise be absent from the report and read as three that came back sound. Measured against the lab, which is why it is worth a line: a collection whose rule is `allow read: if true` answers 200 WITH DOCUMENTS to a request carrying an empty key, while one that cannot exist answers 403 — the rules are evaluated whether or not a key is presented, so the skipped surface may be wide open. That is not a reason to probe without one, since App Check and key restrictions change it and one project does not generalise; it is a reason to say so. Also emitted with resource `rtdb:<host>` when a Realtime Database answers 200 with no keys at its root: the rules never replied, so nothing about that database was established, and a report carrying no Realtime findings would otherwise read as one that was checked and found sound. That is an empty database with an open root, or an address that is not this project's -- databaseURL is read from the application's own bundle, so a project that was renamed, moved region or shipped a stale config points the probe somewhere that answers politely and holds nothing. Measured against the Firebase emulator, which selects its namespace with `?ns=`: with the namespace wrong, every path answered 200 null including one that is denied when addressed correctly. A database whose rules refuse answers 401, which is the discriminator, and is why a correctly locked project collects no note here. Also emitted with resource `scan:interrupted` when the scan was stopped before it finished (Ctrl-C, a CI timeout): the findings written are real but the list is a fragment, and the cancelled requests would otherwise surface as "the target did not answer", reading as a broken target rather than an unfinished scan. |
| `unruly-stage-skipped` | info | A stage of the scan was NOT RUN because the operator did not ask for it, and the reason names the option that would enable it. Distinct from `unruly-surface-not-assessed`, and the distinction is this tool's own argument applied to its own plumbing: "could not be assessed" means the scan tried and the surface refused, which drives exit 3 because an unexamined surface must not pass for a clean one; "was not run" means the scan was told not to look. Reporting a deliberate skip as a failure tells somebody to fix a cause that is their own flag, and inflates exit 3 into a number that no longer separates a blind scan from a narrow one. Emitted once per skipped stage, so an agent reading the stream can see exactly which surfaces a given invocation covered; `unruly-checks-skipped` remains the single human-facing summary of the same fact. |
<!-- fix-plan note -->
The plan chooses its row-level-security statement at run time. PostgREST exposes **views** as relations indistinguishably from tables, a scan cannot read `pg_class` from outside, and `ALTER TABLE … ENABLE ROW LEVEL SECURITY` is an *error* on a view rather than a no-op — so the plan emits a `DO` block that applies `security_invoker = true` to a view and row-level security to a table. That default of `security_invoker = false` is also why a correctly protected table can leak every row through a view over it.

Every finding may declare **where** its remediation is applied — `sql`, `rules-file`, `console`, `rotate-credential` — carried in the JSONL as `fix_kind` and shown in the plan. Unstated is never treated as SQL: most findings predate the field, and guessing "database" would put console instructions into a script somebody executes. The non-SQL section groups by destination, so an operator finishes the rules file before opening the console.

The `-fix` flag prints each finding's own remediation, whatever the backend. The grouped plan — used by the HTML report's copy-all button — additionally collects steps that are **not** SQL (rules files, console settings, redeploys) into their own section, as comments, because that file is piped into `psql`. Before this, a Firebase-only report produced a plan of zero characters while a single Supabase finding produced 814, so an operator with two critical findings was handed an empty box.

| `unruly-scan-summary` | info | How much was examined: relations discovered, schemas, requests. Not a claim that anything is wrong — the denominator for everything else, so a stored report with no exposures can be told apart from a scan that discovered nothing. |
| `unruly-checks-skipped` | info | Checks that did not run, with the flag that enables each — those needing write consent, those turned off by a flag, and `role-escalation`, which is listed on every scan without `-user-jwt` because a default scan reads only as `anon` and cannot speak for policies written `TO authenticated`. |
| `unruly-probe-account-left-behind` | info | This scan registered a user account to measure what a logged-in user can reach, and cannot delete it. Reused on later scans, so one per project. |
| `unruly-credential-rejected` | info | Every request was answered 401/403 and none accepted, so the key does not work here and nothing below describes the project. |
| `unruly-rest-prefix-corrected` | info | PostgREST answered PGRST125 under the default mount path and served its OpenAPI document at the root; the scan continued there. |
| `unruly-rest-prefix-unresolved` | info | PostgREST rejected the mount path and no alternative was confirmed, so probing stopped; nothing about the data was measured. |
| `unruly-subdomains-found` | info | Other hosts resolve under the target's domain. None are scanned and nothing is claimed about them: a second deployment is where an old key with looser policies tends to still be live, and scanning it is the operator's decision. |
| `unruly-target-refused` | info | The host refused every request (429, 5xx, or no answer), so probing stopped and NOTHING about the project was measured. |
| `unruly-target-not-discriminating` | info | The target answered as though a relation that cannot exist does, so discovery, read and write exposure were all skipped. |
| `unruly-probe-budget-exhausted` | info | A probe budget bound the search, so the list is a lower bound. Emitted for relation discovery (`-max-relation-probes`), routine discovery (`-max-rpc-probes`), harvested vocabulary (`-max-seeds`), sensitive-column probing (`-max-column-probes`), the application inventory (`-max-routes`), and the more expensive alternative-request matrix (`-max-bypass-routes`). Route and origin selection is round-robin, so one large origin cannot consume the allowance before another receives a probe. Relation, application-route, and sensitive-column truncation count toward exit 3; routine, vocabulary, and bypass-matrix defaults bind often by design and remain visible without making every ordinary run incomplete. |
| `unruly-probes-unresolved` | info | Probes got no readable answer, usually rate limiting. The relation list is a lower bound.  The cause is recorded and the advice follows it: a throttling host is told to slow the scan, a host answering `PGRST002` (PostgREST running but its schema cache not yet loaded, for a window after a deploy) is told to wait and re-run, and a host that never answered is told to check reachability. Advising a slower scan for a cold server sends the operator to tune a knob that was never the problem. |
| `unruly-probe-row-left-behind` | **high** | A write probe created a row it could not delete. |
| `unruly-probe-object-left-behind` | **high** | A write probe uploaded an object it could not delete. |

`unruly-probe-row-left-behind` is the one exception to the Info rule
above, and deliberately. The others say the scan could not see something. This
one says the scan CHANGED something: a row exists in somebody's database
because this tool put it there and could not take it back. That is not a
severity judgement about their configuration, it is work the operator now has
to do, and burying it at Info among coverage notes would be the tool hiding its
own mess.
