#!/usr/bin/env bash
# Generate the lab's application page.
#
# One generator, called from both fixtures-up and fixtures-reset. It was a
# printf duplicated in two Makefile targets, which is the shape that drifts:
# whichever target somebody edits, the other keeps serving the old page and the
# eval that depends on it passes or fails depending on which command was run
# last.
#
# The page has three jobs.
#
#  1. Ship a service_role key to the browser, so the credential check has
#     something to find. Minted here rather than committed: a JWT-shaped string
#     in the tree trips this repository's own secret scan.
#
#  2. Reference the /api/admin family, because routes are discovered from the
#     application's own markup and the inconsistency check cannot see a route
#     nothing links to.
#
#  3. NAME THE TABLES IT USES, which is what a real application's bundle does
#     and what this page did not do. Vocabulary harvesting is the mechanism that
#     recovered 21 relations of 21 on the reference target where a generic
#     wordlist matched 1; with a page that named none of the schema, the harvest
#     produced words matching nothing, and that path went untested while looking
#     tested.
#
# open_no_rls_archive is deliberately absent. The answer key describes it as
# "named nowhere in any application; reachable only via the hint oracle", and
# that is a real shape -- an old table the current code no longer touches. It is
# what keeps the oracle honest once harvesting works.
set -euo pipefail
out=${1:?usage: make-site.sh <output-path>}
key=$(python3 "$(dirname "$0")/../mint-jwt.py" --role service_role)

cat > "$out" <<HTML
<!doctype html><html><body>
<a href="/api/admin/users">users</a>
<a href="/api/admin/settings">settings</a>
<a href="/api/admin/logs">logs</a>
<a href="/api/public/stats">stats</a>
<a href="/api/public/health">health</a>
<a href="/api/public/version">version</a>
<script>
const SUPABASE_URL="http://127.0.0.1:54321";
const SUPABASE_SERVICE_ROLE_KEY="${key}";

// The queries this application makes, the way a bundled client makes them.
const loadOpen        = () => sb.from('open_no_rls').select('*');
const loadCreds       = () => sb.from('leaky_credentials').select('email, api_key');
const loadTokens      = () => sb.from('tokens').select('user_email, confirmation_token');
const loadDefaults    = () => sb.from('all_defaults_insertable').select('*');
const loadReadOnly    = () => sb.from('read_only_policy').select('id, title');
const submitFeedback  = (row) => sb.from('write_only_policy').insert(row);
const loadProtected   = () => sb.from('protected_rls_no_policy').select('*');
const loadAuthed      = () => sb.from('authenticated_only').select('*');
const loadMine        = () => sb.from('owner_scoped').select('*');
const loadContent     = () => sb.from('public_site_content').select('slug, title, body');
const loadOneColumn   = () => sb.from('content_one_column').select('*');
const loadWritable    = () => sb.from('content_but_writable').select('*');
const loadWithPII     = () => sb.from('content_with_pii').select('*');
const loadNested      = () => sb.from('nested_payloads').select('app_state');
const loadVerbOpen    = () => sb.from('verb_update_open').select('*');
const loadVerbRead    = () => sb.from('verb_read_only').select('*');
const loadVerbDelete  = () => sb.from('verb_delete_open').select('*');
const loadVerbAll     = () => sb.from('verb_all_open').select('*');
const loadVerbNoIns   = () => sb.from('verb_update_noinsert').select('*');
const loadVerbIdent   = () => sb.from('verb_identity_key').select('*');
const rebuildRevenue  = () => sb.rpc('rebuild_daily_revenue');
const purge           = () => sb.rpc('admin_purge_submissions');
</script></body></html>
HTML
