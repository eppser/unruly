#!/usr/bin/env bash
# Seed the Firebase emulators. Run by ../verify.sh after `docker compose up`.
#
# Seeding goes through the emulators' own REST APIs with `Authorization: Bearer
# owner`, which is the documented admin bypass: rules are not evaluated for it.
# That matters — the rules deny most of what is written here, so a seeding path
# that respected them could not create the data the checks then fail to read.
#
# Idempotent: every write is a PUT or a document-id'd POST, so re-running
# replaces rather than accumulates.
set -euo pipefail

PROJECT=unruly-bench-14
FS=http://127.0.0.1:54531/v1/projects/$PROJECT/databases/'(default)'/documents

# The Realtime Database namespace is NOT the project id.
#
# This cost an hour. The emulator serves whatever `?ns=` you ask for and
# CREATES an unknown namespace on demand, with default rules of
# {".read": true, ".write": true}. So `?ns=unruly-bench-14` answered 200 for
# every path, the rules file appeared to be ignored, and the target looked
# wide open. It was a namespace that had never existed, invented by the
# request that asked for it. The configured rules live on
# <project>-default-rtdb. Recorded in the README as the fixture's sharpest
# divergence from production, where a wrong namespace is simply a wrong host.
NS=$PROJECT-default-rtdb
RT=http://127.0.0.1:54532

fs_put() { # collection, docId, fields-json
  curl -sS -o /dev/null -w "" -X PATCH "$FS/$1/$2" \
    -H 'Authorization: Bearer owner' -H 'Content-Type: application/json' \
    --data-binary "$3"
}

rt_put() { # path, json
  curl -sS -o /dev/null -X PUT "$RT/$1.json?ns=$NS" \
    -H 'Authorization: Bearer owner' --data-binary "$2"
}

# --- Firestore -------------------------------------------------------------
# Wide open in both directions: the "test mode" rule left on.
fs_put user_profiles u1 '{"fields":{"email":{"stringValue":"dana@example.invalid"},"phone":{"stringValue":"+1-555-0101"},"password_hash":{"stringValue":"$2b$12$K8h5vQZ0000000000000uOe1JmQ0000000000000000000000"}}}'
fs_put user_profiles u2 '{"fields":{"email":{"stringValue":"marcus@example.invalid"},"phone":{"stringValue":"+1-555-0102"},"password_hash":{"stringValue":"$2b$12$L9i6wR1A111111111111vPf2KnR1111111111111111111111"}}}'
fs_put user_profiles u3 '{"fields":{"email":{"stringValue":"priya@example.invalid"},"phone":{"stringValue":"+1-555-0103"},"password_hash":{"stringValue":"$2b$12$M0j7xS2B222222222222wQg3LoS2222222222222222222222"}}}'
fs_put user_profiles u4 '{"fields":{"email":{"stringValue":"tomas@example.invalid"},"phone":{"stringValue":"+1-555-0104"},"password_hash":{"stringValue":"$2b$12$N1k8yT3C333333333333xRh4MpT3333333333333333333333"}}}'
fs_put user_profiles u5 '{"fields":{"email":{"stringValue":"elena@example.invalid"},"phone":{"stringValue":"+1-555-0105"},"password_hash":{"stringValue":"$2b$12$O2l9zU4D444444444444ySi5NqU4444444444444444444444"}}}'

# World-readable by design. Reporting this is a false positive.
fs_put public_announcements a1 '{"fields":{"title":{"stringValue":"Bench Chat 2.4 is out"},"body":{"stringValue":"Threaded replies, faster search, and a new dark theme."}}}'
fs_put public_announcements a2 '{"fields":{"title":{"stringValue":"Scheduled maintenance"},"body":{"stringValue":"We will be offline for 20 minutes on the first Sunday of next month."}}}'
fs_put public_announcements a3 '{"fields":{"title":{"stringValue":"We are hiring"},"body":{"stringValue":"Two openings on the platform team. Write to jobs@example.invalid."}}}'

# Denied in both directions.
fs_put billing_secrets s1 '{"fields":{"stripe_secret_key":{"stringValue":"sk_test_00000000000000000000000000"},"card_number":{"stringValue":"4111111111111111"}}}'
fs_put billing_secrets s2 '{"fields":{"stripe_secret_key":{"stringValue":"sk_test_11111111111111111111111111"},"card_number":{"stringValue":"5555555555554444"}}}'

# Readable by ANY signed-in user, and anonymous sign-in is enabled.
fs_put employee_records e1 '{"fields":{"name":{"stringValue":"Dana Whitfield"},"salary_usd":{"integerValue":"142000"},"home_address":{"stringValue":"1 Fictional Street, Nowhere"}}}'
fs_put employee_records e2 '{"fields":{"name":{"stringValue":"Marcus Oyelaran"},"salary_usd":{"integerValue":"128500"},"home_address":{"stringValue":"2 Fictional Street, Nowhere"}}}'
fs_put employee_records e3 '{"fields":{"name":{"stringValue":"Priya Raghunathan"},"salary_usd":{"integerValue":"161000"},"home_address":{"stringValue":"3 Fictional Street, Nowhere"}}}'
fs_put employee_records e4 '{"fields":{"name":{"stringValue":"Tomas Berg"},"salary_usd":{"integerValue":"117250"},"home_address":{"stringValue":"4 Fictional Street, Nowhere"}}}'

# Correctly owner-scoped: signing in gains nothing unless you are the owner.
fs_put private_notes n1 '{"fields":{"owner_uid":{"stringValue":"uid-dana"},"note":{"stringValue":"renewal call thursday"}}}'
fs_put private_notes n2 '{"fields":{"owner_uid":{"stringValue":"uid-marcus"},"note":{"stringValue":"expense report overdue"}}}'
fs_put private_notes n3 '{"fields":{"owner_uid":{"stringValue":"uid-priya"},"note":{"stringValue":"draft the incident review"}}}'

# --- Realtime Database -----------------------------------------------------
rt_put public_config '{"app_name":"Bench Chat","min_version":"2.4.0","support_url":"https://example.invalid/help"}'
rt_put admin_tokens '{"svc_deploy":{"token":"sk_live_admin_0001","rotated_at":"2026-01-04"},"svc_backup":{"token":"sk_live_admin_0002","rotated_at":"2025-11-19"}}'
rt_put open_chat '{"lobby":{"m1":{"from":"dana@example.invalid","text":"morning"},"m2":{"from":"tomas@example.invalid","text":"standup in 5"}},"private_dm":{"d1":{"from":"marcus@example.invalid","to":"priya@example.invalid","text":"the shared account password is hunter2-not-real"}}}'

echo "seeded firestore (5 collections) and rtdb ns=$NS (3 subtrees)"
