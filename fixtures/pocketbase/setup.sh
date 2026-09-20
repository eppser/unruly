#!/usr/bin/env bash
# Provision the PocketBase ground-truth fixtures: one deliberately vulnerable
# instance and one hardened, with THE SAME collection names in both.
#
# The same names in both is the point. If the hardened instance lacked a name,
# a scan of it would 404 there and score clean for the wrong reason -- the
# collection was absent, not protected. With the names present and the rules
# closed, a clean result means the scanner read the rules correctly.
#
# Every rule below was measured against a real instance before being written
# here; see docs/pocketbase-ground-truth.md for the truth table and for the
# three traps that measurement caught.
#
#   ./setup.sh            provision both instances and leave them serving
#   ./setup.sh --down     stop them and delete their data
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="${PB_VERSION:-0.39.11}"
VULN_PORT="${PB_VULN_PORT:-8090}"
HARD_PORT="${PB_HARD_PORT:-8091}"
ADMIN="admin@lab.local"
# Lab-only credential. Never a real secret: these instances hold bait rows and
# are destroyed by --down.
PASS="labpass123456"

if [ "${1:-}" = "--down" ]; then
  pkill -f "pocketbase.*--dir $HERE/vuln_data" 2>/dev/null
  pkill -f "pocketbase.*--dir $HERE/hard_data" 2>/dev/null
  sleep 1
  rm -rf "$HERE/vuln_data" "$HERE/hard_data" "$HERE/vuln_migrations" "$HERE/hard_migrations"
  echo "pocketbase fixtures down"
  exit 0
fi

BIN="$HERE/bin/pocketbase"
if [ ! -x "$BIN" ]; then
  echo "fetching pocketbase $VERSION"
  mkdir -p "$HERE/bin"
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) A=darwin_arm64 ;;
    Darwin/x86_64) A=darwin_amd64 ;;
    Linux/aarch64) A=linux_arm64 ;;
    Linux/x86_64) A=linux_amd64 ;;
    *) echo "unsupported platform $(uname -s)/$(uname -m)"; exit 1 ;;
  esac
  curl -sL -o /tmp/pb.zip \
    "https://github.com/pocketbase/pocketbase/releases/download/v${VERSION}/pocketbase_${VERSION}_${A}.zip" || exit 1
  (cd "$HERE/bin" && unzip -oq /tmp/pb.zip pocketbase) || exit 1
  rm -f /tmp/pb.zip
fi

# Each instance gets its OWN migrations directory.
#
# PocketBase writes auto-migrations for schema changes into the working
# directory and applies them at startup. Provisioned in a shared directory, the
# hardened instance applied the VULNERABLE one's migrations and came up as an
# exact clone of it -- readable collections and all -- while its creation calls
# returned 400 "already exists". A health check passed and it looked fine. The
# precision fixture would have been identical to the recall fixture, and every
# true finding scored against it would have read as a false positive.
start() { # dir port
  # REFUSE if something already holds the port, and say WHAT holds it.
  #
  # Without this the readiness probe below can be satisfied by a stranger.
  # Measured on this machine: an ssh port-forward held 8090 and answered
  # /api/health with "404 page not found". The old probe accepted it, so setup
  # configured collections through the API against somebody else's server and
  # every PocketBase test passed against the wrong instance -- including the
  # run that was supposed to prove these fixtures reproduce from the repo.
  #
  # "8090 is held by ssh (pid 87408)" tells an operator what to do.
  # "did not come up" does not.
  holder=$(lsof -nP -iTCP:"$2" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" (pid "$2")"}')
  if [ -n "$holder" ]; then
    echo "port $2 is already held by $holder; refusing to start $1 there."
    echo "stop it, or set PB_VULN_PORT / PB_HARD_PORT to ports that are free."
    return 1
  fi

  mkdir -p "$HERE/$1_migrations"
  "$BIN" --dir "$HERE/$1_data" --migrationsDir "$HERE/$1_migrations" \
    superuser create "$ADMIN" "$PASS" >/dev/null 2>&1
  nohup "$BIN" --dir "$HERE/$1_data" --migrationsDir "$HERE/$1_migrations" \
    serve --http="127.0.0.1:$2" > "$HERE/$1.log" 2>&1 &
  pid=$!

  for _ in $(seq 1 20); do
    sleep 0.5
    # -sf, so a 404 is a failure. `curl -s -o /dev/null` exits 0 for ANY
    # response, which is exactly how a 404 from an unrelated service read as
    # healthy for as long as this file has existed.
    #
    # And kill -0 on the pid we launched: "it came up" has to mean THIS
    # instance came up, not that something answers on the port. The health
    # check has now been fooled twice -- once by a shared migrations dir that
    # made the hardened instance a clone, once by a stranger on the port --
    # so it checks identity, not liveness.
    if kill -0 "$pid" 2>/dev/null &&
       curl -sf -o /dev/null "http://127.0.0.1:$2/api/health"; then
      return 0
    fi
  done
  echo "instance $1 did not come up on $2; last lines of $HERE/$1.log:"
  tail -3 "$HERE/$1.log" 2>/dev/null
  return 1
}

token() { # port
  curl -s -X POST "http://127.0.0.1:$1/api/collections/_superusers/auth-with-password" \
    -H "Content-Type: application/json" \
    -d "{\"identity\":\"$ADMIN\",\"password\":\"$PASS\"}" |
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))'
}

mk() { # port token name listRule viewRule createRule updateRule deleteRule
  curl -s -o /dev/null -X POST "http://127.0.0.1:$1/api/collections" \
    -H "Authorization: $2" -H "Content-Type: application/json" \
    -d "{\"name\":\"$3\",\"type\":\"base\",\"fields\":[{\"name\":\"title\",\"type\":\"text\"},{\"name\":\"secret\",\"type\":\"text\"}],\"listRule\":$4,\"viewRule\":$5,\"createRule\":$6,\"updateRule\":$7,\"deleteRule\":$8}"
}

# mkfile creates a collection with a FILE field, which mk cannot: the file
# surface is a different exposure shape and it was missing from these fixtures
# entirely. docs/pocketbase-ground-truth.md records the measurement it backs --
# a file field's `protected` option defaults to FALSE and /api/files/... does
# not consult the collection's viewRule, so a collection whose record API is
# fully closed still serves every uploaded file to anyone holding the URL.
#
# protected is set explicitly on both, rather than relying on the default,
# because the whole point is which of the two values is in force.
mkfile() { # port token name protected listRule viewRule
  curl -s -o /dev/null -X POST "http://127.0.0.1:$1/api/collections" \
    -H "Authorization: $2" -H "Content-Type: application/json" \
    -d "{\"name\":\"$3\",\"type\":\"base\",\"fields\":[{\"name\":\"title\",\"type\":\"text\"},{\"name\":\"doc\",\"type\":\"file\",\"protected\":$4,\"maxSelect\":1}],\"listRule\":$5,\"viewRule\":$6,\"createRule\":null,\"updateRule\":null,\"deleteRule\":null}"
}

# upload puts a real file in the collection, because the finding this fixture
# backs is about RETRIEVING one. A collection with a file field and no file in
# it proves nothing.
upload() { # port token name
  printf 'card-4111111111111111\n' > "$HERE/bait.txt"
  curl -s -o /dev/null -X POST "http://127.0.0.1:$1/api/collections/$3/records" \
    -H "Authorization: $2" \
    -F "title=bait" -F "doc=@$HERE/bait.txt"
  rm -f "$HERE/bait.txt"
}

seed() { # port token name
  curl -s -o /dev/null -X POST "http://127.0.0.1:$1/api/collections/$3/records" \
    -H "Authorization: $2" -H "Content-Type: application/json" \
    -d '{"title":"bait","secret":"card-4111111111111111"}'
}

start vuln "$VULN_PORT" || exit 1
start hard "$HARD_PORT" || exit 1
TV="$(token "$VULN_PORT")"; TH="$(token "$HARD_PORT")"
[ -n "$TV" ] && [ -n "$TH" ] || { echo "could not authenticate as superuser"; exit 1; }

# Vulnerable: one collection per exposure shape. An empty-string rule is open
# to the world; null is superuser only; an expression behaves as a FILTER and
# answers 200 with zero rows, which is the trap that makes status codes useless
# here.
mk "$VULN_PORT" "$TV" public_notes '""'  '""'  null  null  null
mk "$VULN_PORT" "$TV" locked_notes null  null  null  null  null
mk "$VULN_PORT" "$TV" open_create  null  null  '""'  null  null
mk "$VULN_PORT" "$TV" open_write   '""'  '""'  '""'  '""'  '""'
mk "$VULN_PORT" "$TV" view_only    null  '""'  null  null  null

# The file surface. open_files is readable as a record AND serves its file;
# locked_files refuses every record operation and STILL serves its file,
# because protected defaults to false and the file route does not consult
# viewRule. That second one is the finding -- a collection an operator has
# fully closed, handing out its contents to anyone with the URL.
mkfile "$VULN_PORT" "$TV" open_files   false '""' '""'
mkfile "$VULN_PORT" "$TV" locked_files false null null
upload "$VULN_PORT" "$TV" open_files
upload "$VULN_PORT" "$TV" locked_files
# The expression rule needs its quotes escaped for JSON, not for the shell.
# Written with shell-level escaping first, it produced invalid JSON, the
# collection was never created, and the fixture answered 404 where it should
# have answered 200-with-zero-rows -- caught by verifying the script's output
# against the measured truth table rather than trusting that it ran.
AUTHED_RULE='"@request.auth.id != \"\""'
mk "$VULN_PORT" "$TV" authed_only "$AUTHED_RULE" "$AUTHED_RULE" null null null
for c in public_notes locked_notes open_write view_only authed_only; do
  seed "$VULN_PORT" "$TV" "$c"
done

# Hardened: the SAME names, every rule null, each holding a bait row.
#
# The file collections are mirrored with protected TRUE, which is the
# remediation for the file finding: the record API is closed on BOTH
# instances, and only the hardened one also refuses to serve the file. Same
# names in both, so a hardened instance cannot score clean merely by 404ing.
for c in open_files locked_files; do
  mkfile "$HARD_PORT" "$TH" "$c" true null null
  upload "$HARD_PORT" "$TH" "$c"
done
for c in public_notes locked_notes open_create open_write view_only authed_only; do
  mk "$HARD_PORT" "$TH" "$c" null null null null null
  seed "$HARD_PORT" "$TH" "$c"
done
# And registration closed. PocketBase ships users.createRule as an EMPTY
# STRING, so anyone in the world may create an account on a default install --
# which is why the vulnerable instance keeps the default and this one does not.
curl -s -o /dev/null -X PATCH "http://127.0.0.1:$HARD_PORT/api/collections/users" \
  -H "Authorization: $TH" -H "Content-Type: application/json" -d '{"createRule":null}'

echo "vulnerable: http://127.0.0.1:$VULN_PORT"
echo "hardened:   http://127.0.0.1:$HARD_PORT"
echo "run the graded checks with: UNRULY_PB_LAB=1 go test ./backend/pocketbase/"
