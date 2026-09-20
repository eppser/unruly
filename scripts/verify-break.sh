#!/usr/bin/env bash
# verify-break.sh PACKAGE TEST_PATTERN FILE 'OLD' 'NEW'
#
# Break one thing on purpose and report whether the tests noticed.
#
# The point is the build check. Three times in one week a break was applied,
# the tests reported zero failures, and that was read as "the guard does not
# catch this" -- when the truth was that the edit had left a variable unused,
# the package had not compiled, and NO TEST HAD RUN. Zero failures and a clean
# pass are the same number.
#
# scripts/mutate.py learned this already: it carries --buildcheck because "a
# mutation that does not compile is scored as CAUGHT ... it then reports as
# caught forever while testing nothing". That reasoning applies just as much to
# a break typed by hand during development, and this is where that happens.
#
# Exit 0 means the break was applied, the package still built, and the tests
# were asked. Read the count. Exit 1 means the question was never put.
set -uo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 PACKAGE TEST_PATTERN FILE 'OLD' 'NEW'" >&2
  exit 2
fi
pkg="$1" pattern="$2" file="$3" old="$4" new="$5"

[ -f "$file" ] || { echo "no such file: $file" >&2; exit 2; }
backup="$(mktemp)"
cp "$file" "$backup"
restore() { cp "$backup" "$file"; rm -f "$backup"; }
trap restore EXIT

applied=$(OLD="$old" NEW="$new" python3 - "$file" <<'PY'
import os, sys
p = sys.argv[1]
s = open(p).read()
old, new = os.environ["OLD"], os.environ["NEW"]
n = s.count(old)
if n != 1:
    print(n)
    sys.exit(0)
open(p, "w").write(s.replace(old, new, 1))
print(1)
PY
)
if [ "$applied" != "1" ]; then
  echo "REFUSED: the text to replace appears $applied times, not once." >&2
  echo "A break that matched nothing proves nothing, and one that matched twice" >&2
  echo "changed something you did not read." >&2
  exit 1
fi

if ! go build ./... >/dev/null 2>&1; then
  echo "REFUSED: the break does not compile, so no test can run against it." >&2
  echo "Zero failures would look exactly like a guard that caught nothing." >&2
  echo "Rewrite it so the package still builds -- '&& false' rather than deleting" >&2
  echo "the branch, if the variable would otherwise go unused." >&2
  exit 1
fi

# -v, because the count of tests that actually RAN is the thing that must not
# be guessed. Without it `go test` prints "ok ... [no tests to run]" for a
# pattern that matched nothing, which reads as a pass -- the same conflation of
# "measured and fine" with "never asked" that this script exists to refuse, and
# which it made on its own first outing.
out=$(go test "$pkg" -run "$pattern" -count=1 -v 2>&1)
ran=$(printf '%s' "$out" | grep -cE '^=== RUN' || true)
fails=$(printf '%s' "$out" | grep -cE '^ *--- FAIL' || true)
if [ "$ran" -eq 0 ]; then
  echo "REFUSED: no test matched $pattern in $pkg, so nothing was asked." >&2
  exit 1
fi
if [ "$fails" -eq 0 ]; then
  echo "SURVIVED: $ran test(s) ran against the break and none failed."
  echo "That is a real result: this behaviour is unguarded."
else
  echo "CAUGHT: $fails of $ran test(s) failed."
  printf '%s\n' "$out" | grep -E '^ *--- FAIL' | head -5
fi
# Both outcomes are answers. Only a question that was never put is an error.
exit 0
