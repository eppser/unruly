#!/usr/bin/env bash
# Measure the throttle. Not run by verify.sh -- it is the tool that produced
# the numbers in README.md, kept so a human can reproduce them.
#
# It fires N requests at the same relation as fast as the shell can start
# curls, then counts the status codes. Run it twice; the numbers will not
# match, and that is the finding. The answer key deliberately asserts nothing
# about this ratio, because nothing about it is stable.
#
#   ./measure-throttle.sh [count] [path]
set -u
COUNT="${1:-60}"
PATH_="${2:-customers?select=id&limit=1}"
BASE="http://127.0.0.1:54471/rest/v1"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

start=$(date +%s.%N)
for i in $(seq 1 "$COUNT"); do
  curl -s -o /dev/null -w '%{http_code}\n' "$BASE/$PATH_" >> "$TMP/codes" &
done
wait
end=$(date +%s.%N)

echo "requests: $COUNT  elapsed: $(echo "$end - $start" | bc)s  path: /rest/v1/$PATH_"
sort "$TMP/codes" | uniq -c | awk '{printf "  HTTP %s: %s\n", $2, $1}'
