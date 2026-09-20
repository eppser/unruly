#!/usr/bin/env bash
# Measure what a "403 means the collection exists" rule reports on a project
# whose collections are known.
#
# Usage: benchmark/firebase-protected-precision.sh <wordlist>
#
# Needs .secrets/firebase-lab-config.json. The answer key is
# FirebaseMap/lab/README.md; this script asserts nothing about it, it only
# counts, so the numbers can be checked against a project you own.
set -euo pipefail
W=${1:?usage: $0 <wordlist>}
CFG=${UNRULY_FIREBASE_CONFIG:-.secrets/firebase-lab-config.json}
P=$(python3 -c "import json;print(json.load(open('$CFG'))['projectId'])")
K=$(python3 -c "import json;print(json.load(open('$CFG'))['apiKey'])")
FS="https://firestore.googleapis.com/v1/projects/${P}/databases/(default)/documents"

forbidden=0 ok=0 other=0 tried=0
while read -r name; do
  [ -z "$name" ] && continue
  tried=$((tried+1))
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "${FS}/${name}?key=${K}&pageSize=1")
  case $code in
    403) forbidden=$((forbidden+1)) ;;
    200) ok=$((ok+1)); echo "  readable: $name" ;;
    *)   other=$((other+1)) ;;
  esac
done < "$W"
echo "tried $tried  403 $forbidden  200 $ok  other $other"
echo "Each 403 is what a 'protected collection' claim is built on. Compare that"
echo "count against the collections the project actually has."
