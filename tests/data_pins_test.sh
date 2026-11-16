#!/usr/bin/env bash
# DATA in private/versions.bzl: db, java_db and checks, each with a
# repository, tag, a sha256 manifest digest and a created timestamp. No network.
set -euo pipefail
f="$TEST_SRCDIR/_main/$1"
status=0
for kind in db java_db checks; do
  block=$(sed -n "/^    \"$kind\": {/,/^    },/p" "$f")
  for re in '"repository": "[a-z0-9.-]+/[a-z0-9/_.-]+"' '"tag": "[0-9a-z.]+"' \
            '"digest": "sha256:[0-9a-f]{64}"' '"created": "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z"'; do
    grep -qE "$re" <<<"$block" || { echo "FAIL: DATA[\"$kind\"] lacks $re" >&2; status=1; }
  done
  echo "$kind: $(grep -oE 'sha256:[0-9a-f]{12}' <<<"$block") $(grep -oE '"created": "[^"]*"' <<<"$block")"
done
[[ "$status" == 0 ]] && echo "PASS"
exit "$status"
