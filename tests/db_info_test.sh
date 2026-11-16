#!/usr/bin/env bash
# `bazel run //:db_info` names the pinned DB and checks bundle, with their age.
set -euo pipefail
out=$("$TEST_SRCDIR/_main/$1")
echo "$out"
grep -qE '^db +ghcr.io/aquasecurity/trivy-db@sha256:[0-9a-f]{12} \(built 20[0-9-]+T[0-9:]+Z, [0-9]+ days? old\)' <<<"$out"
grep -qE '^checks +ghcr.io/aquasecurity/trivy-checks@sha256:[0-9a-f]{12} v[0-9.]+ ' <<<"$out"
grep -qE '^ +digest sha256:[0-9a-f]{64}$' <<<"$out"
echo "PASS"
