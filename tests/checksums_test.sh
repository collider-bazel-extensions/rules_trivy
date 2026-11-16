#!/usr/bin/env bash
# Fails when a version in private/versions.bzl doesn't pin all 4 platforms
# with a 64-hex SHA-256. No network.
set -euo pipefail
f="${TEST_SRCDIR}/_main/private/versions.bzl"
block=$(sed -n '/^TRIVY_VERSIONS = {/,/^}/p' "$f")
versions=$(grep -cE '^    "[0-9][^"]*": \{' <<<"$block" || true)
pinned=$(grep -cE '^        "(linux|darwin)_(amd64|arm64)": "[0-9a-f]{64}",' <<<"$block" || true)
echo "versions=$versions pinned=$pinned"
if [[ "$versions" -eq 0 || "$pinned" -ne $(( versions * 4 )) ]]; then
  echo "FAIL: every version needs 4 platforms, each with a 64-hex SHA-256 (tools/update_versions.sh <version>)" >&2
  exit 1
fi
echo "PASS"
