#!/usr/bin/env bash
# Maintainer-time script: re-pin the data artifacts in private/versions.bzl
# (DATA) to the current digests of their upstream tags.
#
#   tools/update_db.sh                 # db, java_db and checks
#   tools/update_db.sh db [checks]     # only these
#
# The pin is the OCI manifest digest; the repository rule verifies the
# manifest and the layer against it when it fetches them. A new DB can
# change what the fixture images report: run `bazel test //tests/...`
# (and //tests:java_db_test) afterwards and adjust tests/BUILD.bazel.
# Consumers bump their own pins with `bazel run @rules_trivy//:db_latest`.
set -euo pipefail
cd "$(dirname "$0")/.."
kinds=()
for k in "$@"; do
    case "$k" in
        db|java_db|checks) kinds+=(--kind "$k") ;;
        *) echo "usage: tools/update_db.sh [db] [java_db] [checks]" >&2; exit 1 ;;
    esac
done
python3 -I private/trivy.py latest --write private/versions.bzl ${kinds[@]+"${kinds[@]}"}
