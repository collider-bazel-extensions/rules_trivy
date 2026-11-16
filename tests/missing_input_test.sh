#!/usr/bin/env bash
# A scan whose input is not in the runfiles fails with exit 2 and one line
# naming that input, never a Trivy error or a Python traceback. Each case
# runs a scan against a copy of this test's runfiles (links only) with one
# input removed.
# Argv: <image test> <tarball image test> <config test>
set -euo pipefail
image_test="$1"; tarball_test="$2"; config_test="$3"
rf="${RUNFILES_DIR:-$TEST_SRCDIR}"
status=0

# expect <test> <pattern> <path to remove, relative to the runfiles>...
expect() {
  local bin="$1" pattern="$2"; shift 2
  local work; work="$(mktemp -d "$TEST_TMPDIR/missing.XXXXXX")"
  cp -a "$rf" "$work/rf"
  local p
  for p in "$@"; do
    [[ -e "$work/rf/$p" || -L "$work/rf/$p" ]] || { echo "FAIL: setup: no $p in the runfiles" >&2; status=1; return; }
    rm -rf "${work:?}/rf/$p"
  done
  set +e
  RUNFILES_DIR="$work/rf" TEST_TMPDIR="$work" XML_OUTPUT_FILE="$work/junit.xml" \
    "$work/rf/_main/$bin" > "$work/out" 2>&1
  local got=$?
  set -e
  echo "==== $bin without $*: exit $got"
  cat "$work/out"
  [[ "$got" == 2 ]] || { echo "FAIL: exit $got, want 2" >&2; status=1; }
  grep -qF -- "$pattern" "$work/out" || { echo "FAIL: output lacks '$pattern'" >&2; status=1; }
  if grep -qE 'Traceback|Trivy failed' "$work/out"; then echo "FAIL: not a clean message" >&2; status=1; fi
}

one() { (cd "$rf" && compgen -G "$1" | head -1) || { echo "FAIL: setup: nothing matches $1" >&2; exit 1; }; }
db=$(one '*trivy_db')
checks=$(one '*trivy_checks')

expect "$image_test" 'the image is missing: tests/images/clean' _main/tests/images/clean
expect "$tarball_test" 'the image is missing: tests/images/vulnerable_load/tarball.tar' \
  _main/tests/images/vulnerable_load/tarball.tar
expect "$image_test" "a pinned data artifact's info.json is missing: external/$db/info.json" "$db/info.json"
expect "$image_test" "the vulnerability DB is missing: external/$db/db/trivy.db" "$db/db/trivy.db"
expect "$config_test" "the checks bundle is missing: external/$checks/policy/bundle.tar.gz" \
  "$checks/policy/bundle.tar.gz"
expect "$config_test" 'a src is missing: tests/testdata/config/k8s/privileged.yaml' \
  _main/tests/testdata/config/k8s/privileged.yaml
expect "$config_test" 'the ignore file is missing: tests/testdata/ignore/config_accepted.trivyignore.yaml' \
  _main/tests/testdata/ignore/config_accepted.trivyignore.yaml

[[ "$status" == 0 ]] && echo "PASS"
exit "$status"
