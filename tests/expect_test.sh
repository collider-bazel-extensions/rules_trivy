#!/usr/bin/env bash
# Runs a (manual) rules_trivy test target and checks its outcome: the exit
# code, lines its output must contain (grep -E), and the JUnit failure count.
# Argv: <test executable> <exit code> <junit failures | -> [<pattern>...]
# A pattern starting with `!` must NOT match.
set -euo pipefail
bin="$1"; want="$2"; junit_want="$3"; shift 3
work="$(mktemp -d "${TEST_TMPDIR:-/tmp}/expect.XXXXXX")"
set +e
XML_OUTPUT_FILE="$work/junit.xml" TEST_UNDECLARED_OUTPUTS_DIR="$work" TEST_TMPDIR="$work" \
  "$bin" > "$work/out" 2>&1
got=$?
set -e
cat "$work/out"
echo "---- exit $got (want $want)"
status=0
[[ "$got" == "$want" ]] || { echo "FAIL: exit $got, want $want" >&2; status=1; }
for p in "$@"; do
  if [[ "$p" == '!'* ]]; then
    if grep -qE -- "${p:1}" "$work/out"; then echo "FAIL: output matches '${p:1}'" >&2; status=1; fi
  elif ! grep -qE -- "$p" "$work/out"; then
    echo "FAIL: output lacks '$p'" >&2; status=1
  fi
done
if [[ "$junit_want" != "-" ]]; then
  failures=$(grep -o '<testsuite [^>]*failures="[0-9]*"' "$work/junit.xml" | sed 's/.*failures="\([0-9]*\)"/\1/' || true)
  [[ "$failures" == "$junit_want" ]] || { echo "FAIL: JUnit failures '$failures', want $junit_want" >&2; status=1; }
fi
[[ "$status" == 0 ]] && echo "PASS"
exit "$status"
