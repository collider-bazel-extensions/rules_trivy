#!/usr/bin/env bash
# A licence test with `formats` writes trivy.json, licenses.spdx.json and
# licenses.cdx.json to its undeclared outputs: each lists the packages with
# their licences, and names the scan by its label, not a sandbox path.
# Argv: <licence test with formats = ["cyclonedx", "spdx-json"]>
set -euo pipefail
bin="$1"
work="$(mktemp -d "${TEST_TMPDIR:-/tmp}/reports.XXXXXX")"
mkdir "$work/out"
TEST_UNDECLARED_OUTPUTS_DIR="$work/out" TEST_TMPDIR="$work" "$bin" > "$work/log" 2>&1 || { cat "$work/log"; exit 1; }
python3 -I - "$work/out" <<'PY'
import json, os, sys
d = sys.argv[1]
want = {"mit-thing": "MIT", "isc-thing": "ISC", "bsd-thing": "BSD-3-Clause", "dual-thing": "MIT OR GPL-3.0-only"}
problems = []
r = json.load(open(os.path.join(d, "trivy.json")))
got = {p["Name"]: " ".join(p.get("Licenses") or []) for res in r["Results"] for p in res.get("Packages") or []}
if got != dict(want, **{"dual-thing": "(MIT OR GPL-3.0-only)"}):
    problems.append("trivy.json packages: %r" % got)
if r["ArtifactName"] != "//tests:license_clean_srcs_test":
    problems.append("trivy.json ArtifactName: %r" % r["ArtifactName"])
s = json.load(open(os.path.join(d, "licenses.spdx.json")))
got = {p["name"]: p.get("licenseDeclared") for p in s["packages"] if p["name"] in want}
if got != want:
    problems.append("licenses.spdx.json packages: %r" % got)
if s["name"] != "//tests:license_clean_srcs_test" or any("/sandbox/" in p["name"] or p["name"][:1] == "/" != p["name"][1:2] for p in s["packages"]):
    problems.append("licenses.spdx.json names a sandbox path: %r" % ([s["name"]] + [p["name"] for p in s["packages"]]))
c = json.load(open(os.path.join(d, "licenses.cdx.json")))
got = {}
for x in c["components"]:
    if x["name"] in want:
        l = x.get("licenses") or [{}]
        got[x["name"]] = l[0].get("expression") or l[0].get("license", {}).get("id")
if got != want:
    problems.append("licenses.cdx.json components: %r" % got)
for p in problems:
    print("FAIL: " + p, file=sys.stderr)
sys.exit(1 if problems else 0)
PY
echo PASS
