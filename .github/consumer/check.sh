#!/usr/bin/env bash
# Consumer checks against the commit's release archive (git archive honours
# .gitattributes export-ignore, as GitHub's tag tarballs do):
#   1. tests/ and tools/ are not shipped, and @rules_trivy//... loads
#   2. no trivy.version() in the root resolves to rules_trivy's pins, and a
#      trivy_config_test passes against them (external labels and runfiles)
#   3. the same version set twice in the root resolves
#   4. an unpinned version fails, naming trivy.version
#   5. a version not in private/versions.bzl, pinned in trivy.version()
#      itself: the scan runs that binary, and a platform without a sha256
#      fails only when fetched, naming sha256
#   6. trivy.checks(digest = <an older bundle>) in the root replaces the pin
#   7. two different trivy.db() digests in the root fail
# Usage: .github/consumer/check.sh <scratch dir>
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
work="$1"
src="$work/rules_trivy"
rm -rf "$work"; mkdir -p "$src"
git -C "$repo" archive HEAD | tar -x -C "$src"
for d in tests tools; do
    if [[ -e "$src/$d" ]]; then echo "FAIL: archive contains $d/" >&2; exit 1; fi
done
version="$(sed -n 's/^trivy.version(version = "\(.*\)")/\1/p' "$src/MODULE.bazel")"
dirs=()
trap 'for d in "${dirs[@]}"; do (cd "$d" && bazel shutdown) >/dev/null 2>&1 || true; done' EXIT

consumer() { # <name> <extra MODULE.bazel lines>
    local c="$work/$1"
    mkdir -p "$c"
    dirs+=("$c")
    if [[ -f "$repo/.bazelversion" ]]; then cp "$repo/.bazelversion" "$c/"; fi
    cat > "$c/MODULE.bazel" <<MOD
module(name = "consumer")
bazel_dep(name = "rules_trivy")
local_path_override(module_name = "rules_trivy", path = "$src")
$2
MOD
    cat > "$c/BUILD.bazel" <<'BUILD'
load("@rules_trivy//:defs.bzl", "trivy_config_test")

trivy_config_test(
    name = "config_test",
    srcs = ["deployment.yaml"],
    severity = "CRITICAL",
)
BUILD
    cat > "$c/deployment.yaml" <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  containers:
    - name: web
      image: registry.example.com/web:1.0
YAML
    echo 'test --sandbox_default_allow_network=false' > "$c/.bazelrc"
}

log() { # <consumer> -> the config test's log
    cat "$work/$1/bazel-testlogs/config_test/test.log"
}

# 1, 2. No trivy.version(): //... loads, and the scan runs on the pins.
consumer untagged ""
(cd "$work/untagged" && bazel query @rules_trivy//... >/dev/null)
echo "PASS: @rules_trivy//... loads from the archive ($(cd "$work/untagged" && bazel query @rules_trivy//... 2>/dev/null | wc -l) targets)"
(cd "$work/untagged" && bazel test //:config_test)
log untagged | grep -q "Trivy $version, fails on CRITICAL" || { log untagged; echo "FAIL: untagged consumer did not run Trivy $version" >&2; exit 1; }
checks_pin="$(sed -n '/^    "checks": {/,/^    },/s/.*"digest": "sha256:\([0-9a-f]\{12\}\).*/\1/p' "$src/private/versions.bzl")"
log untagged | grep -q "trivy-checks@sha256:$checks_pin" || { log untagged; echo "FAIL: untagged consumer did not use the pinned checks" >&2; exit 1; }
echo "PASS: untagged root resolves; trivy_config_test passes with Trivy $version and checks $checks_pin"

# 3. The same version twice in the root.
consumer twice "trivy = use_extension(\"@rules_trivy//:extensions.bzl\", \"trivy\")
trivy.version(version = \"$version\")
trivy.version(version = \"$version\")"
(cd "$work/twice" && bazel build //:config_test)
echo "PASS: repeated identical trivy.version resolves"

# 4. An unpinned version fails with a message naming trivy.version.
consumer unpinned 'trivy = use_extension("@rules_trivy//:extensions.bzl", "trivy")
trivy.version(version = "0.0.1")'
if (cd "$work/unpinned" && bazel build //:config_test) > "$work/unpinned.out" 2>&1; then
    echo "FAIL: unpinned version resolved" >&2; exit 1
fi
grep -q 'trivy.version(version = "0.0.1") is not pinned' "$work/unpinned.out" || {
    cat "$work/unpinned.out" >&2; echo "FAIL: unpinned version: wrong error" >&2; exit 1; }
echo "PASS: unpinned version fails clearly"

# 5. A self-pinned version (Trivy 0.76.1 is not in private/versions.bzl).
consumer pinned 'trivy = use_extension("@rules_trivy//:extensions.bzl", "trivy")
trivy.version(
    version = "0.76.1",
    sha256 = {
        "linux_amd64": "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0",
        "linux_arm64": "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f",
    },
)'
(cd "$work/pinned" && bazel test //:config_test)
log pinned | grep -q "Trivy 0.76.1, fails on CRITICAL" || { log pinned; echo "FAIL: self-pinned consumer did not run Trivy 0.76.1" >&2; exit 1; }
if (cd "$work/pinned" && bazel fetch @@rules_trivy++trivy+trivy_darwin_arm64//...) > "$work/pinned_darwin.out" 2>&1; then
    echo "FAIL: darwin_arm64 fetched without a sha256" >&2; exit 1
fi
grep -q 'no sha256 for Trivy 0.76.1 on darwin_arm64; add it to trivy.version(sha256' "$work/pinned_darwin.out" || {
    cat "$work/pinned_darwin.out" >&2; echo "FAIL: missing sha256: wrong error" >&2; exit 1; }
echo "PASS: self-pinned Trivy 0.76.1 runs; an unpinned platform fails only when fetched, naming sha256"

# 6. An older checks bundle (trivy-checks 2.2.0) pinned in the root.
consumer checks 'trivy = use_extension("@rules_trivy//:extensions.bzl", "trivy")
trivy.checks(digest = "sha256:b63166ca02aa09e30a5127320384d7bd0d2760dc19bab3ab7041a6070114ba45")'
(cd "$work/checks" && bazel test //:config_test)
log checks | grep -q "trivy-checks@sha256:b63166ca02aa v2.2.0" || { log checks; echo "FAIL: root checks pin not applied" >&2; exit 1; }
echo "PASS: trivy.checks(digest) in the root replaces the pinned bundle (v2.2.0)"

# 7. Two different DB digests in one module.
consumer twodb 'trivy = use_extension("@rules_trivy//:extensions.bzl", "trivy")
trivy.db(digest = "sha256:0d6a013bd032c744faa11f7a2b496419407c523a25325987f0ab9344849983fd")
trivy.db(digest = "sha256:4e84a691e70819a98f208b99bbfb292076c301c47e4fc4057dcb9ae8b29df12a")'
if (cd "$work/twodb" && bazel build //:config_test) > "$work/twodb.out" 2>&1; then
    echo "FAIL: two trivy.db() digests resolved" >&2; exit 1
fi
grep -q 'the root module sets trivy.db() twice, differently' "$work/twodb.out" || {
    cat "$work/twodb.out" >&2; echo "FAIL: two trivy.db(): wrong error" >&2; exit 1; }
echo "PASS: two different trivy.db() in one module fail clearly"
