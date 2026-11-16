#!/usr/bin/env bash
# Maintainer-time script: pin the Trivy release tarballs in
# private/versions.bzl from the release's published checksums file.
#
#   tools/update_versions.sh <version>   # add / re-pin <version>
#   tools/update_versions.sh --check     # verify every pinned entry
#
# Every published sum is cross-checked by downloading the tarball and
# hashing it; any mismatch aborts without touching versions.bzl. Bump
# DEFAULT_VERSION and trivy.version() in MODULE.bazel to match
# (//tests:version_test).
set -euo pipefail

cd "$(dirname "$0")/.."
for tool in curl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "update_versions: needs $tool" >&2; exit 1; }
done

work=$(mktemp -d)
trap 'rm -r -f -- "$work"' EXIT

# platform -> upstream asset name (private/versions.bzl ASSETS)
declare -A assets=(
    [linux_amd64]=Linux-64bit
    [linux_arm64]=Linux-ARM64
    [darwin_amd64]=macOS-64bit
    [darwin_arm64]=macOS-ARM64
)
plats=(linux_amd64 linux_arm64 darwin_amd64 darwin_arm64)
repo="https://github.com/aquasecurity/trivy/releases/download"

sha256() { python3 -I -c 'import hashlib,sys; h=hashlib.sha256(); f=open(sys.argv[1],"rb"); [h.update(b) for b in iter(lambda: f.read(1<<20), b"")]; print(h.hexdigest())' "$1"; }

# Prints "<platform> <sha256>" for each platform of <version>, verified
# against the downloaded tarball.
published() {
    local ver="$1" plat asset sum actual base="$repo/v$1"
    curl -fsSL -o "$work/sums" "$base/trivy_${ver}_checksums.txt"
    for plat in "${plats[@]}"; do
        asset="trivy_${ver}_${assets[$plat]}.tar.gz"
        sum=$(awk -v a="$asset" '$2 == a {print $1}' "$work/sums")
        [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || { echo "update_versions: no sum for $asset" >&2; exit 1; }
        curl -fsSL -o "$work/tgz" "$base/$asset"
        actual=$(sha256 "$work/tgz")
        [[ "$actual" == "$sum" ]] || { echo "update_versions: $asset hashes to $actual, published $sum" >&2; exit 1; }
        echo "$plat $sum"
    done
}

if [[ "${1:-}" == "--check" ]]; then
    status=0
    for ver in $(sed -n '/^TRIVY_VERSIONS = {/,/^}/s/^    "\([0-9][^"]*\)": {/\1/p' private/versions.bzl); do
        while read -r plat sum; do
            if grep -qF "\"$plat\": \"$sum\"" private/versions.bzl; then
                echo "OK    $ver $plat"
            else
                echo "DRIFT $ver $plat: published $sum" >&2; status=1
            fi
        done < <(published "$ver")
    done
    exit "$status"
fi

ver="${1:?usage: tools/update_versions.sh <version> | --check}"
published "$ver" > "$work/pins"
python3 -I - private/versions.bzl "$ver" "$work/pins" <<'PY'
import re, sys
path, ver, pins = sys.argv[1:]
rows = [l.split() for l in open(pins) if l.strip()]
entry = '    "{}": {{\n'.format(ver)
for plat, sha in rows:
    entry += '        "{}": "{}",\n'.format(plat, sha)
entry += "    },\n"
text = open(path).read()
pat = re.compile(r'    "' + re.escape(ver) + r'": \{\n.*?\n    \},\n', re.S)
if pat.search(text):
    text = pat.sub(lambda m: entry, text)
else:
    text = text.replace("TRIVY_VERSIONS = {\n", "TRIVY_VERSIONS = {\n" + entry, 1)
open(path, "w").write(text)
print("pinned {} for {} platforms in {}".format(ver, len(rows), path))
PY
