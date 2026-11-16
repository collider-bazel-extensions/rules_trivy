"""Trivy binary and data pins.

Binaries: one release tarball per platform from aquasecurity/trivy,
holding the single `trivy` binary (plus LICENSE, README and contrib/):

    https://github.com/aquasecurity/trivy/releases/download/v<ver>/trivy_<ver>_<asset>.tar.gz

The SHA-256s are the release's published `trivy_<ver>_checksums.txt`,
cross-checked against the downloads. Maintainer flow:

    tools/update_versions.sh <ver>     # add / re-pin <ver> from the checksums file
    tools/update_versions.sh --check   # verify every pin, no writes

Data: the OCI artifacts Trivy otherwise downloads at scan time, pinned by
manifest digest (see DATA below and DESIGN.md). Maintainer flow:

    tools/update_db.sh                 # re-pin all three to their tags' current digests
    tools/update_db.sh db              # only the vulnerability DB

//tests:checksums_test and //tests:data_pins_test fail on an empty or
malformed value.
"""

# The version the `trivy` extension fetches when the root module names none.
DEFAULT_VERSION = "0.76.2"

TRIVY_VERSIONS = {
    "0.76.2": {
        "linux_amd64": "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf",
        "linux_arm64": "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3",
        "darwin_amd64": "e08bb9ea449ecf66c6bfb03cbb8697c503ff33d35fc585c9747e3eaeb7ed4c7b",
        "darwin_arm64": "ae7ea358326960406b703c77b2ac490190797d80b306b5b50c2a27221da0a5b8",
    },
}

# {version}, {asset}: e.g. 0.76.2, Linux-64bit.
TRIVY_URL = "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{asset}.tar.gz"

# Upstream's asset names.
ASSETS = {
    "linux_amd64": "Linux-64bit",
    "linux_arm64": "Linux-ARM64",
    "darwin_amd64": "macOS-64bit",
    "darwin_arm64": "macOS-ARM64",
}

PLATFORMS = {
    "linux_amd64":  ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    "linux_arm64":  ["@platforms//os:linux", "@platforms//cpu:arm64"],
    "darwin_amd64": ["@platforms//os:osx",   "@platforms//cpu:x86_64"],
    "darwin_arm64": ["@platforms//os:osx",   "@platforms//cpu:arm64"],
}

# The OCI artifacts Trivy reads at scan time, pinned by manifest digest.
# `tag` is what tools/update_db.sh (and `bazel run @rules_trivy//:db_latest`)
# resolve to a new digest; `created` is the manifest's
# org.opencontainers.image.created annotation, recorded for the docs (the
# repository reads the real value from the pinned manifest).
#
#   db       the vulnerability DB (trivy image)
#   java_db  the Java index DB (trivy image of an image with .jar files; opt-in)
#   checks   the misconfiguration checks bundle (trivy config)
DATA = {
    "db": {
        "repository": "ghcr.io/aquasecurity/trivy-db",
        "tag": "2",
        "digest": "sha256:0d6a013bd032c744faa11f7a2b496419407c523a25325987f0ab9344849983fd",
        "created": "2026-11-16T13:13:10Z",
    },
    "java_db": {
        "repository": "ghcr.io/aquasecurity/trivy-java-db",
        "tag": "1",
        "digest": "sha256:972051a7b3daea713eeed9cb931e940bc79d6aa5894074267af46bd61d21f6bf",
        "created": "2026-11-16T00:58:26Z",
    },
    "checks": {
        "repository": "ghcr.io/aquasecurity/trivy-checks",
        "tag": "2",
        "digest": "sha256:b0e12d009b01dcc8ca2ebbc199b9caf3922491978d21c17b61c1d7f6dc75220b",
        "created": "2026-10-14T08:54:44Z",
    },
}

# Per kind: the layer media type the pinned manifest must carry, and where
# its content goes in Trivy's cache directory.
DATA_KINDS = {
    "db": struct(
        media_type = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
        cache_dir = "db",
        files = ["trivy.db", "metadata.json"],
    ),
    "java_db": struct(
        media_type = "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip",
        cache_dir = "java-db",
        files = ["trivy-java.db", "metadata.json"],
    ),
    "checks": struct(
        media_type = "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
        cache_dir = "policy",
        # Kept packed: the driver unpacks the ~240 KB bundle per test, since
        # Trivy's walker would skip the runfiles symlinks of unpacked files.
        files = ["bundle.tar.gz"],
    ),
}
