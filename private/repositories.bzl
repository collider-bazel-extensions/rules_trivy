"""Repository rules.

trivy_binary_repo: per-platform repo (`trivy_<platform>`). Downloads the
release tarball at the pinned sha and declares the platform's toolchain
implementation, so the repo name doesn't change with the version.

trivy_data_repo: one of the OCI artifacts Trivy reads at scan time (the
vulnerability DB, the Java DB, the checks bundle), pinned by manifest
digest. It downloads the manifest at that digest (Bazel checks the bytes
hash to it), reads the single layer's digest from it, and downloads the
layer at that digest. Both downloads are content-addressed, so they come
from the repository cache when present, and the content is exactly what
the digest names whichever registry or mirror serves it.
"""

load(":versions.bzl", "ASSETS", "DATA_KINDS", "TRIVY_URL", "TRIVY_VERSIONS")

# ---- binary -------------------------------------------------------------------

_BINARY_BUILD = """\
load("{toolchain_bzl}", "trivy_toolchain")

package(default_visibility = ["//visibility:public"])

exports_files(["trivy"])

trivy_toolchain(
    name = "toolchain_impl",
    version = "{version}",
    trivy = "trivy",
)
"""

def _binary_impl(rctx):
    version = rctx.attr.version
    platform = rctx.attr.platform
    sha256 = rctx.attr.sha256 or TRIVY_VERSIONS.get(version, {}).get(platform, "")
    if not sha256:
        fail(("rules_trivy: no sha256 for Trivy {v} on {p}; add it to " +
              "trivy.version(sha256 = {{\"{p}\": ...}}) (from the release's " +
              "trivy_{v}_checksums.txt).").format(v = version, p = platform))
    rctx.download_and_extract(
        url = TRIVY_URL.format(version = version, asset = ASSETS[platform]),
        sha256 = sha256,
    )
    rctx.file("BUILD.bazel", _BINARY_BUILD.format(
        toolchain_bzl = str(Label("//toolchain:toolchain.bzl")),
        version = version,
    ))

trivy_binary_repo = repository_rule(
    implementation = _binary_impl,
    attrs = {
        "version": attr.string(mandatory = True),
        "platform": attr.string(mandatory = True),
        # Empty: TRIVY_VERSIONS[version][platform]. A version without a pin
        # for this platform fails only when this platform's binary is fetched.
        "sha256": attr.string(),
    },
)

# ---- data (OCI artifacts) -----------------------------------------------------

_MANIFEST_ACCEPT = ",".join([
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])

_DATA_BUILD = """\
load("{data_bzl}", "trivy_data")

package(default_visibility = ["//visibility:public"])

trivy_data(
    name = "data",
    kind = "{kind}",
    srcs = {srcs},
    info = "info.json",
)
"""

def _split_repository(repository):
    """`host/path` -> (host, path); `path` has no tag or digest."""
    if "/" not in repository:
        fail("rules_trivy: repository '{}': expected <registry host>/<path>, e.g. ghcr.io/aquasecurity/trivy-db.".format(repository))
    host, path = repository.split("/", 1)
    if "@" in path or ":" in path:
        fail("rules_trivy: repository '{}': give the repository only (no tag or digest; the digest is `digest`).".format(repository))
    return host, path

def _token(rctx, host, path):
    """An anonymous pull token, or None. Registries following the Docker
    token protocol at https://<host>/token (ghcr.io does) hand one out to
    anyone; a failure is not fatal, since a cached download needs none."""
    url = "https://{h}/token?scope=repository:{p}:pull&service={h}".format(h = host, p = path)
    res = rctx.download(url = url, output = "_token.json", allow_fail = True)
    if not res.success:
        return None
    body = rctx.read("_token.json")
    rctx.delete("_token.json")
    tok = json.decode(body, default = None) if body else None
    if type(tok) != "dict":
        return None
    return tok.get("token") or tok.get("access_token")

def _data_impl(rctx):
    kind = rctx.attr.kind
    spec = DATA_KINDS[kind]
    digest = rctx.attr.digest
    if not digest.startswith("sha256:") or len(digest) != 71:
        fail("rules_trivy: {} digest '{}': expected sha256:<64 hex> (a manifest digest).".format(kind, digest))
    host, path = _split_repository(rctx.attr.repository)
    base = "https://{}/v2/{}".format(host, path)
    token = _token(rctx, host, path)

    def auth(url):
        if not token:
            return {}
        return {url: {"type": "pattern", "pattern": "Bearer <password>", "password": token}}

    manifest_url = "{}/manifests/{}".format(base, digest)
    rctx.download(
        url = manifest_url,
        output = "manifest.json",
        sha256 = digest[len("sha256:"):],
        headers = {"Accept": [_MANIFEST_ACCEPT]},
        auth = auth(manifest_url),
    )
    manifest = json.decode(rctx.read("manifest.json"))
    layers = manifest.get("layers", [])
    if len(layers) != 1 or layers[0].get("mediaType") != spec.media_type:
        fail(("rules_trivy: {repo}@{d} is not a Trivy {kind} artifact: expected one layer of " +
              "{mt}, got {got}.").format(
            repo = rctx.attr.repository,
            d = digest,
            kind = kind,
            mt = spec.media_type,
            got = [l.get("mediaType") for l in layers],
        ))
    layer = layers[0]["digest"]
    blob_url = "{}/blobs/{}".format(base, layer)
    if kind == "checks":
        rctx.download(
            url = blob_url,
            output = spec.cache_dir + "/bundle.tar.gz",
            sha256 = layer[len("sha256:"):],
            auth = auth(blob_url),
        )
    else:
        rctx.download_and_extract(
            url = blob_url,
            output = spec.cache_dir,
            sha256 = layer[len("sha256:"):],
            type = "tar.gz",
            auth = auth(blob_url),
        )
    for f in spec.files:
        if not rctx.path(spec.cache_dir + "/" + f).exists:
            fail("rules_trivy: {}@{}: the layer has no {}.".format(rctx.attr.repository, digest, f))

    metadata = {}
    if "metadata.json" in spec.files:
        metadata = json.decode(rctx.read(spec.cache_dir + "/metadata.json"))
    annotations = manifest.get("annotations", {})
    rctx.file("info.json", json.encode_indent({
        "kind": kind,
        "repository": rctx.attr.repository,
        "digest": digest,
        "layer": layer,
        "created": annotations.get("org.opencontainers.image.created", ""),
        "version": annotations.get("org.opencontainers.image.version", ""),
        "updated_at": metadata.get("UpdatedAt", ""),
        "schema": metadata.get("Version", 0),
        "cache_dir": spec.cache_dir,
    }) + "\n")
    rctx.file("BUILD.bazel", _DATA_BUILD.format(
        data_bzl = str(Label("//private:data.bzl")),
        kind = kind,
        srcs = repr([spec.cache_dir + "/" + f for f in spec.files]),
    ))

trivy_data_repo = repository_rule(
    implementation = _data_impl,
    attrs = {
        "kind": attr.string(mandatory = True, values = DATA_KINDS.keys()),
        "repository": attr.string(mandatory = True),
        "digest": attr.string(mandatory = True),
    },
    doc = "A Trivy data artifact (DB, Java DB, checks bundle) at a pinned manifest digest.",
)
