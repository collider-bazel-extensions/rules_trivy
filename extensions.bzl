"""Bzlmod extension `trivy`. Four tag classes:

  trivy.version(version, sha256 = {platform: sha})  the Trivy binary
  trivy.db(digest, repository)                     the vulnerability DB
  trivy.java_db(digest, repository)                the Java DB (opt-in per test)
  trivy.checks(digest, repository)                 the misconfiguration checks bundle

It creates `trivy_<platform>` (one per platform; each downloads only when a
build needs that platform's binary) and `trivy_db`, `trivy_java_db`,
`trivy_checks` (each downloads only when a test needs it).

rules_trivy's own tags are the base and the root module's override them, tag
class by tag class; other modules' tags are ignored. So a root that names
nothing gets rules_trivy's pins, and a root can bump the DB without touching
the binary.
"""

load("//private:repositories.bzl", "trivy_binary_repo", "trivy_data_repo")
load("//private:versions.bzl", "DATA", "DEFAULT_VERSION", "PLATFORMS", "TRIVY_VERSIONS")

_version_tag = tag_class(attrs = {
    "version": attr.string(mandatory = True),  # e.g. "0.76.2"
    # Pins for a version not in TRIVY_VERSIONS (or to replace a listed
    # version's), by platform, from the release's trivy_<ver>_checksums.txt.
    # A platform left out fails only when its binary is fetched.
    "sha256": attr.string_dict(),
})

_data_tag = tag_class(attrs = {
    # The manifest digest (sha256:...), as `bazel run @rules_trivy//:db_latest`
    # prints it.
    "digest": attr.string(mandatory = True),
    # Default: the upstream repository (ghcr.io/aquasecurity/...). Any OCI
    # registry serving the same digest works, e.g. an internal mirror.
    "repository": attr.string(),
})

_DATA_TAGS = ["db", "java_db", "checks"]

def _one(mod, tags, what, key):
    """The module's tags of one class -> one value (or None); repeating an
    identical tag is fine, two different ones fail."""
    seen = None
    for tag in tags:
        value = key(tag)
        if seen != None and seen != value:
            fail("rules_trivy: {} sets trivy.{}() twice, differently ({} and {}); set one.".format(
                "the root module" if mod.is_root else mod.name,
                what,
                seen,
                value,
            ))
        seen = value
    return seen

def _version_key(tag):
    return struct(version = tag.version, sha256 = dict(tag.sha256))

def _data_key(tag):
    return struct(digest = tag.digest, repository = tag.repository)

def _impl(mctx):
    own, root = {}, {}
    for mod in mctx.modules:
        if not (mod.is_root or mod.name == "rules_trivy"):
            continue
        dest = root if mod.is_root else own
        v = _one(mod, mod.tags.version, "version", _version_key)
        if v:
            dest["version"] = v
        for what in _DATA_TAGS:
            d = _one(mod, getattr(mod.tags, what), what, _data_key)
            if d:
                dest[what] = d
    pins = dict(own)
    pins.update(root)

    v = pins.get("version") or struct(version = DEFAULT_VERSION, sha256 = {})
    for plat in v.sha256:
        if plat not in PLATFORMS:
            fail("rules_trivy: trivy.version(sha256 = ...) has unknown platform '{}'. Platforms: {}".format(
                plat,
                sorted(PLATFORMS.keys()),
            ))
    if v.version not in TRIVY_VERSIONS and not v.sha256:
        fail(("rules_trivy: trivy.version(version = \"{}\") is not pinned. Pinned: {}. " +
              "For another version, pin it yourself: trivy.version(version = ..., " +
              "sha256 = {{<platform>: <sha256 from trivy_<version>_checksums.txt>}}).").format(
            v.version,
            ", ".join(sorted(TRIVY_VERSIONS.keys())),
        ))
    for plat in PLATFORMS.keys():
        trivy_binary_repo(
            name = "trivy_" + plat,
            version = v.version,
            platform = plat,
            sha256 = v.sha256.get(plat, ""),
        )

    for what in _DATA_TAGS:
        d = pins.get(what)
        trivy_data_repo(
            name = "trivy_" + what,
            kind = what,
            digest = d.digest if d else DATA[what]["digest"],
            repository = (d and d.repository) or DATA[what]["repository"],
        )

trivy = module_extension(
    implementation = _impl,
    tag_classes = {
        "version": _version_tag,
        "db": _data_tag,
        "java_db": _data_tag,
        "checks": _data_tag,
    },
)
