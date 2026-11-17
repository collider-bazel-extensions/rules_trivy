"""trivy_image_test, trivy_config_test, trivy_license_test, trivy_ignore_test — test rules.

Each test runs the driver (private/trivy.py) on host python3. It runs
Trivy offline against the pinned data artifacts: the vulnerability DB (and
optionally the Java DB) for images, the checks bundle for configuration.
Findings at or above `severity` fail the test unless the ignore file
accepts them; an expired ignore entry fails the test too. The licence
scan needs no data artifact (the Java DB only for Java archives in an
image) and fails on licences outside its allowlist. JUnit goes to
$XML_OUTPUT_FILE and Trivy's JSON report to the test's undeclared outputs.
"""

load(":providers.bzl", "TrivyDataInfo")

TOOLCHAIN = "//toolchain:trivy"

SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def _shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"

def label_text(label):
    s = str(label)
    return s[2:] if s.startswith("@@//") else s

def _wrapper(ctx, mode, args, extra):
    driver = ctx.file._driver.short_path
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._tmpl,
        output = out,
        substitutions = {
            "__DRIVER__": driver,
            "__MODE__": mode,
            "__ARGS__": " ".join([_shell_quote(a) for a in args]),
            "__EXTRA__": " ".join([_shell_quote(a) for a in extra]),
        },
        is_executable = True,
    )
    return out

def _check_severity(ctx):
    if ctx.attr.severity not in SEVERITIES:
        fail("{}: severity = \"{}\": expected one of {} (the lowest severity that fails the test).".format(
            ctx.label,
            ctx.attr.severity,
            ", ".join(SEVERITIES),
        ))

def _common(ctx, trivy, data):
    """Driver args + runfiles shared by the scanning rules."""
    args = [
        "--label",
        label_text(ctx.label),
        "--trivy",
        trivy.trivy.short_path,
        "--version",
        trivy.version,
        "--severity",
        ctx.attr.severity,
    ]
    files = [ctx.file._driver, trivy.trivy]
    for d in data:
        info = d[TrivyDataInfo]
        args += ["--data", info.info.short_path]
        files += info.files + [info.info]
    if ctx.file.ignore:
        args += ["--ignore", ctx.file.ignore.short_path]
        files.append(ctx.file.ignore)
    return args, files

def _image_test_impl(ctx):
    _check_severity(ctx)
    trivy = ctx.toolchains[TOOLCHAIN].trivy
    images = ctx.files.image
    if len(images) != 1:
        fail("{}: image must be exactly one file or directory (an oci_image's OCI layout, or an image tarball); {} gives {}: {}".format(
            ctx.label,
            ctx.attr.image.label,
            len(images),
            [f.short_path for f in images][:5],
        ))
    image = images[0]
    if not image.is_directory and not image.basename.endswith(".tar"):
        fail("{}: image {}: expected an OCI layout directory (oci_image) or a .tar image tarball (oci_load's `tarball` output group).".format(
            ctx.label,
            image.short_path,
        ))
    data = [ctx.attr._db] + ([ctx.attr.java_db] if ctx.attr.java_db else [])
    args, files = _common(ctx, trivy, data)
    args += ["--image", image.short_path]
    if ctx.attr.ignore_unfixed:
        args.append("--ignore-unfixed")
    if ctx.attr.platform:
        args += ["--platform", ctx.attr.platform]
    wrapper = _wrapper(ctx, "image", args, ctx.attr.extra_args)
    runfiles = ctx.runfiles(files = [wrapper, image] + files)
    return [DefaultInfo(executable = wrapper, runfiles = runfiles)]

_COMMON_ATTRS = {
    "severity": attr.string(
        default = "HIGH",
        doc = "The lowest severity that fails the test: UNKNOWN, LOW, MEDIUM, HIGH or CRITICAL. " +
              "Lower findings are listed but don't fail.",
    ),
    "ignore": attr.label(
        allow_single_file = [".yaml", ".yml"],
        doc = "An ignore file in Trivy's .trivyignore.yaml schema. Every entry needs `id`, " +
              "`statement` (the reason) and `expired_at` (YYYY-MM-DD); an expired entry fails the test.",
    ),
    "extra_args": attr.string_list(
        doc = "Extra Trivy arguments, e.g. [\"--pkg-types=os\"].",
    ),
    "_driver": attr.label(default = "//private:trivy.py", allow_single_file = True),
    "_tmpl": attr.label(default = "//private:run.sh.tmpl", allow_single_file = True),
}

trivy_image_test = rule(
    implementation = _image_test_impl,
    test = True,
    doc = "Scans a container image for known vulnerabilities, offline, against the pinned DB.",
    attrs = dict(_COMMON_ATTRS, **{
        "image": attr.label(
            mandatory = True,
            allow_files = True,
            doc = "An oci_image (its OCI layout directory), or a .tar image tarball " +
                  "(e.g. an oci_load's `tarball` output group).",
        ),
        "ignore_unfixed": attr.bool(
            doc = "Leave out vulnerabilities without a fixed version.",
        ),
        "java_db": attr.label(
            providers = [TrivyDataInfo],
            doc = "The Java DB, needed when the image has .jar/.war/.ear files: " +
                  "\"@rules_trivy//:java_db\" (the pinned ~1 GB trivy-java-db, fetched only " +
                  "when a test names it).",
        ),
        "platform": attr.string(
            doc = "For a multi-platform image index: the platform to scan, e.g. \"linux/arm64\".",
        ),
        "_db": attr.label(default = "//:db", providers = [TrivyDataInfo]),
    }),
    toolchains = [TOOLCHAIN],
)

def _config_test_impl(ctx):
    _check_severity(ctx)
    trivy = ctx.toolchains[TOOLCHAIN].trivy
    srcs = ctx.files.srcs
    if not srcs:
        fail("{}: srcs is empty: nothing to scan.".format(ctx.label))
    manifest = ctx.actions.declare_file(ctx.label.name + ".trivy_manifest")
    ctx.actions.write(manifest, "\n".join([f.short_path for f in srcs]) + "\n")
    args, files = _common(ctx, trivy, [ctx.attr._checks])
    args += ["--manifest", manifest.short_path]
    wrapper = _wrapper(ctx, "config", args, ctx.attr.extra_args)
    runfiles = ctx.runfiles(files = [wrapper, manifest] + srcs + files)
    return [DefaultInfo(executable = wrapper, runfiles = runfiles)]

trivy_config_test = rule(
    implementation = _config_test_impl,
    test = True,
    doc = "Scans configuration (Kubernetes, Helm, Terraform, Dockerfile, ...) for misconfigurations, offline.",
    attrs = dict(_COMMON_ATTRS, **{
        "srcs": attr.label_list(
            allow_files = True,
            doc = "Files to scan: source files, or any rule's outputs (a Helm or Kustomize " +
                  "render, generated Terraform, tree artifacts). Staged under their workspace paths.",
        ),
        "_checks": attr.label(default = "//:checks", providers = [TrivyDataInfo]),
    }),
    toolchains = [TOOLCHAIN],
)

# Trivy's licence categories (as CATEGORIES in trivy.py).
LICENSE_CATEGORIES = ["forbidden", "restricted", "reciprocal", "notice", "permissive", "unencumbered", "unknown"]

LICENSE_FORMATS = ["spdx-json", "cyclonedx"]

def _license_test_impl(ctx):
    trivy = ctx.toolchains[TOOLCHAIN].trivy
    for c in ctx.attr.allow_categories:
        if c not in LICENSE_CATEGORIES:
            fail("{}: allow_categories: unknown category \"{}\": Trivy's are {}.".format(
                ctx.label,
                c,
                ", ".join(LICENSE_CATEGORIES),
            ))
    for f in ctx.attr.formats:
        if f not in LICENSE_FORMATS:
            fail("{}: formats: \"{}\": expected {}.".format(ctx.label, f, " or ".join(LICENSE_FORMATS)))
    srcs = ctx.files.srcs
    if bool(ctx.attr.image) == bool(srcs):
        fail("{}: set exactly one of image (an oci_image or image tarball) and srcs (a source tree, lockfiles).".format(ctx.label))
    if srcs and (ctx.attr.java_db or ctx.attr.platform):
        fail("{}: java_db and platform apply to an image, not srcs.".format(ctx.label))

    # The Java DB brings the vulnerability DB with it: Trivy analyses Java
    # archives only when its vulnerability scanner runs.
    if ctx.attr.java_db and not ctx.attr.vuln_db:
        fail("{}: java_db needs vuln_db (trivy_license_test sets it).".format(ctx.label))
    data = [ctx.attr.vuln_db, ctx.attr.java_db] if ctx.attr.java_db else []
    args = [
        "--label",
        label_text(ctx.label),
        "--trivy",
        trivy.trivy.short_path,
        "--version",
        trivy.version,
    ]
    files = [ctx.file._driver, trivy.trivy]
    for d in data:
        info = d[TrivyDataInfo]
        args += ["--data", info.info.short_path]
        files += info.files + [info.info]
    if ctx.file.ignore:
        args += ["--ignore", ctx.file.ignore.short_path]
        files.append(ctx.file.ignore)
    if ctx.file.allowlist:
        args += ["--allowlist", ctx.file.allowlist.short_path]
        files.append(ctx.file.allowlist)
    for n in ctx.attr.allow:
        args += ["--allow", n]
    for c in ctx.attr.allow_categories:
        args += ["--allow-category", c]
    for f in ctx.attr.formats:
        args += ["--format", f]
    if ctx.attr.license_full:
        args.append("--license-full")
    if ctx.attr.image:
        images = ctx.files.image
        if len(images) != 1:
            fail("{}: image must be exactly one file or directory (an oci_image's OCI layout, or an image tarball); {} gives {}.".format(
                ctx.label,
                ctx.attr.image.label,
                len(images),
            ))
        image = images[0]
        if not image.is_directory and not image.basename.endswith(".tar"):
            fail("{}: image {}: expected an OCI layout directory (oci_image) or a .tar image tarball.".format(
                ctx.label,
                image.short_path,
            ))
        args += ["--image", image.short_path]
        if ctx.attr.platform:
            args += ["--platform", ctx.attr.platform]
        files.append(image)
    else:
        manifest = ctx.actions.declare_file(ctx.label.name + ".trivy_manifest")
        ctx.actions.write(manifest, "\n".join([f.short_path for f in srcs]) + "\n")
        args += ["--manifest", manifest.short_path]
        files += [manifest] + srcs
    wrapper = _wrapper(ctx, "license", args, ctx.attr.extra_args)
    return [DefaultInfo(executable = wrapper, runfiles = ctx.runfiles(files = [wrapper] + files))]

_trivy_license_test = rule(
    implementation = _license_test_impl,
    test = True,
    doc = "Checks the licences Trivy finds in an image or in srcs against an allowlist, offline.",
    attrs = {
        "image": attr.label(
            allow_files = True,
            doc = "An oci_image (its OCI layout directory), or a .tar image tarball. Set this or srcs.",
        ),
        "srcs": attr.label_list(
            allow_files = True,
            doc = "Files to scan: lockfiles (package-lock.json, composer.lock, pom.xml, ...), source " +
                  "trees, any rule's outputs. Staged under their workspace paths. Set this or image.",
        ),
        "allow": attr.string_list(
            doc = "Licences allowed by name, as Trivy reports them (SPDX ids, e.g. \"MPL-2.0\"; " +
                  "\"NOASSERTION\" for packages without one). In an SPDX expression, every AND " +
                  "operand, or one OR operand, must be allowed.",
        ),
        "allow_categories": attr.string_list(
            default = ["notice", "permissive", "unencumbered"],
            doc = "Trivy licence categories allowed: forbidden, restricted, reciprocal, notice, " +
                  "permissive, unencumbered, unknown. A licence is allowed if its category or its name is.",
        ),
        "allowlist": attr.label(
            allow_single_file = True,
            doc = "A file of allowed licences, one per line (or `category: <name>`; `#` comments), " +
                  "added to `allow` and `allow_categories`.",
        ),
        "ignore": attr.label(
            allow_single_file = [".yaml", ".yml"],
            doc = "An ignore file; its `licenses:` entries accept findings. Each needs `id` (the licence), " +
                  "`statement` (the reason) and `expired_at` (YYYY-MM-DD); `packages` (name or " +
                  "name@version) and `paths` (globs) narrow it.",
        ),
        "license_full": attr.bool(
            doc = "Also classify licence texts in files (LICENSE, COPYING, headers): Trivy's --license-full.",
        ),
        "formats": attr.string_list(
            doc = "Extra reports in the test's undeclared outputs, next to trivy.json: " +
                  "\"spdx-json\" (licenses.spdx.json), \"cyclonedx\" (licenses.cdx.json).",
        ),
        "java_db": attr.label(
            providers = [TrivyDataInfo],
            doc = "The Java DB, needed when the image has .jar/.war/.ear files: " +
                  "\"@rules_trivy//:java_db\" (with the vulnerability DB, fetched only when a test names it).",
        ),
        "platform": attr.string(
            doc = "For a multi-platform image index: the platform to scan, e.g. \"linux/arm64\".",
        ),
        "extra_args": attr.string_list(doc = "Extra Trivy arguments."),
        "vuln_db": attr.label(
            providers = [TrivyDataInfo],
            doc = "Set by trivy_license_test with java_db: the vulnerability DB. Not a default, so " +
                  "a licence test without java_db fetches no DB.",
        ),
        "_driver": attr.label(default = "//private:trivy.py", allow_single_file = True),
        "_tmpl": attr.label(default = "//private:run.sh.tmpl", allow_single_file = True),
    },
    toolchains = [TOOLCHAIN],
)

def trivy_license_test(name, java_db = None, **kwargs):
    """Checks the licences Trivy finds in an image or in srcs against an allowlist, offline.

    See _trivy_license_test's attributes. With java_db, the vulnerability DB
    comes too (Trivy analyses Java archives only for its vulnerability
    scanner); without it, no DB is fetched."""
    if java_db:
        kwargs["vuln_db"] = Label("//:db")
    _trivy_license_test(name = name, java_db = java_db, **kwargs)

def _ignore_test_impl(ctx):
    wrapper = _wrapper(ctx, "ignore-test", [
        "--label",
        label_text(ctx.label),
        "--ignore",
        ctx.file.src.short_path,
        "--expect-error",
        ctx.attr.expect_error,
    ], [])
    runfiles = ctx.runfiles(files = [wrapper, ctx.file._driver, ctx.file.src])
    return [DefaultInfo(executable = wrapper, runfiles = runfiles)]

trivy_ignore_test = rule(
    implementation = _ignore_test_impl,
    test = True,
    doc = "Checks an ignore file without scanning: its shape, a reason and expiry on every " +
          "entry, and that none has expired. With `expect_error`, the check must fail with a matching message.",
    attrs = {
        "src": attr.label(mandatory = True, allow_single_file = [".yaml", ".yml"]),
        "expect_error": attr.string(
            doc = "A Python regex (re.search) the check's error must match. Empty: the check must pass.",
        ),
        "_driver": attr.label(default = "//private:trivy.py", allow_single_file = True),
        "_tmpl": attr.label(default = "//private:run.sh.tmpl", allow_single_file = True),
    },
)
