"""trivy_data — a pinned Trivy data artifact as a target. Declared by the
`trivy_db`, `trivy_java_db` and `trivy_checks` repositories (see
repositories.bzl); the scanning rules depend on it."""

load(":providers.bzl", "TrivyDataInfo")

def _impl(ctx):
    files = ctx.files.srcs
    return [
        TrivyDataInfo(kind = ctx.attr.kind, files = files, info = ctx.file.info),
        DefaultInfo(
            files = depset(files + [ctx.file.info]),
            runfiles = ctx.runfiles(files = files + [ctx.file.info]),
        ),
    ]

trivy_data = rule(
    implementation = _impl,
    attrs = {
        "kind": attr.string(mandatory = True, values = ["db", "java_db", "checks"]),
        "srcs": attr.label_list(allow_files = True, mandatory = True),
        "info": attr.label(allow_single_file = [".json"], mandatory = True),
    },
    doc = "A pinned Trivy data artifact.",
)
