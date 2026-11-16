"""trivy_db_info and trivy_db_latest — `bazel run` helpers.

trivy_db_info prints the pinned data artifacts (digest, build time, age).
trivy_db_latest asks the registries for their tags' current digests and
prints the `trivy.db(digest = ...)` lines that pin them: the DB bump tool
for a consumer's MODULE.bazel (it needs the network; tests never do).
"""

load(":providers.bzl", "TrivyDataInfo")
load(":test.bzl", "label_text")
load(":versions.bzl", "DATA")

def _shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"

def _run(ctx, mode, args, files):
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._tmpl,
        output = out,
        substitutions = {
            "__DRIVER__": ctx.file._driver.short_path,
            "__MODE__": mode,
            "__ARGS__": " ".join([_shell_quote(a) for a in args]),
            "__EXTRA__": "",
        },
        is_executable = True,
    )
    return [DefaultInfo(executable = out, runfiles = ctx.runfiles(files = [out, ctx.file._driver] + files))]

_ATTRS = {
    "_driver": attr.label(default = "//private:trivy.py", allow_single_file = True),
    "_tmpl": attr.label(default = "//private:run.sh.tmpl", allow_single_file = True),
}

def _info_impl(ctx):
    args, files = ["--label", label_text(ctx.label)], []
    for d in ctx.attr.data:
        info = d[TrivyDataInfo]
        args += ["--data", info.info.short_path]
        files.append(info.info)
    return _run(ctx, "db-info", args, files)

trivy_db_info = rule(
    implementation = _info_impl,
    executable = True,
    attrs = dict(_ATTRS, data = attr.label_list(providers = [TrivyDataInfo])),
    doc = "`bazel run`: the pinned data artifacts and their age.",
)

def _latest_impl(ctx):
    return _run(ctx, "latest", ["--pins", json.encode(DATA)], [])

trivy_db_latest = rule(
    implementation = _latest_impl,
    executable = True,
    attrs = _ATTRS,
    doc = "`bazel run`: the upstream tags' current digests, as trivy.db/java_db/checks() lines.",
)
