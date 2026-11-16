"""trivy_toolchain — exposes the platform-resolved `trivy` binary as a
`ToolchainInfo`, so rules resolve it via
`ctx.toolchains["@rules_trivy//toolchain:trivy"]`.

`current_trivy_toolchain` forwards the resolved binary as a plain target
(files + runfiles) for `data = [...]` use in tests.
"""

load("//private:providers.bzl", "TrivyBinaryInfo")

TRIVY_TOOLCHAIN_TYPE = Label("//toolchain:trivy")

def _toolchain_impl(ctx):
    info = TrivyBinaryInfo(
        version = ctx.attr.version,
        trivy = ctx.file.trivy,
    )
    return [
        platform_common.ToolchainInfo(trivy = info),
        DefaultInfo(
            files = depset([ctx.file.trivy]),
            runfiles = ctx.runfiles(files = [ctx.file.trivy]),
        ),
    ]

trivy_toolchain = rule(
    implementation = _toolchain_impl,
    attrs = {
        "version": attr.string(mandatory = True),
        "trivy": attr.label(allow_single_file = True, mandatory = True),
    },
)

def _current_impl(ctx):
    info = ctx.toolchains[TRIVY_TOOLCHAIN_TYPE].trivy
    return [
        info,
        DefaultInfo(
            files = depset([info.trivy]),
            runfiles = ctx.runfiles(files = [info.trivy]),
        ),
    ]

current_trivy_toolchain = rule(
    implementation = _current_impl,
    toolchains = [TRIVY_TOOLCHAIN_TYPE],
    doc = "The resolved trivy binary, as files and runfiles.",
)
