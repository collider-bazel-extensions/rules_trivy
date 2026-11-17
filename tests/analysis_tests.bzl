"""Analysis-time tests: providers, executables, and the analysis errors for
bad attributes."""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load(
    "//:defs.bzl",
    "TrivyBinaryInfo",
    "TrivyDataInfo",
    "trivy_config_test",
    "trivy_image_test",
    "trivy_license_test",
)

def _data_info_impl(ctx):
    env = analysistest.begin(ctx)
    info = analysistest.target_under_test(env)[TrivyDataInfo]
    asserts.equals(env, ctx.attr.kind, info.kind)
    asserts.equals(env, ctx.attr.files, sorted([f.basename for f in info.files]))
    asserts.equals(env, "info.json", info.info.basename)
    return analysistest.end(env)

_data_info_test = analysistest.make(_data_info_impl, attrs = {
    "kind": attr.string(),
    "files": attr.string_list(),
})

def _binary_info_impl(ctx):
    env = analysistest.begin(ctx)
    info = analysistest.target_under_test(env)[TrivyBinaryInfo]
    asserts.equals(env, "0.76.2", info.version)
    asserts.equals(env, "trivy", info.trivy.basename)
    return analysistest.end(env)

_binary_info_test = analysistest.make(_binary_info_impl)

def _has_executable_impl(ctx):
    env = analysistest.begin(ctx)
    target = analysistest.target_under_test(env)
    asserts.true(env, target[DefaultInfo].files_to_run.executable != None,
                 "expected target to expose an executable")
    return analysistest.end(env)

_has_executable_test = analysistest.make(_has_executable_impl)

def _no_java_db_impl(ctx):
    # Without java_db, an image test's runfiles carry the DB but not the
    # Java DB (so the ~1 GB download happens only for tests that ask).
    env = analysistest.begin(ctx)
    names = [f.basename for f in analysistest.target_under_test(env)[DefaultInfo].default_runfiles.files.to_list()]
    asserts.true(env, "trivy.db" in names, "expected trivy.db in runfiles")
    asserts.false(env, "trivy-java.db" in names, "unexpected trivy-java.db in runfiles")
    return analysistest.end(env)

_no_java_db_test = analysistest.make(_no_java_db_impl)

def _no_db_impl(ctx):
    # A licence test without java_db carries no data artifact at all.
    env = analysistest.begin(ctx)
    names = [f.basename for f in analysistest.target_under_test(env)[DefaultInfo].default_runfiles.files.to_list()]
    for n in ["trivy.db", "trivy-java.db", "bundle.tar.gz", "info.json"]:
        asserts.false(env, n in names, "unexpected {} in runfiles".format(n))
    return analysistest.end(env)

_no_db_test = analysistest.make(_no_db_impl)

def _fails_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.message)
    return analysistest.end(env)

_fails_test = analysistest.make(
    _fails_impl,
    expect_failure = True,
    attrs = {"message": attr.string()},
)

def analysis_test_suite(name):
    s = name + "_subject"
    m = ["manual"]
    trivy_image_test(name = s + "_image", image = "//tests/images:clean", tags = m)
    trivy_config_test(name = s + "_config", srcs = ["//tests/testdata/config:k8s/hardened.yaml"], tags = m)
    trivy_image_test(name = s + "_bad_severity", image = "//tests/images:clean", severity = "SEVERE", tags = m)
    trivy_config_test(name = s + "_lowercase_severity", srcs = ["//tests/testdata/config:notes.txt"], severity = "high", tags = m)
    native.filegroup(name = s + "_two_files", srcs = ["//tests/testdata/config:notes.txt", "//tests/testdata/config:k8s/hardened.yaml"], tags = m)
    trivy_image_test(name = s + "_two_images", image = ":" + s + "_two_files", tags = m)
    trivy_image_test(name = s + "_not_image", image = "//tests/testdata/config:notes.txt", tags = m)
    trivy_config_test(name = s + "_empty", srcs = [], tags = m)
    _LOCK = "//tests/testdata/license:clean/package-lock.json"
    trivy_license_test(name = s + "_license", srcs = [_LOCK], tags = m)
    trivy_license_test(name = s + "_license_both", image = "//tests/images:clean", srcs = [_LOCK], tags = m)
    trivy_license_test(name = s + "_license_neither", tags = m)
    trivy_license_test(name = s + "_license_category", srcs = [_LOCK], allow_categories = ["copyleft"], tags = m)
    trivy_license_test(name = s + "_license_format", srcs = [_LOCK], formats = ["spdx"], tags = m)
    trivy_license_test(name = s + "_license_java_srcs", srcs = [_LOCK], java_db = "//:java_db", tags = m)

    tests = {
        "_db": (_data_info_test, "//:db", {"kind": "db", "files": ["metadata.json", "trivy.db"]}),
        "_checks": (_data_info_test, "//:checks", {"kind": "checks", "files": ["bundle.tar.gz"]}),
        "_binary": (_binary_info_test, "//toolchain:current", {}),
        "_image_executable": (_has_executable_test, ":" + s + "_image", {}),
        "_config_executable": (_has_executable_test, ":" + s + "_config", {}),
        "_no_java_db": (_no_java_db_test, ":" + s + "_image", {}),
        "_bad_severity": (_fails_test, ":" + s + "_bad_severity", {"message": "severity = \"SEVERE\": expected one of UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL"}),
        "_lowercase_severity": (_fails_test, ":" + s + "_lowercase_severity", {"message": "severity = \"high\""}),
        "_two_images": (_fails_test, ":" + s + "_two_images", {"message": "image must be exactly one file or directory"}),
        "_not_image": (_fails_test, ":" + s + "_not_image", {"message": "expected an OCI layout directory (oci_image) or a .tar image tarball"}),
        "_empty": (_fails_test, ":" + s + "_empty", {"message": "srcs is empty"}),
        "_license_executable": (_has_executable_test, ":" + s + "_license", {}),
        "_license_no_db": (_no_db_test, ":" + s + "_license", {}),
        "_license_both": (_fails_test, ":" + s + "_license_both", {"message": "set exactly one of image"}),
        "_license_neither": (_fails_test, ":" + s + "_license_neither", {"message": "set exactly one of image"}),
        "_license_category": (_fails_test, ":" + s + "_license_category", {"message": "allow_categories: unknown category \"copyleft\": Trivy's are forbidden, restricted, reciprocal, notice, permissive, unencumbered, unknown."}),
        "_license_format": (_fails_test, ":" + s + "_license_format", {"message": "formats: \"spdx\": expected spdx-json or cyclonedx."}),
        "_license_java_srcs": (_fails_test, ":" + s + "_license_java_srcs", {"message": "java_db and platform apply to an image, not srcs."}),
    }
    for suffix, (rule, target, kw) in tests.items():
        rule(name = name + suffix, target_under_test = target, **kw)
    native.test_suite(name = name, tests = [":" + name + t for t in tests])
