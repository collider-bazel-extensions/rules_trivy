"""expect_test: runs a manual rules_trivy test target, checks its exit code,
output and JUnit (see expect_test.sh)."""

load("@rules_shell//shell:sh_test.bzl", "sh_test")

def _quote(s):
    # `args` are Bourne-shell tokenized: keep each pattern one argument.
    return "'" + s.replace("'", "'\\''") + "'"

def expect_test(name, target, exit_code, junit_failures = None, patterns = [], **kwargs):
    sh_test(
        name = name,
        srcs = ["//tests:expect_test.sh"],
        args = [
            "$(rootpath {})".format(target),
            str(exit_code),
            "-" if junit_failures == None else str(junit_failures),
        ] + [_quote(p) for p in patterns],
        data = [target],
        **kwargs
    )
