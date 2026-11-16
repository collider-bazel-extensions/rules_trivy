"""Tiny test images, built without a base image or a registry: an Alpine
os-release and an apk database naming one package version, plus optional
extra files. That is all Trivy needs to detect the OS and match the
package against the vulnerability DB."""

load("@rules_oci//oci:defs.bzl", "oci_image")
load("@tar.bzl//tar:tar.bzl", "tar")

def alpine_image(name, installed, files = {}, architecture = "amd64", **kwargs):
    """installed: an apk `installed` database file; files: {path in image: label}.

    mtree paths start with `./`: a bare one-component directory line would
    make mtree descend into it, and later lines land beneath."""
    lines = [
        "./etc uid=0 gid=0 mode=0755 type=dir",
        "./etc/os-release uid=0 gid=0 mode=0644 time=0 type=file content=$(location :os-release)",
        "./etc/alpine-release uid=0 gid=0 mode=0644 time=0 type=file content=$(location :alpine-release)",
        "./lib uid=0 gid=0 mode=0755 type=dir",
        "./lib/apk uid=0 gid=0 mode=0755 type=dir",
        "./lib/apk/db uid=0 gid=0 mode=0755 type=dir",
        "./lib/apk/db/installed uid=0 gid=0 mode=0644 time=0 type=file content=$(location {})".format(installed),
    ]
    dirs = {}
    for path, label in files.items():
        parts = path.split("/")
        for i in range(1, len(parts)):
            d = "/".join(parts[:i])
            if d not in dirs and d not in ("etc", "lib"):
                dirs[d] = True
                lines.append("./{} uid=0 gid=0 mode=0755 type=dir".format(d))
        lines.append("./{} uid=0 gid=0 mode=0644 time=0 type=file content=$(location {})".format(path, label))
    tar(
        name = name + "_layer",
        srcs = [":os-release", ":alpine-release", installed] + files.values(),
        mtree = lines,
    )
    oci_image(
        name = name,
        tars = [":" + name + "_layer"],
        os = "linux",
        architecture = architecture,
        **kwargs
    )
