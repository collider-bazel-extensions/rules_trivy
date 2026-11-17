"""Public API for rules_trivy.

  trivy_image_test   — an image (rules_oci oci_image, or an image tarball)
                       has no known vulnerabilities at or above `severity`,
                       scanned offline against the pinned vulnerability DB
  trivy_config_test  — files (Kubernetes manifests, Helm / Kustomize renders,
                       Terraform, Dockerfiles; any rule's outputs) have no
                       misconfigurations at or above `severity`, checked
                       offline with the pinned checks bundle
  trivy_license_test — the licences Trivy finds in an image or in files
                       (lockfiles, source trees) are all on an allowlist
                       (licence names and Trivy's categories), offline
  trivy_ignore_test  — an ignore file is well formed and none of its
                       entries has expired, without scanning

Every scan accepts findings listed in `ignore` (Trivy's .trivyignore.yaml
schema, plus a `licenses:` section for licence findings), where every
entry needs a `statement` (the reason) and an `expired_at` date; an
expired entry fails the test.
"""

load("//private:providers.bzl", _TrivyBinaryInfo = "TrivyBinaryInfo", _TrivyDataInfo = "TrivyDataInfo")
load(
    "//private:test.bzl",
    _trivy_config_test = "trivy_config_test",
    _trivy_ignore_test = "trivy_ignore_test",
    _trivy_image_test = "trivy_image_test",
    _trivy_license_test = "trivy_license_test",
)

trivy_image_test = _trivy_image_test
trivy_config_test = _trivy_config_test
trivy_license_test = _trivy_license_test
trivy_ignore_test = _trivy_ignore_test

TrivyBinaryInfo = _TrivyBinaryInfo
TrivyDataInfo = _TrivyDataInfo
