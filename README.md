# rules_trivy

Bazel rules for [Trivy](https://github.com/aquasecurity/trivy), the vulnerability and misconfiguration scanner. They run Trivy scans as **hermetic, offline Bazel tests**: no test downloads anything, and a result depends only on the commit.

- `trivy_image_test` — scans a container image (a rules_oci `oci_image`, or an image tarball) for known vulnerabilities, against a vulnerability DB pinned as a Bazel repository.
- `trivy_config_test` — scans Kubernetes manifests, Helm and Kustomize renders, Terraform, Dockerfiles (any rule's output files) for misconfigurations, with a pinned checks bundle.
- `trivy_ignore_test` — checks an ignore file on its own: its shape, a reason and an expiry on every entry, and that none has expired.

Both scans fail on findings at or above a `severity`, except those listed in an `ignore` file, where every entry carries a reason (`statement`) and an expiry (`expired_at`). An expired entry fails the test, naming it.

No host Trivy needed. The binary is the upstream release for linux and darwin on amd64 and arm64, pinned by SHA-256 (Trivy 0.76.2). The vulnerability DB, the Java DB and the checks bundle are pinned by OCI manifest digest; each test log shows the DB's digest and age. The rules need `python3` (3.8+) on the host.

## Installation

```python
bazel_dep(name = "rules_trivy", version = "0.1.0")
archive_override(
    module_name = "rules_trivy",
    urls = ["https://github.com/collider-bazel-extensions/rules_trivy/archive/refs/tags/v0.1.0.tar.gz"],
    strip_prefix = "rules_trivy-0.1.0",
    integrity = "sha256-zZOueYD5WjBEc284evzq4qzW9eFMSJuhpeFISYsTETY=",
)
```

To pin by git tag instead, replace the `archive_override` with:

```python
git_override(
    module_name = "rules_trivy",
    remote = "https://github.com/collider-bazel-extensions/rules_trivy",
    tag = "v0.1.0",
)
```

The release archive (the tag tarball) leaves out `tests/` and `tools/`: `tests/` loads dev-only modules (rules_oci, tar.bzl, rules_shell) and `tools/` is for maintainers. So `bazel query @rules_trivy//...` works for consumers pinning with `archive_override`. A `git_override` clone still contains them; name packages instead (for example `@rules_trivy//:all`).

That's all: rules_trivy registers its toolchain and fetches only what a build needs. That means the binary for the platform in use, the vulnerability DB (~140 MB download, ~1.8 GB unpacked) for image tests, and the checks bundle (~240 KB) for config tests. The Java DB (~1 GB) is fetched only for tests that ask for it. Downloads are content-addressed, so they are shared through Bazel's repository cache.

## `trivy_image_test`

```python
load("@rules_oci//oci:defs.bzl", "oci_image")
load("@rules_trivy//:defs.bzl", "trivy_image_test")

oci_image(
    name = "image",
    base = "@distroless_base",
    tars = [":app_layer"],
)

trivy_image_test(
    name = "image_vulns_test",
    image = ":image",
    severity = "HIGH",                      # HIGH and CRITICAL fail
    ignore = ".trivyignore.yaml",           # optional
)
```

On findings the test fails, listing each with its package, installed and fixed versions:

```
trivy //app:image_vulns_test: Trivy 0.76.2, fails on HIGH and above
  db       ghcr.io/aquasecurity/trivy-db@sha256:0d6a013bd032 (built 2026-11-16T13:03Z, 0 days old)
  below HIGH (not failing): 2 MEDIUM
trivy //app:image_vulns_test: 2 finding(s) at or above HIGH in app/image:
  HIGH      CVE-2026-22184    zlib 1.3.1-r2 (fixed: 1.3.2-r0)  zlib: zlib: Arbitrary code execution via buffer overflow in untgz utility
  HIGH      CVE-2026-85091    zlib 1.3.1-r2 (fixed: 1.3.2-r1)  zlib: zlib: Heap buffer overflow in gz_vacate() allows arbitrary code execution
Fix them, or accept one in the ignore file (`ignore`) with a statement and an expired_at.
```

- **The image:**
  - An `oci_image` (its OCI layout directory).
  - An `oci_image_index`, with `platform` naming the image to scan. Without `platform`, a multi-platform index is an error: Trivy itself would silently scan the first image.
  - An image tarball, for example an `oci_load`'s `tarball` output group:

    ```python
    filegroup(name = "image_tarball", srcs = [":image_load"], output_group = "tarball")
    ```

  The layout is staged as real files: Trivy refuses symlinked blobs, which rules_oci creates.
- **Offline:** Trivy runs with `--skip-db-update --skip-java-db-update --offline-scan` against the pinned DB.
- **Severity:** findings below `severity` are counted in the log but don't fail.
- **Missing inputs:** before Trivy runs, the test checks the image, the pinned DB and checks bundle, `srcs` and the ignore file are in its runfiles. A missing one fails (exit 2) with one line naming it, e.g. `the vulnerability DB is missing: external/+trivy+trivy_db/db/trivy.db`.
- **Java:** an image with `.jar`/`.war`/`.ear` files needs the Java DB. Without it, Trivy refuses to scan and the test says so. Add `java_db = "@rules_trivy//:java_db"`.
- **Reports:**
  - JUnit goes to `$XML_OUTPUT_FILE`, one failing test case per finding;
  - Trivy's JSON report goes to the test's undeclared outputs (`bazel-testlogs/<pkg>/<name>/test.outputs/trivy.json`).

| Argument | Default | |
|---|---|---|
| `image` | | an `oci_image`, `oci_image_index`, or image `.tar` (required) |
| `severity` | `"HIGH"` | lowest failing severity: `UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `ignore` | none | an ignore file (below) |
| `ignore_unfixed` | `False` | leave out vulnerabilities without a fixed version |
| `java_db` | none | `"@rules_trivy//:java_db"` for images with Java archives |
| `platform` | none | for an image index: `"linux/arm64"`, ... |
| `extra_args` | `[]` | extra Trivy arguments, e.g. `["--pkg-types=os"]` |

## `trivy_config_test`

```python
load("@rules_trivy//:defs.bzl", "trivy_config_test")

trivy_config_test(
    name = "manifests_test",
    srcs = [
        "//deploy:helm_render",        # any rule's outputs: a Helm or Kustomize render
        "//infra:terraform_files",
        "Dockerfile",
    ],
    severity = "HIGH",
    ignore = ".trivyignore.yaml",
)
```

```
trivy //deploy:manifests_test: 3 finding(s) at or above HIGH in 4 file(s):
  HIGH      KSV-0017          deploy/rendered/deployment.yaml:18  Privileged
  HIGH      DS-0002           Dockerfile  Image user should not be 'root'
  HIGH      AWS-0092          infra/main.tf:3  S3 Buckets not publicly accessible through ACL.
```

- **Workspace paths, even for generated files.** Bazel's inputs are symlinks, and Trivy's directory walker skips symlinks: a scan of a runfiles tree finds nothing and passes. So each input (files and tree artifacts) is staged as a real file (a hard link, or a copy) under its workspace path. Findings, and an ignore entry's `paths`, use `deploy/rendered/deployment.yaml`, not `bazel-out/...`.
- **Nothing recognised is an error.** If Trivy finds no configuration it knows in `srcs`, the test fails rather than passing having checked nothing.
- **What Trivy reads:**
  - Kubernetes manifests (by content);
  - Helm charts (rendered offline, without chart dependencies);
  - Terraform, Dockerfiles, CloudFormation, Azure ARM and Ansible.

  Kustomize isn't rendered by Trivy: scan your render's output.
- **Terraform remote modules** (`source = "terraform-aws-modules/..."` or `git::`) are never downloaded. Trivy has no switch to stop it trying, so the test runs it with no route out, notes the module it couldn't load, and checks the rest. Vendor a module (a local `source`) to have it checked.
- **Checks:** from the pinned trivy-checks bundle, not Trivy's run-time download (`--skip-check-update`).
- Takes `severity`, `ignore` and `extra_args` like `trivy_image_test`, and writes the same reports.

## The ignore file

An ignore file uses Trivy's own [`.trivyignore.yaml`](https://trivy.dev/docs/latest/guide/configuration/filtering/#trivyignoreyaml) schema, with two rules added: every entry needs a `statement` (the reason) and an `expired_at` date.

```yaml
vulnerabilities:
  - id: CVE-2026-22184
    statement: untgz is not in the image; only libz is
    expired_at: 2027-03-31
  - id: CVE-2026-85091
    statement: no gzip file output on this path
    expired_at: 2027-01-31
    purls: ["pkg:apk/alpine/zlib@1.3.1-r2?arch=x86_64&distro=3.22.0"]   # optional
misconfigurations:
  - id: KSV-0017
    statement: the node agent needs host access
    expired_at: 2027-06-30
    paths: ["deploy/rendered/agent.yaml"]   # optional; workspace paths, globs allowed
```

- **Entries:** `vulnerabilities` and `misconfigurations` hold lists of entries. Each entry has `id`, `statement` and `expired_at` (`YYYY-MM-DD`). `paths` and `purls` (vulnerabilities only) narrow it.
- **Expiry.** An entry expires at the start of its `expired_at` day (UTC), as in Trivy. Trivy itself just stops applying an expired entry; here the test fails, naming it:

  ```
  trivy //app:image_vulns_test: ignore file app/.trivyignore.yaml: 1 expired entry:
    vulnerabilities[0] (CVE-2026-22184): expired_at 2027-03-31 -- 'untgz is not in the image; only libz is'
  Review each: fix the finding, or extend expired_at with a current statement.
  ```

- **Malformed files fail clearly,** listing every problem, before anything is scanned:

  ```
  ignore file app/.trivyignore.yaml is malformed:
    vulnerabilities[0] (CVE-2026-22184): unknown key 'reason' -- the reason goes in 'statement' (Trivy's key) (known: id, statement, expired_at, paths, purls)
    vulnerabilities[0] (CVE-2026-22184): 'statement' is missing or empty (the reason this finding is accepted)
  ```

- **The YAML subset:** the file is read without a YAML library. Block mappings and lists, `[a, b]` lists, plain or quoted strings, and comments are supported. Anchors, tags, multi-line (`|`, `>`) strings and `{...}` mappings are rejected by line number rather than guessed at.
- **What applies:** the checked entries are handed to Trivy as its `--ignorefile`, so matching (`id`, `paths`, `purls`) is Trivy's. An image test lists what each entry suppressed, and notes entries that matched nothing.
- **Caching.** Bazel caches a passing test until its inputs change, and the date isn't an input. So a cached pass doesn't notice an entry expiring. Inputs do change whenever the DB pin is bumped, which re-runs every image test. For a hard guarantee, run the scans uncached on a schedule: `bazel test --nocache_test_results //...`.

### `trivy_ignore_test`

```python
load("@rules_trivy//:defs.bzl", "trivy_ignore_test")

trivy_ignore_test(name = "trivyignore_test", src = ".trivyignore.yaml")

trivy_ignore_test(                       # a bad file must fail with this message
    name = "typo_is_caught_test",
    src = "testdata/bad.trivyignore.yaml",
    expect_error = "unknown key 'reason'",  # Python regex (re.search)
)
```

It runs the ignore-file check without a scan, so it needs no DB.

## The pinned data, its age, and bumping it

Trivy normally downloads three OCI artifacts at scan time. rules_trivy pins each by manifest digest instead:

| Artifact | Repository | Used by | Size (download / unpacked) |
|---|---|---|---|
| vulnerability DB | `ghcr.io/aquasecurity/trivy-db` (tag `2`) | `trivy_image_test` | ~140 MB / ~1.8 GB |
| Java DB | `ghcr.io/aquasecurity/trivy-java-db` (tag `1`) | `trivy_image_test(java_db = ...)` | ~1 GB / ~1.6 GB |
| checks bundle | `ghcr.io/aquasecurity/trivy-checks` (tag `2`) | `trivy_config_test` | ~240 KB |

- **How a pin is fetched:** the repository rule downloads the manifest at the pinned digest, which Bazel verifies, and then the single layer at the digest the manifest names. A result is therefore reproducible for a given commit.
- **Its age is visible:**
  - every test log prints each artifact's digest, build time and age;
  - `bazel run @rules_trivy//:db_info` prints them too.

  ```
  db       ghcr.io/aquasecurity/trivy-db@sha256:0d6a013bd032 (built 2026-11-16T13:03Z, 0 days old)
           digest sha256:0d6a013bd032c744faa11f7a2b496419407c523a25325987f0ab9344849983fd
  ```

- **To bump** (aquasecurity rebuilds the DB every few hours), ask for the current digests:

  ```sh
  bazel run @rules_trivy//:db_latest
  ```

  ```
  trivy = use_extension("@rules_trivy//:extensions.bzl", "trivy")
  trivy.db(digest = "sha256:...")  # ghcr.io/aquasecurity/trivy-db:2, created 2026-11-16T13:13:10Z
  trivy.java_db(digest = "sha256:...")  # ...
  trivy.checks(digest = "sha256:...")  # ...
  ```

  Paste the lines you want into your `MODULE.bazel`. Only the root module's tags count, each replacing rules_trivy's pin for that artifact. Without them you get the pins of your rules_trivy release.
- **Old digests stay fetchable.** A pin keeps working: GHCR still serves the DB's old manifests and layers. When this was written, the package listed about 12,000 untagged versions back to 2021, and a 4-month-old DB layer still downloaded and matched its digest (DESIGN.md).
- **Mirrors.** `trivy.db(digest = ..., repository = "registry.example.com/mirror/trivy-db")` fetches the same digest from another registry. Bazel's `--downloader_config` can also rewrite the URLs.

## Offline, and nothing implicit

Every scan:
- passes `--skip-db-update`, `--skip-java-db-update`, `--skip-check-update`, `--offline-scan`, `--skip-version-check` and `--disable-telemetry`;
- has `HTTP(S)_PROXY` pointing at a closed local port, `PATH` empty, and `HOME` and the cache directory in the test's temporary directory. So anything left that would reach the network (a Terraform remote module) fails the same way inside or outside a network sandbox;
- never reads a `trivy.yaml` or `.trivyignore` from the working directory, `TRIVY_*` environment variables, or WASM modules from `~/.trivy`;
- uses Trivy's cache backend `memory` and opens the DB read-only (it's linked into the cache directory, never copied or written).

This repository's own tests run with `--sandbox_default_allow_network=false` (`.bazelrc`), and `//tests:network_blocked_test` checks the sandbox really has no network.

## Pinned versions

| Component | Version | Source |
|---|---|---|
| Trivy | `0.76.2` | aquasecurity/trivy releases (published checksums, verified against the downloads) |
| vulnerability DB | `sha256:0d6a013bd032…` (2026-11-16T13:13Z) | `ghcr.io/aquasecurity/trivy-db:2` |
| Java DB | `sha256:972051a7b3da…` (2026-11-16T00:58Z) | `ghcr.io/aquasecurity/trivy-java-db:1` |
| checks bundle | `sha256:b0e12d009b01…` (v2.3.0, 2026-10-14) | `ghcr.io/aquasecurity/trivy-checks:2` |

To use another Trivy version, name it in your `MODULE.bazel`. A version rules_trivy doesn't list needs its shas, from the release's `trivy_<version>_checksums.txt`; a platform left out fails only if a build needs it:

```python
trivy = use_extension("@rules_trivy//:extensions.bzl", "trivy")
trivy.version(
    version = "0.76.1",
    sha256 = {
        "linux_amd64": "c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0",
        "linux_arm64": "e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f",
    },
)
```

Maintainers:
- `tools/update_versions.sh <version>` pins all four platforms from the checksums file, cross-checked against the downloads, and `--check` verifies the pins. Then bump `DEFAULT_VERSION` and `trivy.version()` in `MODULE.bazel` (`//tests:version_test`).
- `tools/update_db.sh` re-pins the data.

## Development

```sh
bazel test //tests/...                    # offline (.bazelrc)
bazel test //tests:java_db_test           # + the ~1 GB Java DB
(cd tests/consumer && bazel test //...)   # rules_trivy from another repository
.github/consumer/check.sh /tmp/consumer   # the release archive, as a consumer
```

See [DESIGN.md](DESIGN.md) for the design and trade-offs, and [CLAUDE.md](CLAUDE.md) for the repo layout and test inventory.

---

## Requesting a new rules package

Want Bazel rules for another tool or service?
[Request a rules package](https://github.com/collider-bazel-extensions/.github/issues/new?template=request-a-rules-package.yml).
The [organization page](https://github.com/collider-bazel-extensions) lists every package.
