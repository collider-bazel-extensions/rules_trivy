# rules_trivy

Bazel rules for Trivy: hermetic, offline scans as tests.
- `trivy_image_test`: an image's known vulnerabilities, against a pinned vulnerability DB;
- `trivy_config_test`: misconfigurations in any rule's outputs, with a pinned checks bundle;
- `trivy_ignore_test`: an ignore file's shape and expiry.

See DESIGN.md.

## Commit requirements

- All tests must pass before any commit with code changes:
  - `bazel test //tests/...` (offline: `.bazelrc` sets `--sandbox_default_allow_network=false`);
  - `bazel test //tests:java_db_test`;
  - `(cd tests/consumer && bazel test //...)`;
  - `.github/consumer/check.sh <scratch dir>` (it archives `HEAD`, so commit first).
- All documentation (`README.md`, `DESIGN.md`, `CLAUDE.md`) must be updated to reflect any code changes before committing: new rules, changed attributes, new public API surface, behaviour changes.
- No test may touch the network. A new scan path must keep working under the sandbox flag, and anything Trivy would download must be pinned as a repository.
- Commit messages end with a blank line and `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Repo layout

```
rules_trivy/
├── MODULE.bazel              # module; trivy extension + toolchains; dev: rules_oci, tar.bzl, rules_shell
├── .bazelrc                  # test --sandbox_default_allow_network=false
├── .gitattributes            # tests/, tools/ export-ignore: the release archive loads with //...
├── .github/consumer/check.sh # CI: the git archive as a consumer (//... loads, tag behaviours, root pins)
├── BUILD.bazel               # //:db, //:java_db, //:checks (aliases), //:db_info, //:db_latest
├── defs.bzl                  # public API re-exports
├── extensions.bzl            # trivy.version / db / java_db / checks (own tags, root overrides per class)
├── private/
│   ├── versions.bzl          # DEFAULT_VERSION, TRIVY_VERSIONS (sha256 pins), ASSETS, PLATFORMS,
│   │                         # DATA (manifest-digest pins), DATA_KINDS (media type, cache layout)
│   ├── repositories.bzl      # trivy_binary_repo; trivy_data_repo (manifest + layer by digest, GHCR token)
│   ├── data.bzl              # trivy_data (TrivyDataInfo) declared in each data repo
│   ├── providers.bzl         # TrivyBinaryInfo, TrivyDataInfo
│   ├── test.bzl              # trivy_image_test, trivy_config_test, trivy_ignore_test
│   ├── info.bzl              # trivy_db_info, trivy_db_latest (bazel run)
│   ├── trivy.py              # driver: ignore-file parser/validator, staging, offline trivy run, verdict,
│   │                         # JUnit; db-info; latest (tag -> digest, rewrites versions.bzl)
│   └── run.sh.tmpl           # wrapper: runfiles, then python3 -I driver
├── toolchain/                # toolchain_type, per-platform toolchains, :current
├── tools/update_versions.sh  # binary pins from trivy_<ver>_checksums.txt (verified); --check
├── tools/update_db.sh        # DATA pins from the upstream tags
└── tests/
    ├── BUILD.bazel, analysis_tests.bzl, expect.bzl + expect_test.sh (run a manual target, check exit/output/JUnit)
    ├── images/               # tiny alpine images (os-release + apk db; tar.bzl + rules_oci), index, tarball, java
    ├── testdata/config/      # k8s hardened/privileged/template, Dockerfile, terraform, remote module, notes.txt
    ├── testdata/ignore/      # accepted/expired/empty ignore files + one malformed file per error
    ├── consumer/             # separate consumer module (external labels, rules_oci image; CI)
    └── checksums_test.sh, data_pins_test.sh, version_test.sh, db_info_test.sh, network_blocked_test.sh
```

## Key concepts

- **Data pins.**
  - The DB, Java DB and checks bundle are pinned by OCI manifest digest. The repo rule downloads the manifest (sha = digest), then its one layer (sha = layer digest), so both come from the repository cache when present.
  - The DB unpacks to ~1.8 GB. Tests symlink it into a per-test Trivy cache dir, and Trivy opens it read-only.
  - The checks bundle stays packed and is unpacked per test.
  - The Java DB is fetched only by tests with `java_db`.
- **Staging.** Trivy refuses symlinked OCI layout blobs and skips symlinked config files, so inputs are hard-linked (or copied) into `$TEST_TMPDIR`. Configs go under their workspace paths. An image index is resolved to one platform's manifest by the driver, because Trivy ignores `--platform` with `--input`.
- **Nothing implicit.**
  - Flags: `--config ""`, `--ignorefile <checked file|"">`, `--module-dir <empty>`, the skip/offline flags, and `--cache-backend memory`.
  - Environment: `TRIVY_*` removed, `HTTP(S)_PROXY` set to `127.0.0.1:9`, `PATH` empty, and `HOME` in the tmpdir.
- **Ignore file.** Trivy's `.trivyignore.yaml` schema, read by a strict YAML-subset parser in `trivy.py`. `id`, `statement` and `expired_at` are mandatory; an expired entry (today ≥ expired_at, UTC) fails the test. The checked entries go to Trivy as JSON.
- **Verdict.** Trivy reports everything (`--exit-code 0`). The driver fails on severity ≥ `severity`. Exit 0 pass, 1 findings or expired entries, 2 errors.
- **Toolchain.** Unversioned `trivy_<plat>` repos. Keep `DEFAULT_VERSION` and `trivy.version()` in `MODULE.bazel` equal (`//tests:version_test`).

## Public API

```python
load("@rules_trivy//:defs.bzl",
    "trivy_image_test",   # image, severity, ignore, ignore_unfixed, java_db, platform, extra_args
    "trivy_config_test",  # srcs, severity, ignore, extra_args
    "trivy_ignore_test",  # src, expect_error (regex; empty = must pass)
    "TrivyBinaryInfo", "TrivyDataInfo",
)
# @rules_trivy//:db, :java_db, :checks   pinned data (TrivyDataInfo)
# bazel run @rules_trivy//:db_info       pinned data + age
# bazel run @rules_trivy//:db_latest     current upstream digests as trivy.db/java_db/checks() lines
# MODULE.bazel: trivy.version(version, sha256 = {plat: sha}); trivy.db / java_db / checks(digest, repository)
```

## Development

```sh
bazel test //tests/...
bazel test //tests:java_db_test               # ~1 GB Java DB download, once
(cd tests/consumer && bazel test //...)
.github/consumer/check.sh /tmp/consumer       # from HEAD's git archive
tools/update_versions.sh 0.76.2               # re-pin; --check verifies
tools/update_db.sh                            # re-pin DATA; then re-run the tests (fixtures depend on the DB)
```

### Test results (last full run: 2026-11-16)

All 56 `//tests/...` targets pass on Linux x86_64 (Trivy 0.76.2, DB `sha256:0d6a013bd032…`) with network blocked in the sandbox, plus the manual `//tests:java_db_test`. Other checks:
- **Consumer module:** `tests/consumer` passes: a rules_oci image with accepted CVEs, a config test and an ignore test, from another repository.
- **Release archive:** `.github/consumer/check.sh` passes all seven checks: `//...` loads (20 targets) without `tests/`/`tools/`; no tag resolves to the pins; repeated tag; unpinned version fails; self-pinned 0.76.1 runs, an unpinned darwin platform fails on fetch; root `trivy.checks()` pin applied (v2.2.0); two `trivy.db()` fail.
- **Pins:** `tools/update_versions.sh --check`: all four platforms match the published checksums and the downloads. `tools/update_db.sh`'s rewrite restored a deliberately stale DB pin.
- **Python:** `trivy.py` parses as Python 3.8 syntax. Only Python 3.14 was available to run it.

| Test target | What it verifies | Result |
|---|---|---|
| `//tests:vulnerable_image_test` | vulnerable image fails at HIGH: 2 CVEs with fixed versions, MEDIUMs counted, JUnit 2 failures, DB digest + age shown | PASSED |
| `//tests:clean_image_test` | clean image passes at UNKNOWN | PASSED |
| `//tests:severity_critical_test`, `//tests:severity_medium_test` | threshold: same image passes at CRITICAL, fails with 4 at MEDIUM | PASSED |
| `//tests:ignored_image_test`, `//tests:ignored_image_output_test` | both HIGHs ignored (one by purl) → pass; each suppression listed with its statement | PASSED |
| `//tests:expired_ignore_test` | an expired entry fails, naming it (and only it) | PASSED |
| `//tests:malformed_ignore_test` | a malformed ignore file fails the scan (exit 2) with the problem and an example | PASSED |
| `//tests:tarball_image_test` | `oci_load` tarball input finds the same | PASSED |
| `//tests:index_arm64_test`, `//tests:index_amd64_test`, `//tests:index_no_platform_test` | `oci_image_index`: `platform` picks the image; none given fails | PASSED |
| `//tests:ignore_unfixed_test` | `ignore_unfixed` keeps fixed CVEs | PASSED |
| `//tests:java_without_db_test` | jar without `java_db`: exit 2, says to set it | PASSED |
| `//tests:java_db_test` (manual) | with the Java DB: log4j-core 2.14.1 → CVE-2021-44228 CRITICAL | PASSED |
| `//tests:misconfigured_test` | k8s, a genrule render, Dockerfile, Terraform: HIGH findings by workspace path + line; checks bundle shown | PASSED |
| `//tests:hardened_config_test`, `//tests:hardened_medium_test` | hardened manifest passes at HIGH, fails at MEDIUM (KSV-0125) | PASSED |
| `//tests:ignored_config_test`, `//tests:expired_config_test` | misconfig ignores (with `paths`); expired one fails | PASSED |
| `//tests:remote_module_test`, `//tests:remote_module_note_test` | remote Terraform module isn't fetched; NOTE printed; passes | PASSED |
| `//tests:unrecognised_test` | nothing recognised → exit 2, not a silent pass | PASSED |
| `//tests:ignore_*_test` (18) | valid/empty files pass; 13 malformed files and 2 expired ones fail with their messages | PASSED |
| `//tests:checksums_test`, `//tests:data_pins_test`, `//tests:version_test` | pins well-formed; binary = DEFAULT_VERSION = MODULE.bazel | PASSED |
| `//tests:db_info_test` | `bazel run //:db_info` output | PASSED |
| `//tests:network_blocked_test` | the test sandbox has no network | PASSED |
| `//tests:analysis_tests_*` (11) | providers (data kinds, binary), executables, no Java DB unless asked, bad/lowercase severity, two files / non-image as `image`, empty `srcs` | PASSED |

## Known limitations

- `python3` (3.8+) is required on the host.
- A cached passing test doesn't notice an ignore entry expiring; run uncached on a schedule.
- Remote Terraform modules are never evaluated.
- Fixture expectations depend on the pinned DB; a DB bump can change them.
- Only Linux x86_64 was run; the darwin and arm64 binaries are pinned and verified, not executed.
