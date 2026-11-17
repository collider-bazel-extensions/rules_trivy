#!/usr/bin/env python3
"""rules_trivy driver (host python3, 3.8+; standard library only).

Modes:
  image         trivy image --input <OCI layout dir | image tarball>, offline
  config        trivy config over staged srcs, offline
  license       trivy's licence scanner over an image or staged srcs, offline,
                checked against an allowlist
  check-ignore  validate an ignore file (shape, reasons, expiry) and exit
  db-info       print the pinned data artifacts and their age
  latest        resolve the upstream tags to digests (network; bazel run only)

Exit codes: 0 pass, 1 findings at or above the threshold, licences outside
the allowlist (or an expired ignore entry), 2 rules_trivy or Trivy failed (bad ignore file, Trivy error).

Paths given with --runfiles are runfiles short paths (`pkg/f` in the main
repository, `../repo/f` in another), resolved against $RUNFILES_DIR.
"""

import argparse
import datetime
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from xml.sax.saxutils import escape, quoteattr

SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# ---- runfiles -----------------------------------------------------------------


def runfile(path):
    root = os.environ.get("RUNFILES_DIR")
    if not root:
        return path
    if path.startswith("../"):
        return os.path.join(root, path[3:])
    return os.path.join(root, "_main", path)


def workspace_path(short_path):
    """Where a file is staged: its workspace path (`external/<repo>/...`
    for files from other repositories)."""
    return "external/" + short_path[3:] if short_path.startswith("../") else short_path


# ---- ignore file: a strict YAML subset ------------------------------------------
#
# The ignore file uses Trivy's own .trivyignore.yaml schema. The standard
# library has no YAML parser, so this reads the subset that schema needs --
# block mappings and sequences, flow lists of scalars, plain / 'single' /
# "double"-quoted scalars, comments -- and rejects anything else by line
# instead of guessing (anchors, tags, multi-line scalars, flow mappings).


class IgnoreError(Exception):
    pass


_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*:(?:\s+(.*))?$")


def _strip_comment(s):
    out, quote = [], None
    for i, c in enumerate(s):
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t"):
            break
        out.append(c)
    return "".join(out).rstrip()


def _scalar(text, line):
    t = text.strip()
    if t == "":
        return None
    if t[0] == '"':
        if len(t) < 2 or not t.endswith('"'):
            raise IgnoreError("line {}: unterminated double-quoted string".format(line))
        try:
            return json.loads(t)
        except ValueError:
            raise IgnoreError("line {}: unsupported escape in {}".format(line, t))
    if t[0] == "'":
        if len(t) < 2 or not t.endswith("'"):
            raise IgnoreError("line {}: unterminated single-quoted string".format(line))
        return t[1:-1].replace("''", "'")
    if t[0] in "&*!|>{%@`":
        raise IgnoreError("line {}: unsupported YAML ({!r}): use plain or quoted strings".format(line, t[0]))
    if t[0] == "[":
        return _flow_list(t, line)
    return t


def _flow_list(t, line):
    if not t.endswith("]"):
        raise IgnoreError("line {}: a flow list must close on the same line".format(line))
    body = t[1:-1].strip()
    if not body:
        return []
    items, cur, quote = [], [], None
    for c in body:
        if quote:
            cur.append(c)
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
            cur.append(c)
        elif c == ",":
            items.append("".join(cur))
            cur = []
        elif c in "[]{}":
            raise IgnoreError("line {}: nested flow collections are not supported".format(line))
        else:
            cur.append(c)
    items.append("".join(cur))
    out = []
    for it in items:
        v = _scalar(it, line)
        if v is None:
            raise IgnoreError("line {}: empty item in flow list".format(line))
        if isinstance(v, list):
            raise IgnoreError("line {}: nested lists are not supported".format(line))
        out.append(v)
    return out


def parse_yaml_subset(text):
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        body = raw.rstrip()
        stripped = body.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        if body.lstrip(" \t") != stripped or "\t" in body[: len(body) - len(stripped)]:
            raise IgnoreError("line {}: tab in indentation".format(n))
        if stripped == "---" and not lines:
            continue
        lines.append([len(body) - len(stripped), _strip_comment(stripped), n])
    if not lines:
        return None
    value, i = _block(lines, 0, lines[0][0])
    if i < len(lines):
        raise IgnoreError("line {}: unexpected content (check the indentation)".format(lines[i][2]))
    return value


def _block(lines, i, indent):
    if lines[i][1] == "-" or lines[i][1].startswith("- "):
        return _sequence(lines, i, indent)
    return _mapping(lines, i, indent)


def _sequence(lines, i, indent):
    out = []
    while i < len(lines) and lines[i][0] == indent and (lines[i][1] == "-" or lines[i][1].startswith("- ")):
        content, n = lines[i][1], lines[i][2]
        rest = content[1:].lstrip(" ")
        if not rest:
            if i + 1 < len(lines) and lines[i + 1][0] > indent:
                v, i = _block(lines, i + 1, lines[i + 1][0])
                out.append(v)
            else:
                raise IgnoreError("line {}: empty list item".format(n))
        elif _KEY.match(rest):
            # `- key: value` starts a mapping whose keys align with `key`.
            col = indent + (len(content) - len(rest))
            lines[i] = [col, rest, n]
            v, i = _mapping(lines, i, col)
            out.append(v)
        else:
            out.append(_scalar(rest, n))
            i += 1
    if i < len(lines) and lines[i][0] > indent:
        raise IgnoreError("line {}: unexpected indentation".format(lines[i][2]))
    return out, i


def _mapping(lines, i, indent):
    out = {}
    while i < len(lines) and lines[i][0] == indent:
        content, n = lines[i][1], lines[i][2]
        if content == "-" or content.startswith("- "):
            break
        m = _KEY.match(content)
        if not m:
            raise IgnoreError("line {}: expected `key: value`, got {!r}".format(n, content))
        key, rest = m.group(1), m.group(2)
        if key in out:
            raise IgnoreError("line {}: duplicate key '{}'".format(n, key))
        i += 1
        if rest is None or rest.strip() == "":
            if i < len(lines) and lines[i][0] > indent:
                out[key], i = _block(lines, i, lines[i][0])
            elif i < len(lines) and lines[i][0] == indent and (lines[i][1] == "-" or lines[i][1].startswith("- ")):
                out[key], i = _sequence(lines, i, indent)
            else:
                out[key] = None
        else:
            out[key] = _scalar(rest, n)
    if i < len(lines) and lines[i][0] > indent:
        raise IgnoreError("line {}: unexpected indentation".format(lines[i][2]))
    return out, i


# ---- ignore file: schema --------------------------------------------------------

_SECTIONS = {
    "vulnerabilities": ("id", "statement", "expired_at", "paths", "purls"),
    "misconfigurations": ("id", "statement", "expired_at", "paths"),
    # Applied by rules_trivy, not Trivy: id is the licence (as Trivy names
    # it, or NOASSERTION for a package without one); packages narrows it to
    # `name` or `name@version`, paths to file paths (globs).
    "licenses": ("id", "statement", "expired_at", "paths", "packages"),
}
_HINTS = {
    "reason": "the reason goes in 'statement' (Trivy's key)",
    "comment": "the reason goes in 'statement' (Trivy's key)",
    "expires": "the expiry goes in 'expired_at' (Trivy's key)",
    "expiry": "the expiry goes in 'expired_at' (Trivy's key)",
    "expires_at": "the expiry goes in 'expired_at' (Trivy's key)",
    "expiration": "the expiry goes in 'expired_at' (Trivy's key)",
    "secrets": "rules_trivy scans don't report secrets",
    "license": "the section is 'licenses'",
}


def _date(v):
    if not isinstance(v, str) or not re.match(r"^\d{4}-\d{2}-\d{2}$", v):
        return None
    try:
        return datetime.date.fromisoformat(v)
    except ValueError:
        return None


def load_ignore(path, shown, today):
    """-> (sections {name: [entry]}, expired [(name, entry)]). Raises
    IgnoreError listing every problem. An entry expires at the start of its
    expired_at day (UTC), as in Trivy."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError) as e:
        raise IgnoreError("cannot read it: {}".format(e))
    doc = parse_yaml_subset(text)
    if doc is None:
        return {}, []
    if not isinstance(doc, dict):
        raise IgnoreError("expected a mapping with `vulnerabilities:`, `misconfigurations:` and/or `licenses:` lists")
    problems, sections, expired = [], {}, []
    for key, entries in doc.items():
        if key not in _SECTIONS:
            hint = _HINTS.get(key)
            problems.append("unknown section '{}'{} (known: {})".format(
                key, " -- " + hint if hint else "", ", ".join(sorted(_SECTIONS))))
            continue
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            problems.append("{}: expected a list of entries".format(key))
            continue
        known = _SECTIONS[key]
        sections[key] = []
        for idx, e in enumerate(entries):
            where = "{}[{}]".format(key, idx)
            if not isinstance(e, dict):
                problems.append("{}: expected a mapping with id, statement and expired_at".format(where))
                continue
            if isinstance(e.get("id"), str) and e["id"].strip():
                where += " ({})".format(e["id"])
            for k in e:
                if k not in known:
                    hint = _HINTS.get(k)
                    problems.append("{}: unknown key '{}'{} (known: {})".format(
                        where, k, " -- " + hint if hint else "", ", ".join(known)))
            for k in ("id", "statement"):
                v = e.get(k)
                if not isinstance(v, str) or not v.strip():
                    what = "the reason this finding is accepted" if k == "statement" else "the finding's ID"
                    problems.append("{}: '{}' is missing or empty ({})".format(where, k, what))
            if "expired_at" not in e or e["expired_at"] is None:
                problems.append("{}: 'expired_at' is missing (YYYY-MM-DD: when to review it again)".format(where))
            elif _date(e["expired_at"]) is None:
                problems.append("{}: expired_at {!r} is not a date (YYYY-MM-DD)".format(where, e["expired_at"]))
            for k in ("paths", "purls", "packages"):
                if k in e and k in known and not (
                        isinstance(e[k], list) and e[k] and all(isinstance(x, str) and x for x in e[k])):
                    problems.append("{}: '{}' must be a non-empty list of strings".format(where, k))
            sections[key].append(e)
            d = _date(e.get("expired_at"))
            if d is not None and today >= d:
                expired.append((where, e))
    if problems:
        raise IgnoreError("\n".join("  " + p for p in problems))
    return sections, expired


def trivy_ignore_yaml(sections):
    """The validated, unexpired entries in Trivy's schema, as JSON (which
    is YAML), so Trivy applies exactly what was checked here. expired_at is
    dropped: expiry was already enforced. `licenses` is left out: rules_trivy
    applies it."""
    out = {}
    for key, entries in sections.items():
        if key == "licenses":
            continue
        out[key] = [{k: v for k, v in e.items() if k != "expired_at"} for e in entries]
    return json.dumps(out, indent=1) + "\n"


def report_expired(shown, expired):
    lines = ["ignore file {}: {} expired entr{}:".format(shown, len(expired), "y" if len(expired) == 1 else "ies")]
    for where, e in expired:
        lines.append("  {}: expired_at {} -- {!r}".format(where, e["expired_at"], e["statement"]))
    lines.append("Review each: fix the finding, or extend expired_at with a current statement.")
    return "\n".join(lines)


# ---- trivy invocation ------------------------------------------------------------


def utc_today():
    return datetime.datetime.now(datetime.timezone.utc).date()


class MissingInput(Exception):
    pass


def require(short, what):
    """The runfile at `short`, or MissingInput naming it (as `what`)."""
    path = runfile(short)
    if not os.path.exists(path):  # False for a dangling link, too
        raise MissingInput("{} is missing: {}".format(what, workspace_path(short)))
    return path


# Per data kind: its name in messages, and the files in its cache_dir (as
# DATA_KINDS in private/versions.bzl).
DATA_FILES = {
    "db": ("vulnerability DB", ["trivy.db", "metadata.json"]),
    "java_db": ("Java DB", ["trivy-java.db", "metadata.json"]),
    "checks": ("checks bundle", ["bundle.tar.gz"]),
}


def data_info(info_short):
    info_path = require(info_short, "a pinned data artifact's info.json")
    with open(info_path) as f:
        info = json.load(f)
    info["_root"] = os.path.dirname(info_path)
    return info


def require_data(info_short, info):
    """The cache files a scan reads (db-info has only the info.json)."""
    what, files = DATA_FILES.get(info.get("kind"), (info.get("kind"), []))
    for name in files:
        require(os.path.join(os.path.dirname(info_short), info["cache_dir"], name), "the " + what)


def age_text(info):
    stamp = info.get("updated_at") or info.get("created") or ""
    try:
        t = datetime.datetime.strptime(stamp[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return "age unknown"
    days = (datetime.datetime.now(datetime.timezone.utc) - t).days
    return "built {}Z, {} day{} old".format(stamp[:16], days, "" if days == 1 else "s")


def describe(info):
    d = info["digest"]
    v = " v" + info["version"] if info.get("version") else ""
    return "{}@{}{} ({})".format(info["repository"], d[:19], v, age_text(info))


def setup_cache(cache, infos):
    for info in infos:
        dest = os.path.join(cache, info["cache_dir"])
        src = os.path.join(info["_root"], info["cache_dir"])
        os.makedirs(dest, exist_ok=True)
        if info["kind"] == "checks":
            content = os.path.join(dest, "content")
            os.makedirs(content)
            with tarfile.open(os.path.join(src, "bundle.tar.gz")) as t:
                for m in t.getmembers():
                    if not (m.isfile() or m.isdir()) or m.name.startswith("/") or ".." in m.name.split("/"):
                        raise RuntimeError("checks bundle: unexpected member {!r}".format(m.name))
                if hasattr(tarfile, "data_filter"):  # 3.12+, and backports
                    t.extractall(content, filter="data")
                else:
                    t.extractall(content)
            with open(os.path.join(dest, "metadata.json"), "w") as f:
                json.dump({"Digest": info["digest"], "DownloadedAt": "2000-01-01T00:00:00Z"}, f)
        else:
            # The DB files are 1-2 GB: link, never copy. Trivy opens them read-only.
            for name in os.listdir(src):
                os.symlink(os.path.realpath(os.path.join(src, name)), os.path.join(dest, name))


def trivy_env(tmp):
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("TRIVY_")}
    home = os.path.join(tmp, "home")
    os.makedirs(home, exist_ok=True)
    env.update({
        "HOME": home,
        "XDG_CACHE_HOME": os.path.join(home, ".cache"),
        "XDG_CONFIG_HOME": os.path.join(home, ".config"),
        "XDG_DATA_HOME": os.path.join(home, ".local", "share"),
        "TMPDIR": tmp,
        # Nothing may come from the network. Trivy's own downloads are all
        # switched off by flags; anything left (a Terraform remote module,
        # a future feature) goes to a proxy that isn't there and fails at
        # once, the same way inside or outside a network sandbox.
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
        "http_proxy": "http://127.0.0.1:9",
        "https_proxy": "http://127.0.0.1:9",
        "all_proxy": "http://127.0.0.1:9",
        "NO_PROXY": "",
        "no_proxy": "",
        # Nor from other programs: go-getter shells out to git for git::
        # module sources.
        "PATH": os.path.join(tmp, "no-path"),
    })
    return env


def common_flags(cache, tmp, ignorefile, out_json):
    module_dir = os.path.join(tmp, "modules")
    os.makedirs(module_dir, exist_ok=True)
    return [
        "--cache-dir", cache,
        "--cache-backend", "memory",
        "--config", "",              # no trivy.yaml from the working directory
        "--ignorefile", ignorefile,  # "" = none; never ./.trivyignore
        "--module-dir", module_dir,  # no WASM modules from ~/.trivy
        "--skip-version-check",
        "--disable-telemetry",
        "--format", "json",
        "--output", out_json,
        "--exit-code", "0",
    ]


def run_trivy(cmd, env):
    p = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    return p.returncode, p.stdout


def log_lines(out, levels=("WARN", "ERROR", "FATAL")):
    keep = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[1].strip() in levels:
            keep.append("\t".join(parts[1:]))
    return keep


# ---- findings ------------------------------------------------------------------


def sev_rank(s):
    s = (s or "UNKNOWN").upper()
    return SEVERITIES.index(s) if s in SEVERITIES else 0


def findings(report, kind):
    out = []
    for res in report.get("Results") or []:
        target = res.get("Target", "")
        if kind == "image":
            for v in res.get("Vulnerabilities") or []:
                fixed = v.get("FixedVersion")
                out.append({
                    "id": v.get("VulnerabilityID", "?"),
                    "severity": (v.get("Severity") or "UNKNOWN").upper(),
                    "target": target,
                    "what": "{} {}{}".format(v.get("PkgName", "?"), v.get("InstalledVersion", ""),
                                             " (fixed: {})".format(fixed) if fixed else " (no fix)"),
                    "title": (v.get("Title") or "").strip(),
                })
        else:
            for m in res.get("Misconfigurations") or []:
                if m.get("Status") != "FAIL":
                    continue
                cause = m.get("CauseMetadata") or {}
                line = cause.get("StartLine")
                out.append({
                    "id": m.get("ID") or m.get("AVDID") or "?",
                    "severity": (m.get("Severity") or "UNKNOWN").upper(),
                    "target": target,
                    "what": "{}{}".format(target, ":{}".format(line) if line else ""),
                    "title": (m.get("Title") or "").strip(),
                })
    return out


def suppressed(report):
    out = []
    mods = list(report.get("ExperimentalModifiedFindings") or [])
    for res in report.get("Results") or []:
        mods += res.get("ExperimentalModifiedFindings") or []
    for m in mods:
        f = m.get("Finding") or {}
        fid = f.get("VulnerabilityID") or f.get("ID") or f.get("AVDID") or "?"
        out.append((fid, m.get("Statement", ""), m.get("Source", "")))
    return out


def write_junit(path, suite, failing, threshold, passed=None):
    cases = []
    for f in failing:
        name = "{} {}".format(f["id"], f["what"])
        msg = "{} {}: {}".format(f["severity"], f["id"], f["title"] or f["what"])
        cases.append('  <testcase classname={} name={}><failure message={}>{}</failure></testcase>'.format(
            quoteattr(suite), quoteattr(name), quoteattr(msg), escape(f["target"])))
    if not cases:
        cases.append('  <testcase classname={} name={}/>'.format(
            quoteattr(suite), quoteattr(passed or "no findings at or above " + threshold)))
    with open(path, "w") as out:
        out.write('<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>\n')
        out.write('<testsuite name={} tests="{}" failures="{}">\n'.format(
            quoteattr(suite), max(1, len(failing)), len(failing)))
        out.write("\n".join(cases) + "\n</testsuite>\n</testsuites>\n")


# ---- scan modes ------------------------------------------------------------------


def stage(manifest, dest):
    """Copy (hard link where possible) every input to its workspace path:
    Trivy's walker skips symlinks, and Bazel's inputs are symlinks."""
    count = 0
    with open(runfile(manifest)) as f:
        for line in f:
            if not line.strip():
                continue
            short = line.rstrip("\n")
            src = os.path.realpath(runfile(short))
            rel = workspace_path(short)
            if os.path.isdir(src):
                for root, _, files in os.walk(src):
                    for name in files:
                        s = os.path.join(root, name)
                        _put(os.path.realpath(s), os.path.join(dest, rel, os.path.relpath(s, src)))
                        count += 1
            else:
                _put(src, os.path.join(dest, rel))
                count += 1
    return count


def _put(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    try:
        os.link(src, dst)
    except OSError:
        shutil.copyfile(src, dst)


class LayoutError(Exception):
    pass


_INDEX = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")


def _platform_text(p):
    p = p or {}
    return "/".join(x for x in (p.get("os"), p.get("architecture"), p.get("variant")) if x) or "(no platform)"


def stage_layout(src, dest, platform):
    """Stage an OCI layout for Trivy, as real files with one image.

    Trivy refuses a layout whose blobs are symlinks, and rules_oci links
    layer blobs to their tarballs (runfiles are links too): every file is
    hard-linked (or copied). Trivy also ignores --platform with --input and
    scans an index's first manifest, so an index is resolved here: to the
    manifest for `platform`, or to its only manifest; the staged index.json
    names just that one."""
    def blob(digest):
        return os.path.join(src, "blobs", *digest.split(":", 1))

    with open(os.path.join(src, "index.json")) as f:
        descs = json.load(f).get("manifests") or []
    # Flatten nested indexes (rules_oci's oci_image_index nests one).
    while len(descs) == 1 and descs[0].get("mediaType") in _INDEX:
        with open(blob(descs[0]["digest"])) as f:
            descs = json.load(f).get("manifests") or []
    descs = [d for d in descs if d.get("mediaType") not in _INDEX]
    descs = [d for d in descs if _platform_text(d.get("platform")) != "unknown/unknown"]  # attestations
    if not descs:
        raise LayoutError("no image manifest in index.json")
    if platform:
        want = platform.split("/")
        chosen = [d for d in descs if _platform_text(d.get("platform")).split("/")[: len(want)] == want]
        if len(chosen) != 1:
            raise LayoutError("platform {!r} matches {} of the index's images ({})".format(
                platform, len(chosen), ", ".join(_platform_text(d.get("platform")) for d in descs)))
    elif len(descs) > 1:
        raise LayoutError("a multi-platform index ({}): set `platform` to the one to scan".format(
            ", ".join(_platform_text(d.get("platform")) for d in descs)))
    else:
        chosen = descs
    for root, _, names in os.walk(src):
        for n in names:
            path = os.path.join(root, n)
            rel = os.path.relpath(path, src)
            if rel == "index.json":
                continue
            _put(os.path.realpath(path), os.path.join(dest, rel))
    with open(os.path.join(dest, "index.json"), "w") as f:
        json.dump({"schemaVersion": 2, "manifests": chosen}, f)
    return dest


def check_inputs(a, kind):
    """Every input the scan reads, before Trivy runs: -> the data infos;
    MissingInput names the first one missing."""
    require(a.trivy, "the Trivy binary")
    if kind == "image" or (kind == "license" and a.image):
        require(a.image, "the image")
    else:
        with open(require(a.manifest, "the srcs manifest")) as f:
            for line in f:
                if line.strip():
                    require(line.rstrip("\n"), "a src")
    if a.ignore:
        require(a.ignore, "the ignore file")
    if a.allowlist:
        require(a.allowlist, "the allowlist")
    infos = []
    for short in a.data:
        info = data_info(short)
        require_data(short, info)
        infos.append(info)
    return infos


def scan(a, kind):
    label = a.label
    try:
        infos = check_inputs(a, kind)
    except MissingInput as e:
        print("trivy {}: {} (not in the test's runfiles)".format(label, e), file=sys.stderr)
        return 2
    tmp = tempfile.mkdtemp(prefix="trivy.", dir=os.environ.get("TEST_TMPDIR"))
    threshold = a.severity.upper()
    print("trivy {}: Trivy {}, fails on {} and above".format(label, a.version, threshold))

    ignorefile = ""
    shown = ""
    if a.ignore:
        shown = workspace_path(a.ignore)
        try:
            sections, expired = load_ignore(runfile(a.ignore), shown, utc_today())
        except IgnoreError as e:
            print("trivy {}: ignore file {} is malformed:\n{}".format(label, shown, e), file=sys.stderr)
            print("Each entry needs id, statement (the reason) and expired_at (YYYY-MM-DD), e.g.\n"
                  "  vulnerabilities:\n"
                  "    - id: CVE-2026-12345\n"
                  "      statement: not reachable: we never call the affected API\n"
                  "      expired_at: 2027-03-31", file=sys.stderr)
            return 2
        if expired:
            print("trivy {}: {}".format(label, report_expired(shown, expired)), file=sys.stderr)
            return 1
        ignorefile = os.path.join(tmp, "trivyignore.yaml")
        with open(ignorefile, "w") as f:
            f.write(trivy_ignore_yaml(sections))

    for info in infos:
        print("  {:8} {}".format(info["kind"], describe(info)))
    cache = os.path.join(tmp, "cache")
    os.makedirs(cache)
    setup_cache(cache, infos)
    out_json = os.path.join(tmp, "trivy.json")
    flags = common_flags(cache, tmp, ignorefile, out_json)

    if kind == "image":
        image = os.path.realpath(runfile(a.image))
        if os.path.isdir(image) and not os.path.exists(os.path.join(image, "index.json")):
            print("trivy {}: image {} is a directory without index.json: not an OCI image layout "
                  "(give an oci_image, or an image tarball)".format(label, workspace_path(a.image)), file=sys.stderr)
            return 2
        what = workspace_path(a.image)
        if os.path.isdir(image):
            try:
                image = stage_layout(image, os.path.join(tmp, "image"), a.platform)
            except LayoutError as e:
                print("trivy {}: image {}: {}".format(label, workspace_path(a.image), e), file=sys.stderr)
                return 2
        elif a.platform:
            print("trivy {}: platform applies to an OCI layout (oci_image_index); {} is a tarball".format(
                label, workspace_path(a.image)), file=sys.stderr)
            return 2
        cmd = [runfile(a.trivy), "image", "--input", image, "--scanners", "vuln", "--show-suppressed",
               "--skip-db-update", "--skip-java-db-update", "--offline-scan"] + flags
        if a.ignore_unfixed:
            cmd.append("--ignore-unfixed")
        cmd += a.extra
    else:
        target = os.path.join(tmp, "scan")
        os.makedirs(target)
        n = stage(a.manifest, target)
        what = "{} file(s)".format(n)
        cmd = [runfile(a.trivy), "config", "--skip-check-update"] + flags + a.extra + [target]

    rc, out = run_trivy(cmd, trivy_env(tmp))
    logs = log_lines(out)
    if rc != 0 or not os.path.exists(out_json):
        print("trivy {}: Trivy failed (exit {}):".format(label, rc), file=sys.stderr)
        for line in log_lines(out, ("ERROR", "FATAL")) or out.splitlines()[-20:]:
            print("  " + line, file=sys.stderr)
        if "Unable to initialize the Java DB" in out:
            print("The image has Java archives, which Trivy can only scan with the Java DB: set "
                  "`java_db = \"@rules_trivy//:java_db\"` (the pinned trivy-java-db, a ~1 GB "
                  "download, fetched once).", file=sys.stderr)
        return 2
    with open(out_json) as f:
        report = json.load(f)
    outputs = os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR")
    if outputs:
        shutil.copyfile(out_json, os.path.join(outputs, "trivy.json"))

    if kind == "config" and not report.get("Results"):
        print("trivy {}: Trivy recognised no configuration in srcs ({}): nothing was checked. "
              "It reads Kubernetes manifests, Helm charts, Terraform, Dockerfiles, CloudFormation, "
              "Azure ARM and Ansible by file name and content.".format(label, what), file=sys.stderr)
        return 2

    notes = [l for l in logs if "Failed to load module" in l]
    for l in notes:
        print("  NOTE: " + l)
    if notes:
        print("  NOTE: remote Terraform modules are never downloaded in a test; vendor them "
              "(a local `source`) to have them checked.")

    all_f = findings(report, kind)
    failing = [f for f in all_f if sev_rank(f["severity"]) >= sev_rank(threshold)]
    below = [f for f in all_f if sev_rank(f["severity"]) < sev_rank(threshold)]
    failing.sort(key=lambda f: (-sev_rank(f["severity"]), f["id"], f["what"]))
    sup = suppressed(report)

    if a.junit:
        write_junit(a.junit, label, failing, threshold)

    if sup:
        print("  ignored by {}:".format(shown))
        for fid, statement, _ in sorted(set(sup)):
            print("    {}  {}".format(fid, statement))
    if a.ignore and kind == "config":
        n = len(sections.get("misconfigurations", []))
        print("  ignore file {}: {} entr{} applied".format(shown, n, "y" if n == 1 else "ies"))
    if a.ignore and kind == "image":
        used = {fid for fid, _, _ in sup}
        for key, entries in sections.items():
            if key != "vulnerabilities":
                continue
            for e in entries:
                if e["id"] not in used:
                    print("  note: ignore entry {} ({}) matched nothing".format(e["id"], key))
    if below:
        counts = {}
        for f in below:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        print("  below {} (not failing): {}".format(threshold, ", ".join(
            "{} {}".format(counts[s], s) for s in reversed(SEVERITIES) if s in counts)))

    if not failing:
        print("PASS: no findings at or above {} in {}".format(threshold, what))
        return 0
    print("trivy {}: {} finding(s) at or above {} in {}:".format(label, len(failing), threshold, what),
          file=sys.stderr)
    for f in failing:
        print("  {:8}  {:16}  {}  {}".format(f["severity"], f["id"], f["what"], f["title"][:80]), file=sys.stderr)
    print("Fix them, or accept one in the ignore file (`ignore`) with a statement and an expired_at.",
          file=sys.stderr)
    return 1


# ---- licence scan --------------------------------------------------------------------

# Trivy's licence categories (Google's licence classification), most to least
# restrictive. OR in an expression takes its least restrictive operand's
# category, AND its most restrictive; WITH, and names Trivy doesn't know,
# are "unknown".
CATEGORIES = ["forbidden", "restricted", "reciprocal", "notice", "permissive", "unencumbered", "unknown"]

# A package Trivy found no licence for (SPDX's name for "none found").
NOASSERTION = "NOASSERTION"

_JAVA_ARCHIVE = re.compile(r"\.(jar|war|ear|par)$")


class PolicyError(Exception):
    pass


def load_allowlist(path, shown):
    """-> (names, categories). One licence per line, or `category: <name>`;
    `#` starts a comment."""
    names, cats, problems = [], [], []
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = re.match(r"^category\s*:\s*(\S+)$", line)
            if m:
                if m.group(1) not in CATEGORIES:
                    problems.append("line {}: unknown category {!r} (Trivy's: {})".format(
                        n, m.group(1), ", ".join(CATEGORIES)))
                cats.append(m.group(1))
            elif line.startswith("category"):
                problems.append("line {}: expected `category: <name>`, got {!r}".format(n, line))
            else:
                names.append(line)
    if problems:
        raise PolicyError("allowlist {}:\n{}".format(shown, "\n".join("  " + p for p in problems)))
    return names, cats


def _spdx_tokens(text):
    return [t for t in re.split(r"(\(|\)|\s+)", text) if t and not t.isspace()]


def _spdx_parse(tokens):
    """An SPDX licence expression -> ("or"|"and", [nodes]) | ("id", name), or
    None if it isn't one (then the whole text is one name)."""
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def take():
        pos[0] += 1
        return tokens[pos[0] - 1]

    def expr(op="OR"):
        sub = (lambda: expr("AND")) if op == "OR" else atom
        nodes = [sub()]
        while peek() == op:
            take()
            nodes.append(sub())
        return nodes[0] if len(nodes) == 1 else (op.lower(), nodes)

    def atom():
        t = peek()
        if t == "(":
            take()
            node = expr()
            if take() != ")":
                raise ValueError
            return node
        if t is None or t in ("AND", "OR", "WITH", ")"):
            raise ValueError
        name = take()
        if peek() == "WITH":
            take()
            exc = take() if peek() not in (None, "AND", "OR", "WITH", "(", ")") else None
            if exc is None:
                raise ValueError
            name += " WITH " + exc
        return ("id", name)

    try:
        node = expr()
        if pos[0] != len(tokens):
            return None
        return node
    except (ValueError, IndexError):
        return None


def names_allow(name, allowed):
    """Whether `allow` alone admits licence `name`: listed itself, or an SPDX
    expression whose every AND operand / some OR operand is listed."""
    if name.lower() in allowed:
        return True
    node = _spdx_parse(_spdx_tokens(name))

    def ok(n):
        if n[0] == "id":
            return n[1].lower() in allowed
        return any(map(ok, n[1])) if n[0] == "or" else all(map(ok, n[1]))
    return node is not None and node[0] != "id" and ok(node)


def license_findings(report):
    """-> [{license, category, pkg, version, path}] for every package licence
    (NOASSERTION where a package has none) and licence file in the report."""
    cats, by_name = {}, {}
    for res in report.get("Results") or []:
        if res.get("Class") == "license":
            for l in res.get("Licenses") or []:
                cats[(l.get("PkgName") or "", l.get("Name") or "")] = l.get("Category") or "unknown"
                by_name.setdefault(l.get("Name") or "", l.get("Category") or "unknown")
    out = []
    for res in report.get("Results") or []:
        cls, target = res.get("Class"), res.get("Target", "")
        for p in res.get("Packages") or []:
            path = p.get("FilePath") or (target if cls == "lang-pkgs" else "")
            base = {"pkg": p.get("Name", "?"), "version": p.get("Version", ""), "path": path}
            lics = [l for l in p.get("Licenses") or [] if l]
            if not lics:
                out.append(dict(base, license=NOASSERTION, category="unknown"))
            for l in lics:
                out.append(dict(base, license=l, category=cats.get((base["pkg"], l), by_name.get(l, "unknown"))))
        if cls == "license-file":
            for l in res.get("Licenses") or []:
                out.append({"pkg": "", "version": "", "path": l.get("FilePath") or target,
                            "license": l.get("Name") or "?", "category": l.get("Category") or "unknown"})
    return out


def finding_text(f):
    who = "{} {}".format(f["pkg"], f["version"]).strip() if f["pkg"] else "licence file"
    return who + ("  ({})".format(f["path"]) if f["path"] else "")


def ignore_match(e, f):
    if e["id"].lower() != f["license"].lower():
        return False
    if "packages" in e and not any(x in (f["pkg"], "{}@{}".format(f["pkg"], f["version"])) for x in e["packages"]):
        return False
    if "paths" in e and not any(fnmatch.fnmatchcase(f["path"], x) for x in e["paths"]):
        return False
    return True


def _layers(image):
    """Yield an open tarfile per layer of `image` (a staged OCI layout with
    one manifest, or an image tarball), in order."""
    if os.path.isdir(image):
        def blob(d):
            return os.path.join(image, "blobs", *d.split(":", 1))
        with open(os.path.join(image, "index.json")) as f:
            desc = json.load(f)["manifests"][0]
        with open(blob(desc["digest"])) as f:
            layers = [l["digest"] for l in json.load(f).get("layers") or []]
        for d in layers:
            with tarfile.open(blob(d), "r|*") as t:
                yield t
        return
    with tarfile.open(image) as outer:
        names = outer.getnames()
        if "manifest.json" in names:
            layers = json.load(outer.extractfile("manifest.json"))[0].get("Layers") or []
        else:  # an OCI layout as a tarball
            idx = json.load(outer.extractfile("index.json"))
            man = json.load(outer.extractfile("blobs/" + "/".join(idx["manifests"][0]["digest"].split(":", 1))))
            layers = ["blobs/" + "/".join(l["digest"].split(":", 1)) for l in man.get("layers") or []]
        for name in layers:
            with tarfile.open(fileobj=outer.extractfile(name), mode="r|*") as t:
                yield t


def java_archives(image):
    """The Java archives in the image's final file system (whiteouts applied)."""
    files = set()
    for t in _layers(image):
        added, gone, opaque = set(), set(), set()
        for m in t:
            path = re.sub(r"^(\./)+", "", m.name).strip("/")
            d, base = os.path.split(path)
            if base == ".wh..wh..opq":
                opaque.add(d)
            elif base.startswith(".wh."):
                gone.add(os.path.join(d, base[4:]))
            elif m.isfile() and _JAVA_ARCHIVE.search(base):
                added.add(path)
        # A layer's whiteouts hide what the layers below it have.
        files = {x for x in files
                 if not any(x == g or x.startswith(g + "/") for g in gone)
                 and not any(x.startswith(d + "/") or not d for d in opaque)}
        files |= added
    return sorted(files)


def license_scan(a):
    label = a.label
    try:
        infos = check_inputs(a, "license")
    except MissingInput as e:
        print("trivy {}: {} (not in the test's runfiles)".format(label, e), file=sys.stderr)
        return 2
    tmp = tempfile.mkdtemp(prefix="trivy.", dir=os.environ.get("TEST_TMPDIR"))
    print("trivy {}: Trivy {}, licence scan".format(label, a.version))

    names, cats = list(a.allow), list(a.allow_category)
    if a.allowlist:
        try:
            n2, c2 = load_allowlist(runfile(a.allowlist), workspace_path(a.allowlist))
        except PolicyError as e:
            print("trivy {}: {}".format(label, e), file=sys.stderr)
            return 2
        names += n2
        cats += c2
    allowed = {n.lower() for n in names}
    print("  allowed: categories {}{}".format(", ".join(sorted(set(cats), key=CATEGORIES.index)) or "(none)",
                                             "; licences " + ", ".join(names) if names else ""))

    entries, shown = [], ""
    if a.ignore:
        shown = workspace_path(a.ignore)
        try:
            sections, expired = load_ignore(runfile(a.ignore), shown, utc_today())
        except IgnoreError as e:
            print("trivy {}: ignore file {} is malformed:\n{}".format(label, shown, e), file=sys.stderr)
            print("A licence entry needs id (the licence), statement (the reason) and expired_at "
                  "(YYYY-MM-DD); packages and paths narrow it, e.g.\n"
                  "  licenses:\n"
                  "    - id: GPL-3.0-only\n"
                  "      packages: [gpl-thing]\n"
                  "      statement: build-time tool only, never shipped\n"
                  "      expired_at: 2027-03-31", file=sys.stderr)
            return 2
        expired = [(w, e) for w, e in expired if w.startswith("licenses[")]
        if expired:
            print("trivy {}: {}".format(label, report_expired(shown, expired)), file=sys.stderr)
            return 1
        entries = sections.get("licenses", [])

    for info in infos:
        print("  {:8} {}".format(info["kind"], describe(info)))
    cache = os.path.join(tmp, "cache")
    os.makedirs(cache)
    setup_cache(cache, infos)
    out_json = os.path.join(tmp, "trivy.json")
    flags = common_flags(cache, tmp, "", out_json) + ["--list-all-pkgs"]
    if a.license_full:
        flags.append("--license-full")
    java = any(i["kind"] == "java_db" for i in infos)

    if a.image:
        image = os.path.realpath(runfile(a.image))
        what = workspace_path(a.image)
        if os.path.isdir(image):
            if not os.path.exists(os.path.join(image, "index.json")):
                print("trivy {}: image {} is a directory without index.json: not an OCI image layout "
                      "(give an oci_image, or an image tarball)".format(label, what), file=sys.stderr)
                return 2
            try:
                image = stage_layout(image, os.path.join(tmp, "image"), a.platform)
            except LayoutError as e:
                print("trivy {}: image {}: {}".format(label, what, e), file=sys.stderr)
                return 2
        elif a.platform:
            print("trivy {}: platform applies to an OCI layout (oci_image_index); {} is a tarball".format(
                label, what), file=sys.stderr)
            return 2
        if not java:
            try:
                jars = java_archives(image)
            except (tarfile.TarError, OSError, KeyError, IndexError, ValueError) as e:
                print("trivy {}: image {}: cannot list its layers for Java archives: {}".format(label, what, e),
                      file=sys.stderr)
                return 2
            if jars:
                print("trivy {}: image {} has Java archives ({}{}), whose licences Trivy reads only with "
                      "the Java DB: set `java_db = \"@rules_trivy//:java_db\"` (the pinned trivy-java-db, "
                      "a ~1 GB download, fetched once).".format(
                          label, what, ", ".join(jars[:3]), ", ..." if len(jars) > 3 else ""), file=sys.stderr)
                return 2
        # Trivy analyses Java archives only for the vulnerability scanner;
        # its findings are dropped here.
        scanners = "vuln,license" if java else "license"
        cmd = [runfile(a.trivy), "image", "--input", image, "--scanners", scanners,
               "--skip-db-update", "--skip-java-db-update", "--offline-scan"] + flags + a.extra
    else:
        target = os.path.join(tmp, "scan")
        os.makedirs(target)
        n = stage(a.manifest, target)
        what = "{} file(s)".format(n)
        cmd = [runfile(a.trivy), "fs", "--scanners", "license", "--skip-db-update", "--offline-scan"] + \
            flags + a.extra + [target]

    env = trivy_env(tmp)
    rc, out = run_trivy(cmd, env)
    if rc != 0 or not os.path.exists(out_json):
        print("trivy {}: Trivy failed (exit {}):".format(label, rc), file=sys.stderr)
        for line in log_lines(out, ("ERROR", "FATAL")) or out.splitlines()[-20:]:
            print("  " + line, file=sys.stderr)
        return 2
    with open(out_json) as f:
        report = json.load(f)
    # The reports name what was scanned by the test's label, not by the
    # sandbox path Trivy saw (the SBOMs' root package).
    report["ArtifactName"] = label
    with open(out_json, "w") as f:
        json.dump(report, f, indent=2)
    outputs = os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR")
    if outputs:
        shutil.copyfile(out_json, os.path.join(outputs, "trivy.json"))
        for fmt in a.formats:
            dest = os.path.join(outputs, "licenses." + {"spdx-json": "spdx.json", "cyclonedx": "cdx.json"}[fmt])
            # convert has no version-check / telemetry flags; trivy_env's
            # dead proxy keeps it offline.
            crc, cout = run_trivy([runfile(a.trivy), "convert", "--format", fmt, "--output", dest,
                                   "--config", "", "--ignorefile", "", "--cache-dir", cache, out_json], env)
            if crc != 0:
                print("trivy {}: Trivy could not write the {} report (exit {}):".format(label, fmt, crc),
                      file=sys.stderr)
                for line in log_lines(cout, ("ERROR", "FATAL")) or cout.splitlines()[-20:]:
                    print("  " + line, file=sys.stderr)
                return 2

    found = license_findings(report)
    if not found:
        print("trivy {}: Trivy found no packages{} in {}: nothing was checked. It reads OS package "
              "databases and language lockfiles (package-lock.json, composer.lock, pom.xml, ...){}.".format(
                  label, " or licence files" if a.license_full else "", what,
                  "" if a.license_full else ", and with license_full = True, licence texts"), file=sys.stderr)
        return 2

    failing, ignored, used = [], [], set()
    for f in found:
        if f["category"] in cats or names_allow(f["license"], allowed):
            continue
        hit = next((i for i, e in enumerate(entries) if ignore_match(e, f)), None)
        if hit is None:
            failing.append(f)
        else:
            used.add(hit)
            ignored.append((f, entries[hit]))
    failing.sort(key=lambda f: (CATEGORIES.index(f["category"]) if f["category"] in CATEGORIES else 99,
                                f["license"], f["pkg"], f["path"]))

    if a.junit:
        write_junit(a.junit, label, [{
            "id": f["license"], "what": finding_text(f), "severity": f["category"],
            "title": "", "target": f["path"]} for f in failing], "", passed="every licence allowed")

    counts = {}
    for f in found:
        counts[f["category"]] = counts.get(f["category"], 0) + 1
    npkg = len({(f["pkg"], f["version"], f["path"]) for f in found if f["pkg"]})
    nfiles = len([f for f in found if not f["pkg"]])
    print("  {} package(s){}; licences by category: {}".format(
        npkg, ", {} licence file(s)".format(nfiles) if nfiles else "",
        ", ".join("{} {}".format(counts[c], c) for c in CATEGORIES if c in counts)))
    if ignored:
        print("  ignored by {}:".format(shown))
        for f, e in ignored:
            print("    {:24} {}  -- {}".format(f["license"], finding_text(f), e["statement"]))
    for i, e in enumerate(entries):
        if i not in used:
            print("  note: ignore entry licenses[{}] ({}) matched nothing".format(i, e["id"]))

    if not failing:
        print("PASS: every licence in {} is allowed".format(what))
        return 0
    print("trivy {}: {} licence finding(s) not allowed in {}:".format(label, len(failing), what), file=sys.stderr)
    for f in failing:
        print("  {:12}  {:24}  {}".format(f["category"], f["license"], finding_text(f)), file=sys.stderr)
    if any(f["license"] == NOASSERTION for f in failing):
        print("NOASSERTION: Trivy found no licence for the package (e.g. Go modules without the module "
              "cache, or a lockfile that doesn't record them).", file=sys.stderr)
    print("Allow them (`allow`, `allow_categories` or the `allowlist` file), or accept one in the ignore "
          "file under `licenses:` with a statement and an expired_at.", file=sys.stderr)
    return 1


def check_ignore_file(ignore):
    """-> (exit code, message)."""
    shown = workspace_path(ignore)
    try:
        sections, expired = load_ignore(runfile(ignore), shown, utc_today())
    except IgnoreError as e:
        return 2, "ignore file {} is malformed:\n{}".format(shown, e)
    if expired:
        return 1, report_expired(shown, expired)
    n = sum(len(v) for v in sections.values())
    return 0, "ignore file {}: {} entr{}, none expired".format(shown, n, "y" if n == 1 else "ies")


def check_ignore(a):
    rc, msg = check_ignore_file(a.ignore)
    print(msg, file=sys.stderr if rc else sys.stdout)
    return rc


def ignore_test(a):
    rc, msg = check_ignore_file(a.ignore)
    print(msg)
    if not a.expect_error:
        if rc:
            print("FAIL {}: the ignore file was expected to pass the check".format(a.label), file=sys.stderr)
            return 1
        print("PASS")
        return 0
    if not rc:
        print("FAIL {}: expected the check to fail matching {!r}, but it passed".format(a.label, a.expect_error),
              file=sys.stderr)
        return 1
    if not re.search(a.expect_error, msg):
        print("FAIL {}: the check failed, but not matching {!r}".format(a.label, a.expect_error), file=sys.stderr)
        return 1
    print("PASS: failed as expected (matches {!r})".format(a.expect_error))
    return 0


def db_info(a):
    for i in a.data:
        info = data_info(i)
        print("{:8} {}".format(info["kind"], describe(info)))
        print("         digest {}".format(info["digest"]))
    return 0


# ---- latest: resolve tags to digests (network) ------------------------------------


def _registry_get(repository, ref, accept):
    host, path = repository.split("/", 1)
    with urllib.request.urlopen("https://{h}/token?scope=repository:{p}:pull&service={h}".format(h=host, p=path),
                                timeout=60) as r:
        tok = json.load(r)
    req = urllib.request.Request("https://{}/v2/{}/manifests/{}".format(host, path, ref), headers={
        "Accept": accept,
        "Authorization": "Bearer " + (tok.get("token") or tok.get("access_token")),
    })
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.headers.get("Docker-Content-Digest"), json.load(r)


def pins_from_versions_bzl(path):
    text = open(path).read()
    pins = {}
    for kind in ("db", "java_db", "checks"):
        m = re.search(r'    "' + kind + r'": \{(.*?)\n    \}', text, re.S)
        if m:
            pins[kind] = dict(re.findall(r'"(repository|tag|digest|created)": "([^"]*)"', m.group(1)))
    return pins


def latest(a):
    pins = json.loads(a.pins) if a.pins else pins_from_versions_bzl(a.write)
    rows = []
    for kind in a.kinds or ["db", "java_db", "checks"]:
        p = pins[kind]
        digest, manifest = _registry_get(p["repository"], p["tag"],
                                         "application/vnd.oci.image.manifest.v1+json")
        created = (manifest.get("annotations") or {}).get("org.opencontainers.image.created", "")
        rows.append((kind, p, digest, created))
    if a.write:
        text = open(a.write).read()
        for kind, p, digest, created in rows:
            block = re.compile(r'(    "' + kind + r'": \{\n.*?"digest": ")[^"]*(",\n\s*"created": ")[^"]*(")', re.S)
            text, n = block.subn(lambda m: m.group(1) + digest + m.group(2) + created + m.group(3), text)
            if n != 1:
                print("latest: no DATA[{!r}] entry in {}".format(kind, a.write), file=sys.stderr)
                return 2
        with open(a.write, "w") as f:
            f.write(text)
        for kind, p, digest, created in rows:
            print("pinned {} {}@{} (created {})".format(kind, p["repository"], digest, created))
        return 0
    print("# Current upstream digests; to pin them, put these in your MODULE.bazel:")
    print('trivy = use_extension("@rules_trivy//:extensions.bzl", "trivy")')
    for kind, p, digest, created in rows:
        cur = " (rules_trivy pins this one)" if digest == p["digest"] else ""
        print('trivy.{}(digest = "{}")  # {}:{}, created {}{}'.format(kind, digest, p["repository"], p["tag"],
                                                                     created, cur))
    return 0


# ---- main ---------------------------------------------------------------------------


def main(argv):
    sys.stdout.reconfigure(line_buffering=True)
    p = argparse.ArgumentParser(prog="trivy.py", fromfile_prefix_chars=None)
    p.add_argument("mode", choices=["image", "config", "license", "check-ignore", "ignore-test", "db-info", "latest"])
    p.add_argument("--runfiles", action="store_true")
    p.add_argument("--label", default="")
    p.add_argument("--trivy")
    p.add_argument("--version", default="")
    p.add_argument("--image")
    p.add_argument("--platform", default="")
    p.add_argument("--manifest")
    p.add_argument("--data", action="append", default=[])
    p.add_argument("--severity", default="HIGH", choices=SEVERITIES)
    p.add_argument("--ignore")
    p.add_argument("--ignore-unfixed", action="store_true")
    p.add_argument("--junit")
    p.add_argument("--pins")
    p.add_argument("--kind", dest="kinds", action="append")
    p.add_argument("--write")
    p.add_argument("--expect-error", default="")
    p.add_argument("--allow", action="append", default=[])
    p.add_argument("--allow-category", action="append", default=[], choices=CATEGORIES)
    p.add_argument("--allowlist")
    p.add_argument("--license-full", action="store_true")
    p.add_argument("--format", dest="formats", action="append", default=[], choices=["spdx-json", "cyclonedx"])
    p.add_argument("extra", nargs="*")
    a = p.parse_args(argv)
    try:
        if a.mode in ("image", "config"):
            return scan(a, a.mode)
        if a.mode == "license":
            return license_scan(a)
        if a.mode == "check-ignore":
            return check_ignore(a)
        if a.mode == "ignore-test":
            return ignore_test(a)
        if a.mode == "db-info":
            return db_info(a)
        return latest(a)
    except MissingInput as e:
        print("rules_trivy {}: {} (not in the runfiles)".format(a.label or a.mode, e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
