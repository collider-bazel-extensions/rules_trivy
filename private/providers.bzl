"""Providers exposed by rules_trivy."""

TrivyBinaryInfo = provider(
    doc = "The Trivy toolchain binary.",
    fields = {
        "version": "string — pinned Trivy version",
        "trivy": "File — the trivy executable",
    },
)

TrivyDataInfo = provider(
    doc = "A pinned Trivy data artifact (vulnerability DB, Java DB or checks bundle).",
    fields = {
        "kind": "string — db | java_db | checks",
        "files": "list of File — the artifact's files (for Trivy's cache directory)",
        "info": "File — info.json: repository, digest, layer, created, updated_at",
    },
)
