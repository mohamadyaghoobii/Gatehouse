from __future__ import annotations

import re
from typing import Iterable

from app.analysis.categories import ARTIFACTS_CACHE
from app.analysis.context import AnalysisContext
from app.analysis.registry import rule
from app.schemas import Finding

_BROAD_PATH_RE = re.compile(r"path\s*:\s*['\"]?(\.|\./|\*|\$\{?\{?\s*github\.workspace)", re.I)
_RETENTION_RE = re.compile(r"retention-days\s*:\s*(\d+)", re.I)


@rule(
    id="ART-BROAD-PATH",
    title="Artifact upload path is too broad",
    category=ARTIFACTS_CACHE,
    severity="low",
    description="An artifact path covers the workspace root or a wildcard, risking accidental exposure.",
    providers=["github_actions"],
)
def broad_artifact_path(ctx: AnalysisContext) -> Iterable[Finding]:
    if "upload-artifact" not in ctx.text:
        return []
    match = _BROAD_PATH_RE.search(ctx.text)
    if not match:
        return []
    return [
        ctx.finding(
            id="ART-BROAD-PATH",
            title="Artifact upload path is too broad",
            severity="low",
            category=ARTIFACTS_CACHE,
            field_path="with.path",
            location=match.group(0).strip(),
            line=ctx.find_line(match.group(0).strip()),
            description="An artifact upload targets the workspace root or a wildcard path.",
            impact="Broad paths can sweep up secret files, caches, or source that should not be published.",
            remediation="Upload only the specific build output directory and exclude sensitive files.",
            safer_example="with:\n  name: dist\n  path: dist/",
            confidence=0.6,
        )
    ]


@rule(
    id="ART-LONG-RETENTION",
    title="Artifact retention is unusually long",
    category=ARTIFACTS_CACHE,
    severity="info",
    description="Artifacts are retained for an extended period, increasing exposure if they hold sensitive data.",
    providers=["github_actions"],
)
def long_retention(ctx: AnalysisContext) -> Iterable[Finding]:
    match = _RETENTION_RE.search(ctx.text)
    if not match or int(match.group(1)) <= 30:
        return []
    days = int(match.group(1))
    return [
        ctx.finding(
            id="ART-LONG-RETENTION",
            title=f"Artifacts retained for {days} days",
            severity="info",
            category=ARTIFACTS_CACHE,
            field_path="with.retention-days",
            location=match.group(0).strip(),
            line=ctx.find_line(match.group(0).strip()),
            description="Artifact retention is set well above the typical window.",
            impact="Long retention keeps build output downloadable for longer, widening the exposure window.",
            remediation="Keep retention as short as the workflow needs, typically a few days for transient build output.",
            safer_example="with:\n  retention-days: 5",
            confidence=0.5,
        )
    ]


@rule(
    id="ART-BROAD-CACHE",
    title="Cache path is overly broad",
    category=ARTIFACTS_CACHE,
    severity="low",
    description="A cache definition covers the workspace root or untrusted paths.",
)
def broad_cache(ctx: AnalysisContext) -> Iterable[Finding]:
    text = ctx.text
    if "cache" not in text.lower():
        return []
    for job in ctx.pipeline.jobs:
        raw = job.raw if isinstance(job.raw, dict) else {}
        cache = raw.get("cache")
        paths = []
        if isinstance(cache, dict):
            value = cache.get("paths")
            paths = value if isinstance(value, list) else [value] if value else []
        if any(str(path).strip() in {".", "./", "/", "*"} for path in paths):
            return [
                ctx.finding(
                    id="ART-BROAD-CACHE",
                    title=f"Cache path in '{job.name}' is overly broad",
                    severity="low",
                    category=ARTIFACTS_CACHE,
                    job=job.name,
                    field_path="cache.paths",
                    location=job.name,
                    line=job.line,
                    description="A cache definition includes the workspace root or a wildcard path.",
                    impact="Broad caches can persist and replay tampered files across pipeline runs (cache poisoning).",
                    remediation="Scope caches to dependency directories with a key derived from the lockfile.",
                    safer_example="cache:\n  key: $CI_COMMIT_REF_SLUG\n  paths:\n    - .npm/",
                    confidence=0.58,
                )
            ]
    return []
