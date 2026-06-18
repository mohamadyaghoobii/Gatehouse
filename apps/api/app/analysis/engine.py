from __future__ import annotations

from collections import Counter

import app.analysis.rules  # noqa: F401  (registers all rules)
from app.analysis.categories import ALL_CATEGORIES
from app.analysis.context import AnalysisContext
from app.analysis.registry import catalog, rules_for
from app.analysis.scoring import compute_score
from app.parsers import parse_pipeline
from app.schemas import (
    AnalyzeResponse,
    Finding,
    PermissionEntry,
    PipelineJob,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def rule_catalog() -> list[dict]:
    return catalog()


def analyze_pipeline(
    content: str,
    platform: str = "auto",
    project_name: str | None = None,
    repository: str | None = None,
    environment: str | None = None,
    strict_mode: bool = False,
    enabled_categories: list[str] | None = None,
) -> AnalyzeResponse:
    pipeline = parse_pipeline(content, platform)
    ctx = AnalysisContext(
        pipeline=pipeline,
        strict_mode=strict_mode,
        repository=repository,
        environment=environment,
    )

    allowed = {item.strip().lower() for item in enabled_categories} if enabled_categories else None
    findings: list[Finding] = []
    checks_run = 0
    for meta in rules_for(pipeline.provider):
        if allowed is not None and meta.category.lower() not in allowed:
            continue
        checks_run += 1
        findings.extend(meta.func(ctx))

    findings = _dedupe(findings)
    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), item.category, item.id))

    breakdown = compute_score(findings, checks_run)
    severity_counts = Counter(item.severity for item in findings)
    category_counts = Counter(item.category for item in findings)

    jobs = [
        PipelineJob(
            name=job.name,
            stage=job.stage,
            runner=job.runner,
            steps=len(job.steps),
            uses_secrets=job.uses_secrets,
            line=job.line,
        )
        for job in pipeline.jobs
    ]

    permissions_summary = [
        PermissionEntry(scope=scope, access=access) for scope, access in pipeline.permission_summary.items()
    ]
    secret_exposure = sum(1 for item in findings if item.category == "Secrets")

    return AnalyzeResponse(
        score=breakdown.score,
        grade=breakdown.grade,
        score_breakdown=breakdown,
        summary=_summary(pipeline.provider, jobs, findings, breakdown.score),
        provider=pipeline.provider,
        platform=pipeline.provider,
        pipeline_name=pipeline.name,
        triggers=pipeline.triggers,
        stages=pipeline.stages,
        jobs=jobs,
        permissions_summary=permissions_summary,
        secret_exposure_count=secret_exposure,
        findings=findings,
        severity_counts={key: severity_counts.get(key, 0) for key in SEVERITY_ORDER},
        category_counts={category: category_counts.get(category, 0) for category in ALL_CATEGORIES if category_counts.get(category)},
        recommended_next_steps=_next_steps(findings),
        metadata={
            "project_name": project_name,
            "repository": repository,
            "environment": environment,
            "jobs_analyzed": len(pipeline.jobs),
            "stages_analyzed": len(pipeline.stages),
            "lines_analyzed": len(pipeline.lines),
            "checks_run": checks_run,
            "strict_mode": strict_mode,
        },
    )


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.id, finding.job, finding.line, finding.location)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _summary(provider: str, jobs: list[PipelineJob], findings: list[Finding], score: int) -> str:
    label = provider.replace("_", " ")
    if not findings:
        return f"No risks were detected across {len(jobs)} {label} job(s). Pipeline scored {score}/100."
    high = sum(1 for item in findings if item.severity in {"critical", "high"})
    return (
        f"Reviewed {len(jobs)} {label} job(s) and found {len(findings)} issue(s), "
        f"including {high} critical/high. Pipeline scored {score}/100."
    )


def _next_steps(findings: list[Finding]) -> list[str]:
    if not findings:
        return [
            "Keep actions and dependencies pinned to immutable references.",
            "Maintain protected environments and approval gates for deployments.",
            "Run Gatehouse on every pull request that touches pipeline files.",
        ]
    by_category = Counter(item.category for item in findings)
    priorities = {
        "Secrets": "Remove hardcoded secrets and rotate anything that may have been committed.",
        "Permissions": "Apply least-privilege token permissions and scope write access to single jobs.",
        "Supply Chain": "Pin third-party actions to commit SHAs and verify downloaded scripts.",
        "Trigger Safety": "Harden risky triggers such as pull_request_target and unscoped branches.",
        "Deployment Safety": "Add approval gates and validation before changes reach an environment.",
        "Runtime Scripts": "Replace unsafe shell patterns with hardened, least-privilege equivalents.",
        "Artifacts & Cache": "Scope artifact and cache paths and shorten retention.",
        "Reliability": "Add timeouts, concurrency control, and a test gate before deploys.",
    }
    ordered = sorted(by_category, key=lambda category: -by_category[category])
    steps = [priorities[category] for category in ordered if category in priorities]
    return steps[:5]
