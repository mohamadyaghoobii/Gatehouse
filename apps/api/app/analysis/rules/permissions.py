from __future__ import annotations

from typing import Iterable

from app.analysis.categories import PERMISSIONS
from app.analysis.context import AnalysisContext
from app.analysis.registry import rule
from app.schemas import Finding

SENSITIVE_SCOPES = {"contents", "packages", "deployments", "actions", "security-events", "pull-requests"}

_GH_PERMS_DOC = "https://docs.github.com/actions/security-guides/automatic-token-authentication"


@rule(
    id="GH-PERM-WRITE-ALL",
    title="Workflow grants write-all permissions",
    category=PERMISSIONS,
    severity="high",
    description="The workflow token is granted write access to every scope via write-all.",
    providers=["github_actions"],
)
def github_write_all(ctx: AnalysisContext) -> Iterable[Finding]:
    if ctx.pipeline.permissions != "write-all":
        return []
    return [
        ctx.finding(
            id="GH-PERM-WRITE-ALL",
            title="Workflow grants write-all permissions",
            severity="high",
            category=PERMISSIONS,
            field_path="permissions",
            location="permissions: write-all",
            line=ctx.find_line("write-all"),
            description="The workflow grants the GITHUB_TOKEN write access to every scope.",
            impact="A single compromised step can push code, publish packages, edit releases, or alter other workflows.",
            remediation="Set read-only defaults at the top level and grant write only to the jobs that need it.",
            safer_example="permissions:\n  contents: read",
            confidence=0.95,
            references=[_GH_PERMS_DOC],
        )
    ]


@rule(
    id="GH-PERM-MISSING",
    title="Workflow does not declare token permissions",
    category=PERMISSIONS,
    severity="low",
    description="No explicit permissions block is set, so the token inherits repository defaults.",
    providers=["github_actions"],
)
def github_missing_permissions(ctx: AnalysisContext) -> Iterable[Finding]:
    if ctx.pipeline.permissions is not None:
        return []
    job_level = any(job.permissions is not None for job in ctx.pipeline.jobs)
    if job_level:
        return []
    severity = "medium" if ctx.strict_mode else "low"
    return [
        ctx.finding(
            id="GH-PERM-MISSING",
            title="Workflow does not declare token permissions",
            severity=severity,
            category=PERMISSIONS,
            field_path="permissions",
            location="workflow root",
            description="The workflow relies on the repository default token permissions instead of declaring its own.",
            impact="Default permissions vary by repository and organization, making the real blast radius hard to reason about.",
            remediation="Declare explicit read-only defaults at the workflow root and elevate per job as needed.",
            safer_example="permissions:\n  contents: read",
            confidence=0.7,
            references=[_GH_PERMS_DOC],
        )
    ]


@rule(
    id="GH-PERM-ID-TOKEN",
    title="id-token write is granted without a clear OIDC consumer",
    category=PERMISSIONS,
    severity="medium",
    description="id-token: write is enabled but no OIDC-based action appears to use it.",
    providers=["github_actions"],
)
def github_id_token(ctx: AnalysisContext) -> Iterable[Finding]:
    summary = ctx.pipeline.permission_summary
    grants_id_token = summary.get("id-token") == "write" or summary.get("*") == "write"
    if not grants_id_token:
        return []
    text = ctx.text.lower()
    if any(hint in text for hint in ("aws-actions/configure-aws-credentials", "azure/login", "google-github-actions", "oidc")):
        return []
    return [
        ctx.finding(
            id="GH-PERM-ID-TOKEN",
            title="id-token write is granted without a clear OIDC consumer",
            severity="medium",
            category=PERMISSIONS,
            field_path="permissions.id-token",
            location="permissions.id-token: write",
            line=ctx.find_line("id-token"),
            description="The workflow can mint OIDC tokens but no cloud-login action consumes them.",
            impact="An unused id-token grant widens the token surface and can be abused if a step is compromised.",
            remediation="Remove id-token: write unless a job exchanges the token with a cloud provider via OIDC.",
            safer_example="permissions:\n  contents: read\n  id-token: write  # only on the job that calls configure-aws-credentials",
            confidence=0.68,
            references=[_GH_PERMS_DOC],
        )
    ]


@rule(
    id="GH-PERM-BROAD-WRITE",
    title="Sensitive write permission set at workflow scope",
    category=PERMISSIONS,
    severity="medium",
    description="A sensitive scope is granted write at the workflow level instead of per job.",
    providers=["github_actions"],
)
def github_broad_write(ctx: AnalysisContext) -> Iterable[Finding]:
    permissions = ctx.pipeline.permissions
    if not isinstance(permissions, dict):
        return []
    findings: list[Finding] = []
    for scope, access in permissions.items():
        scope = str(scope)
        if str(access).lower() == "write" and scope in SENSITIVE_SCOPES:
            findings.append(
                ctx.finding(
                    id="GH-PERM-BROAD-WRITE",
                    title=f"{scope}: write is granted to the whole workflow",
                    severity="medium",
                    category=PERMISSIONS,
                    field_path=f"permissions.{scope}",
                    location=f"permissions.{scope}: write",
                    line=ctx.find_line(f"{scope}:"),
                    description=f"The sensitive scope '{scope}' is granted write access at workflow level.",
                    impact="Every job inherits the elevated scope, so any compromised step gains write access it may not need.",
                    remediation="Keep workflow defaults read-only and move the write grant into the specific job that needs it.",
                    safer_example="permissions:\n  contents: read\n\njobs:\n  release:\n    permissions:\n      contents: write",
                    confidence=0.82,
                    references=[_GH_PERMS_DOC],
                )
            )
    return findings
