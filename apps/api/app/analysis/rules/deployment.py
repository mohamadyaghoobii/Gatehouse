from __future__ import annotations

import re
from typing import Iterable

from app.analysis.categories import DEPLOYMENT_SAFETY
from app.analysis.context import AnalysisContext
from app.analysis.patterns import DEPLOY_COMMAND_RE, DEPLOY_NAME_RE
from app.analysis.registry import rule
from app.parsers.models import Job
from app.schemas import Finding

_KUBECTL_RE = re.compile(r"kubectl\s+apply", re.I)
_TF_APPLY_RE = re.compile(r"terraform\s+apply", re.I)
_SSH_PASS_RE = re.compile(r"sshpass|ssh\s+[^\n]*-o\s+StrictHostKeyChecking=no", re.I)


def _is_deploy_job(job: Job) -> bool:
    if DEPLOY_NAME_RE.search(job.name):
        return True
    for step in job.steps:
        if step.run and DEPLOY_COMMAND_RE.search(step.run):
            return True
    return False


@rule(
    id="DEPLOY-NO-APPROVAL",
    title="Deployment job has no approval gate",
    category=DEPLOYMENT_SAFETY,
    severity="medium",
    description="A deployment job runs without an environment, manual gate, or approval.",
)
def deploy_without_gate(ctx: AnalysisContext) -> Iterable[Finding]:
    findings: list[Finding] = []
    for job in ctx.pipeline.jobs:
        if not _is_deploy_job(job):
            continue
        if ctx.provider == "github_actions":
            gated = bool(job.environment)
        elif ctx.provider == "gitlab_ci":
            gated = job.when == "manual" or bool(job.environment)
        else:
            gated = "input" in (ctx.text if isinstance(ctx.text, str) else "")
        if gated:
            continue
        prod = bool(re.search(r"prod", job.name, re.I)) or "production" in ctx.text.lower()
        findings.append(
            ctx.finding(
                id="DEPLOY-NO-APPROVAL",
                title=f"Deployment job '{job.name}' has no approval gate",
                severity="high" if prod else "medium",
                category=DEPLOYMENT_SAFETY,
                job=job.name,
                location=job.name,
                line=job.line,
                description="A deployment-related job runs automatically without a protected environment or manual approval.",
                impact="Changes can reach the target environment without human review or branch protection.",
                remediation="Gate deployments with a protected environment, required reviewers, or a manual approval step.",
                safer_example=_gate_example(ctx.provider),
                confidence=0.72,
            )
        )
    return findings


@rule(
    id="DEPLOY-KUBECTL-NO-VALIDATION",
    title="kubectl apply runs without validation",
    category=DEPLOYMENT_SAFETY,
    severity="low",
    description="kubectl apply runs without --dry-run, diff, or server-side validation.",
)
def kubectl_no_validation(ctx: AnalysisContext) -> Iterable[Finding]:
    findings: list[Finding] = []
    for job in ctx.pipeline.jobs:
        for step in job.steps:
            body = step.run or ""
            if _KUBECTL_RE.search(body) and "dry-run" not in body and "diff" not in body:
                findings.append(
                    ctx.finding(
                        id="DEPLOY-KUBECTL-NO-VALIDATION",
                        title="kubectl apply runs without validation",
                        severity="low",
                        category=DEPLOYMENT_SAFETY,
                        job=job.name,
                        location=step.label,
                        line=step.line,
                        description="A kubectl apply step runs without a dry-run or diff to validate the change.",
                        impact="An invalid or unexpected manifest is applied directly to the cluster.",
                        remediation="Run kubectl diff or kubectl apply --dry-run=server before applying, and review the output.",
                        safer_example="kubectl diff -f k8s/\nkubectl apply -f k8s/ --dry-run=server",
                        confidence=0.6,
                    )
                )
                return findings
    return findings


@rule(
    id="DEPLOY-TERRAFORM-NO-PLAN",
    title="terraform apply runs without a reviewed plan",
    category=DEPLOYMENT_SAFETY,
    severity="medium",
    description="terraform apply runs with auto-approve or without a saved plan.",
)
def terraform_no_plan(ctx: AnalysisContext) -> Iterable[Finding]:
    for job in ctx.pipeline.jobs:
        for step in job.steps:
            body = step.run or ""
            if _TF_APPLY_RE.search(body) and ("-auto-approve" in body or "plan" not in body):
                return [
                    ctx.finding(
                        id="DEPLOY-TERRAFORM-NO-PLAN",
                        title="terraform apply runs without a reviewed plan",
                        severity="medium",
                        category=DEPLOYMENT_SAFETY,
                        job=job.name,
                        location=step.label,
                        line=step.line,
                        description="terraform apply runs with auto-approve or without a separately reviewed plan.",
                        impact="Infrastructure changes are applied without an approval checkpoint on the plan.",
                        remediation="Run terraform plan -out, require review of the plan, then apply the saved plan file.",
                        safer_example="terraform plan -out tfplan\n# review, then\nterraform apply tfplan",
                        confidence=0.7,
                    )
                ]
    return []


@rule(
    id="DEPLOY-UNSAFE-SSH",
    title="Unsafe SSH deployment pattern",
    category=DEPLOYMENT_SAFETY,
    severity="medium",
    description="Deployment uses password-based SSH or disables host key checking.",
)
def unsafe_ssh(ctx: AnalysisContext) -> Iterable[Finding]:
    match = _SSH_PASS_RE.search(ctx.text)
    if not match:
        return []
    return [
        ctx.finding(
            id="DEPLOY-UNSAFE-SSH",
            title="Unsafe SSH deployment pattern",
            severity="medium",
            category=DEPLOYMENT_SAFETY,
            location=match.group(0).strip()[:60],
            line=ctx.find_line(match.group(0).strip()[:40]),
            description="The deployment uses password-based SSH or disables strict host key checking.",
            impact="Disabled host verification or password auth makes the deploy vulnerable to interception and credential theft.",
            remediation="Use key-based auth with known hosts pinned and keep StrictHostKeyChecking enabled.",
            confidence=0.66,
        )
    ]


def _gate_example(provider: str) -> str:
    if provider == "gitlab_ci":
        return "deploy-prod:\n  stage: deploy\n  when: manual\n  environment:\n    name: production"
    if provider == "jenkins":
        return "stage('Approve') {\n  steps { input message: 'Deploy to production?' }\n}"
    return "jobs:\n  deploy:\n    environment:\n      name: production  # add required reviewers in repo settings"
