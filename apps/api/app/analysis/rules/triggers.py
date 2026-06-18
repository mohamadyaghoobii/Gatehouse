from __future__ import annotations

from typing import Iterable

from app.analysis.categories import TRIGGER_SAFETY
from app.analysis.context import AnalysisContext
from app.analysis.registry import rule
from app.schemas import Finding

_PR_TARGET_DOC = "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/"


@rule(
    id="TRIG-PR-TARGET",
    title="Workflow runs on pull_request_target",
    category=TRIGGER_SAFETY,
    severity="high",
    description="pull_request_target runs with repository secrets in the context of forked code.",
    providers=["github_actions"],
)
def pull_request_target(ctx: AnalysisContext) -> Iterable[Finding]:
    if "pull_request_target" not in ctx.pipeline.triggers:
        return []
    checks_out_pr = "github.event.pull_request.head" in ctx.text or "ref: ${{ github.head_ref" in ctx.text
    severity = "critical" if checks_out_pr else "high"
    return [
        ctx.finding(
            id="TRIG-PR-TARGET",
            title="Workflow runs on pull_request_target",
            severity=severity,
            category=TRIGGER_SAFETY,
            field_path="on.pull_request_target",
            location="on: pull_request_target",
            line=ctx.find_line("pull_request_target"),
            description="The workflow triggers on pull_request_target, which exposes write tokens and secrets to fork PRs.",
            impact=(
                "Combined with checking out PR code, this lets a forked pull request run with full repository secrets."
                if checks_out_pr
                else "pull_request_target carries secrets, so any code path influenced by the fork is sensitive."
            ),
            remediation="Prefer pull_request, and never check out and execute untrusted PR code in a privileged context.",
            safer_example="on:\n  pull_request:\n    branches: [main]",
            confidence=0.88,
            references=[_PR_TARGET_DOC],
        )
    ]


@rule(
    id="TRIG-UNSCOPED-BRANCHES",
    title="Push or pull_request trigger has no branch filter",
    category=TRIGGER_SAFETY,
    severity="low",
    description="A push/pull_request trigger runs on all branches without a guardrail.",
    providers=["github_actions"],
)
def unscoped_branches(ctx: AnalysisContext) -> Iterable[Finding]:
    raw_on = ctx.pipeline.raw.get("on") if isinstance(ctx.pipeline.raw, dict) else None
    deploy_like = "deploy" in ctx.text.lower() or "prod" in ctx.text.lower()
    if not deploy_like:
        return []
    if isinstance(raw_on, dict):
        push = raw_on.get("push")
        if isinstance(push, dict) and ("branches" in push or "tags" in push):
            return []
    elif isinstance(raw_on, (str, list)):
        pass
    else:
        return []
    if "push" not in ctx.pipeline.triggers:
        return []
    return [
        ctx.finding(
            id="TRIG-UNSCOPED-BRANCHES",
            title="Deploy workflow triggers on push without a branch filter",
            severity="low",
            category=TRIGGER_SAFETY,
            field_path="on.push.branches",
            location="on.push",
            line=ctx.find_line("on:", "push:"),
            description="A deployment-related workflow triggers on push but does not restrict which branches can run it.",
            impact="Feature or experimental branches could trigger privileged or deployment behavior.",
            remediation="Restrict the trigger to protected branches such as main or release/*.",
            safer_example="on:\n  push:\n    branches: [main]",
            confidence=0.62,
        )
    ]


@rule(
    id="TRIG-SCHEDULED-PRIVILEGE",
    title="Scheduled workflow runs with elevated permissions",
    category=TRIGGER_SAFETY,
    severity="medium",
    description="A schedule trigger is combined with write permissions on the default token.",
    providers=["github_actions"],
)
def scheduled_privilege(ctx: AnalysisContext) -> Iterable[Finding]:
    if "schedule" not in ctx.pipeline.triggers:
        return []
    summary = ctx.pipeline.permission_summary
    elevated = summary.get("*") == "write" or any(value == "write" for value in summary.values())
    if not elevated:
        return []
    return [
        ctx.finding(
            id="TRIG-SCHEDULED-PRIVILEGE",
            title="Scheduled workflow runs with elevated permissions",
            severity="medium",
            category=TRIGGER_SAFETY,
            field_path="on.schedule",
            location="on.schedule",
            line=ctx.find_line("schedule"),
            description="A scheduled workflow holds write permissions on the default token.",
            impact="Scheduled jobs run unattended, so an elevated token increases the impact of any compromised dependency.",
            remediation="Run scheduled workflows with read-only defaults and elevate only the steps that require it.",
            confidence=0.6,
        )
    ]


@rule(
    id="TRIG-GITLAB-BROAD-RULES",
    title="GitLab job rules are too broad",
    category=TRIGGER_SAFETY,
    severity="low",
    description="A deploy job uses only/except/rules that match every branch.",
    providers=["gitlab_ci"],
)
def gitlab_broad_rules(ctx: AnalysisContext) -> Iterable[Finding]:
    findings: list[Finding] = []
    for job in ctx.pipeline.jobs:
        raw = job.raw if isinstance(job.raw, dict) else {}
        name = job.name.lower()
        if "deploy" not in name and "prod" not in name:
            continue
        has_scope = any(key in raw for key in ("only", "except", "rules", "environment"))
        if has_scope:
            continue
        findings.append(
            ctx.finding(
                id="TRIG-GITLAB-BROAD-RULES",
                title=f"Deploy job '{job.name}' has no branch or rules guard",
                severity="low",
                category=TRIGGER_SAFETY,
                job=job.name,
                location=job.name,
                line=job.line,
                description="A deployment job has no only/except/rules constraint, so it can run from any ref.",
                impact="Deployments may be triggered from unprotected branches.",
                remediation="Add rules that restrict the job to protected branches and the intended environment.",
                safer_example="rules:\n  - if: '$CI_COMMIT_BRANCH == \"main\"'",
                confidence=0.58,
            )
        )
    return findings
