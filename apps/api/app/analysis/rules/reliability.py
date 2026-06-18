from __future__ import annotations

from typing import Iterable

from app.analysis.categories import MAINTAINABILITY, RELIABILITY
from app.analysis.context import AnalysisContext
from app.analysis.patterns import DEPLOY_COMMAND_RE, DEPLOY_NAME_RE
from app.analysis.registry import rule
from app.schemas import Finding

_TEST_HINTS = ("test", "lint", "pytest", "npm test", "go test", "jest", "vitest", "check", "scan")


@rule(
    id="REL-MISSING-TIMEOUT",
    title="Job has no timeout",
    category=RELIABILITY,
    severity="low",
    description="A GitHub Actions job does not set timeout-minutes and can hang for hours.",
    providers=["github_actions"],
)
def missing_timeout(ctx: AnalysisContext) -> Iterable[Finding]:
    findings: list[Finding] = []
    for job in ctx.pipeline.jobs:
        if job.timeout is None:
            findings.append(
                ctx.finding(
                    id="REL-MISSING-TIMEOUT",
                    title=f"Job '{job.name}' has no timeout",
                    severity="low",
                    category=RELIABILITY,
                    job=job.name,
                    field_path=f"jobs.{job.name}.timeout-minutes",
                    location=job.name,
                    line=job.line,
                    description="The job does not declare timeout-minutes.",
                    impact="A hung step can run until the platform maximum, wasting runner minutes and delaying feedback.",
                    remediation="Set a realistic timeout-minutes for each job.",
                    safer_example="timeout-minutes: 20",
                    confidence=0.65,
                )
            )
    return findings


@rule(
    id="REL-NO-CONCURRENCY",
    title="Workflow has no concurrency control",
    category=RELIABILITY,
    severity="info",
    description="No concurrency group is set, so stale runs are not cancelled.",
    providers=["github_actions"],
)
def no_concurrency(ctx: AnalysisContext) -> Iterable[Finding]:
    raw = ctx.pipeline.raw if isinstance(ctx.pipeline.raw, dict) else {}
    if "concurrency" in raw:
        return []
    if "push" not in ctx.pipeline.triggers and "pull_request" not in ctx.pipeline.triggers:
        return []
    return [
        ctx.finding(
            id="REL-NO-CONCURRENCY",
            title="Workflow has no concurrency control",
            severity="info",
            category=RELIABILITY,
            field_path="concurrency",
            location="workflow root",
            description="The workflow does not define a concurrency group to cancel superseded runs.",
            impact="Outdated runs keep consuming runners and can race deployments from rapid pushes.",
            remediation="Add a concurrency group keyed on the ref with cancel-in-progress.",
            safer_example="concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true",
            confidence=0.5,
        )
    ]


@rule(
    id="REL-DEPLOY-WITHOUT-TESTS",
    title="Deployment runs without a preceding test stage",
    category=RELIABILITY,
    severity="medium",
    description="A deploy job has no dependency on a test/lint job and the pipeline has no test stage.",
)
def deploy_without_tests(ctx: AnalysisContext) -> Iterable[Finding]:
    jobs = ctx.pipeline.jobs
    if len(jobs) < 1:
        return []
    text = ctx.text.lower()
    has_tests = any(hint in text for hint in _TEST_HINTS)
    deploy_jobs = [job for job in jobs if DEPLOY_NAME_RE.search(job.name) or any(step.run and DEPLOY_COMMAND_RE.search(step.run) for step in job.steps)]
    if not deploy_jobs or has_tests:
        return []
    job = deploy_jobs[0]
    return [
        ctx.finding(
            id="REL-DEPLOY-WITHOUT-TESTS",
            title="Deployment runs without a preceding test stage",
            severity="medium",
            category=RELIABILITY,
            job=job.name,
            location=job.name,
            line=job.line,
            description="A deployment job runs but the pipeline contains no visible test or lint stage.",
            impact="Untested changes can ship straight to an environment, increasing the chance of a bad release.",
            remediation="Add a test/lint stage and make the deploy job depend on it before shipping.",
            safer_example="deploy:\n  needs: [test]",
            confidence=0.62,
        )
    ]


@rule(
    id="MNT-NO-WORKFLOW-NAME",
    title="Workflow is missing a name",
    category=MAINTAINABILITY,
    severity="info",
    description="The workflow has no top-level name, making runs harder to identify.",
    providers=["github_actions"],
)
def missing_name(ctx: AnalysisContext) -> Iterable[Finding]:
    if ctx.pipeline.name:
        return []
    return [
        ctx.finding(
            id="MNT-NO-WORKFLOW-NAME",
            title="Workflow is missing a name",
            severity="info",
            category=MAINTAINABILITY,
            field_path="name",
            location="workflow root",
            description="The workflow does not declare a top-level name.",
            impact="Unnamed workflows are harder to find in the Actions UI and in audit logs.",
            remediation="Add a descriptive top-level name.",
            safer_example="name: build-and-deploy",
            confidence=0.4,
        )
    ]


@rule(
    id="MNT-NO-POST-FAILURE",
    title="Jenkins pipeline has no post/failure handling",
    category=MAINTAINABILITY,
    severity="info",
    description="A declarative Jenkins pipeline has no post block for notifications or cleanup.",
    providers=["jenkins"],
)
def jenkins_no_post(ctx: AnalysisContext) -> Iterable[Finding]:
    notes = ctx.pipeline.notes
    if not notes.get("declarative") or notes.get("has_post"):
        return []
    return [
        ctx.finding(
            id="MNT-NO-POST-FAILURE",
            title="Jenkins pipeline has no post/failure handling",
            severity="info",
            category=MAINTAINABILITY,
            location="pipeline",
            description="The declarative pipeline does not define a post block for failure handling or cleanup.",
            impact="Failures may go unnoticed and workspaces may not be cleaned up reliably.",
            remediation="Add a post block with failure notifications and always-cleanup steps.",
            safer_example="post {\n  failure { mail to: 'team@example.com', subject: 'Build failed' }\n  always { cleanWs() }\n}",
            confidence=0.45,
        )
    ]
