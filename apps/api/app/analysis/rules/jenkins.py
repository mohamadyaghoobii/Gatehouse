from __future__ import annotations

from typing import Iterable

from app.analysis.categories import SECRETS
from app.analysis.context import AnalysisContext
from app.analysis.patterns import SECRET_NAME_RE
from app.analysis.registry import rule
from app.schemas import Finding


@rule(
    id="JENKINS-SECRET-OUTSIDE-CREDENTIALS",
    title="Secret handled outside withCredentials",
    category=SECRETS,
    severity="high",
    description="A Jenkinsfile references sensitive values without wrapping them in withCredentials.",
    providers=["jenkins"],
)
def secret_outside_credentials(ctx: AnalysisContext) -> Iterable[Finding]:
    if ctx.pipeline.notes.get("uses_withCredentials"):
        return []
    match = SECRET_NAME_RE.search(ctx.text)
    if not match:
        return []
    return [
        ctx.finding(
            id="JENKINS-SECRET-OUTSIDE-CREDENTIALS",
            title="Secret handled outside withCredentials",
            severity="high",
            category=SECRETS,
            location=match.group(0),
            line=ctx.find_line(match.group(0)),
            description="The Jenkinsfile handles a sensitive value without binding it through withCredentials.",
            impact="Secrets that are not bound and masked can leak into console output and environment dumps.",
            remediation="Bind credentials with withCredentials so Jenkins masks them in the build log.",
            safer_example="withCredentials([string(credentialsId: 'deploy-token', variable: 'TOKEN')]) {\n  sh './deploy.sh'\n}",
            confidence=0.7,
        )
    ]
