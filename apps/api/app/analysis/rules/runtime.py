from __future__ import annotations

import re
from typing import Iterable

from app.analysis.categories import RUNTIME_SCRIPTS
from app.analysis.context import AnalysisContext
from app.analysis.patterns import (
    CHMOD_777_RE,
    DOCKER_PASSWORD_RE,
    SET_X_RE,
    SUDO_RE,
)
from app.analysis.registry import rule
from app.schemas import Finding

_DOCKER_SOCK_RE = re.compile(r"/var/run/docker\.sock", re.I)
_PRIVILEGED_RE = re.compile(r"privileged\s*[:=]\s*true|--privileged|docker:dind", re.I)
_FAIL_FAST_RE = re.compile(r"set\s+-[a-z]*e|#!/bin/bash\s+-e|set\s+-euo", re.I)


@rule(
    id="RUN-CHMOD-777",
    title="World-writable permissions set with chmod 777",
    category=RUNTIME_SCRIPTS,
    severity="medium",
    description="A step sets 777 permissions, making files world-writable.",
)
def chmod_777(ctx: AnalysisContext) -> Iterable[Finding]:
    match = CHMOD_777_RE.search(ctx.text)
    if not match:
        return []
    return [
        ctx.finding(
            id="RUN-CHMOD-777",
            title="World-writable permissions set with chmod 777",
            severity="medium",
            category=RUNTIME_SCRIPTS,
            location=match.group(0),
            line=ctx.find_line(match.group(0)),
            description="A shell step grants world-writable permissions with chmod 777.",
            impact="World-writable files let any process on the runner modify scripts or output before they are used.",
            remediation="Grant the minimum permissions needed, typically 755 for executables or 644 for data.",
            safer_example="chmod 755 ./scripts/deploy.sh",
            confidence=0.8,
        )
    ]


@rule(
    id="RUN-DOCKER-PASSWORD",
    title="Docker login uses an inline password",
    category=RUNTIME_SCRIPTS,
    severity="high",
    description="docker login is called with -p/--password, exposing the credential to logs and process lists.",
)
def docker_password(ctx: AnalysisContext) -> Iterable[Finding]:
    match = DOCKER_PASSWORD_RE.search(ctx.text)
    if not match:
        return []
    return [
        ctx.finding(
            id="RUN-DOCKER-PASSWORD",
            title="Docker login uses an inline password",
            severity="high",
            category=RUNTIME_SCRIPTS,
            location=match.group(0).strip()[:60],
            line=ctx.find_line(match.group(0).strip()[:40]),
            description="docker login passes the password directly on the command line.",
            impact="The credential can leak through shell history, process listings, and build logs.",
            remediation="Pipe the password from a secret via stdin using --password-stdin.",
            safer_example='echo "$REGISTRY_TOKEN" | docker login -u ci --password-stdin registry.example.com',
            confidence=0.82,
        )
    ]


@rule(
    id="RUN-SET-X",
    title="Shell tracing may expose secrets",
    category=RUNTIME_SCRIPTS,
    severity="low",
    description="set -x enables command tracing that can print secret values into logs.",
)
def shell_tracing(ctx: AnalysisContext) -> Iterable[Finding]:
    if not SET_X_RE.search(ctx.text):
        return []
    if not any(hint in ctx.text.lower() for hint in ("secret", "token", "password", "key")):
        return []
    return [
        ctx.finding(
            id="RUN-SET-X",
            title="Shell tracing may expose secrets",
            severity="low",
            category=RUNTIME_SCRIPTS,
            location="set -x",
            line=ctx.find_line("set -x"),
            description="The pipeline enables shell command tracing while handling sensitive values.",
            impact="Traced commands print expanded variables, which can leak secrets into the build log.",
            remediation="Avoid set -x around sensitive commands, or disable tracing before using secrets.",
            confidence=0.55,
        )
    ]


@rule(
    id="RUN-SUDO",
    title="Pipeline runs commands with sudo",
    category=RUNTIME_SCRIPTS,
    severity="info",
    description="sudo is used in a step, which usually is not needed on hosted runners.",
)
def sudo_usage(ctx: AnalysisContext) -> Iterable[Finding]:
    for job in ctx.pipeline.jobs:
        for step in job.steps:
            if step.run and SUDO_RE.search(step.run):
                return [
                    ctx.finding(
                        id="RUN-SUDO",
                        title="Pipeline runs commands with sudo",
                        severity="info",
                        category=RUNTIME_SCRIPTS,
                        job=job.name,
                        location=step.label,
                        line=step.line,
                        description="A step elevates privileges with sudo.",
                        impact="Unnecessary privilege elevation widens what a compromised step can do to the runner.",
                        remediation="Run as the default user and install tools without root where possible.",
                        confidence=0.45,
                    )
                ]
    return []


@rule(
    id="RUN-NO-FAIL-FAST",
    title="Multi-line shell script does not fail fast",
    category=RUNTIME_SCRIPTS,
    severity="info",
    description="A multi-command run block does not enable set -e, so failures may be ignored.",
)
def no_fail_fast(ctx: AnalysisContext) -> Iterable[Finding]:
    for job in ctx.pipeline.jobs:
        for step in job.steps:
            body = step.run or ""
            if body.count("\n") >= 2 and not _FAIL_FAST_RE.search(body):
                return [
                    ctx.finding(
                        id="RUN-NO-FAIL-FAST",
                        title="Multi-line shell script does not fail fast",
                        severity="info",
                        category=RUNTIME_SCRIPTS,
                        job=job.name,
                        location=step.label,
                        line=step.line,
                        description="A multi-command shell step does not enable strict error handling.",
                        impact="Without set -euo pipefail, a failing command can be silently ignored and ship a broken build.",
                        remediation="Start multi-line scripts with set -euo pipefail.",
                        safer_example="run: |\n  set -euo pipefail\n  ./build.sh\n  ./test.sh",
                        confidence=0.5,
                    )
                ]
    return []


@rule(
    id="RUN-DOCKER-SOCKET",
    title="Docker socket is mounted into the build",
    category=RUNTIME_SCRIPTS,
    severity="high",
    description="The host Docker socket is mounted, which is equivalent to root on the host.",
)
def docker_socket(ctx: AnalysisContext) -> Iterable[Finding]:
    if not _DOCKER_SOCK_RE.search(ctx.text):
        return []
    return [
        ctx.finding(
            id="RUN-DOCKER-SOCKET",
            title="Docker socket is mounted into the build",
            severity="high",
            category=RUNTIME_SCRIPTS,
            location="/var/run/docker.sock",
            line=ctx.find_line("docker.sock"),
            description="The pipeline mounts the host Docker socket into a job or container.",
            impact="Access to the Docker socket is effectively root on the host and enables container breakout.",
            remediation="Use a rootless builder such as Kaniko or BuildKit instead of mounting the Docker socket.",
            confidence=0.8,
        )
    ]


@rule(
    id="RUN-PRIVILEGED",
    title="Privileged or Docker-in-Docker execution",
    category=RUNTIME_SCRIPTS,
    severity="high",
    description="The pipeline runs privileged containers or Docker-in-Docker.",
)
def privileged(ctx: AnalysisContext) -> Iterable[Finding]:
    match = _PRIVILEGED_RE.search(ctx.text)
    if not match:
        return []
    return [
        ctx.finding(
            id="RUN-PRIVILEGED",
            title="Privileged or Docker-in-Docker execution",
            severity="high",
            category=RUNTIME_SCRIPTS,
            location=match.group(0),
            line=ctx.find_line(match.group(0), "dind", "privileged"),
            description="The pipeline uses privileged mode or Docker-in-Docker.",
            impact="Privileged workloads weaken isolation and increase breakout and credential exposure risk.",
            remediation="Prefer rootless builders (Kaniko, BuildKit) or tightly scoped, isolated privileged runners.",
            confidence=0.78,
        )
    ]
