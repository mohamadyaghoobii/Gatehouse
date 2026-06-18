from __future__ import annotations

from typing import Iterable

from app.analysis.categories import SECRETS
from app.analysis.context import AnalysisContext
from app.analysis.patterns import (
    DOCKER_BUILD_ARG_SECRET_RE,
    ECHO_SECRET_RE,
    ENV_ARTIFACT_RE,
    HARDCODED_SECRET_RE,
    SECRET_VALUE_RE,
)
from app.analysis.registry import rule
from app.schemas import Finding

_PLACEHOLDER_HINTS = ("${{", "$(", "${", "<", "secrets.", "vault", "changeme", "example", "your-")


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.strip().strip("'\"").lower()
    return any(hint in lowered for hint in _PLACEHOLDER_HINTS) or lowered in {"true", "false", "null"}


@rule(
    id="SECRET-HARDCODED-VALUE",
    title="Hardcoded secret value in pipeline",
    category=SECRETS,
    severity="critical",
    description="A secret-like key is assigned a literal value instead of referencing a secret store.",
)
def hardcoded_secret(ctx: AnalysisContext) -> Iterable[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for match in HARDCODED_SECRET_RE.finditer(ctx.text):
        key = match.group("key")
        value = match.group("value")
        if _looks_like_placeholder(value) or key.lower() in seen:
            continue
        seen.add(key.lower())
        findings.append(
            ctx.finding(
                id="SECRET-HARDCODED-VALUE",
                title=f"Hardcoded secret assigned to {key}",
                severity="critical",
                category=SECRETS,
                field_path=key,
                location=match.group(0).strip()[:80],
                line=ctx.find_line(match.group(0).strip()[:40]),
                description=f"The value for '{key}' is written directly into the pipeline definition.",
                impact="Anyone with read access to the repository or its history can harvest the credential.",
                remediation="Move the value into the platform secret store and reference it at runtime.",
                safer_example="env:\n  DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}",
                confidence=0.8,
            )
        )
        if len(findings) >= 6:
            break
    return findings


@rule(
    id="SECRET-LITERAL-CREDENTIAL",
    title="Literal credential pattern detected",
    category=SECRETS,
    severity="critical",
    description="A value matches a known credential shape such as an API key, token, or private key.",
)
def literal_credential(ctx: AnalysisContext) -> Iterable[Finding]:
    match = SECRET_VALUE_RE.search(ctx.text)
    if not match:
        return []
    return [
        ctx.finding(
            id="SECRET-LITERAL-CREDENTIAL",
            title="Literal credential pattern detected",
            severity="critical",
            category=SECRETS,
            location="pipeline text",
            line=ctx.find_line(match.group(0)),
            description="A value in the pipeline matches the shape of a real credential or private key.",
            impact="Committed credentials can be extracted from history and used against production systems.",
            remediation="Revoke and rotate the credential, purge it from history, and store it in the secret manager.",
            confidence=0.9,
        )
    ]


@rule(
    id="SECRET-ECHO",
    title="Secret is echoed to the build log",
    category=SECRETS,
    severity="high",
    description="A shell step prints a secret or token to stdout, which lands in build logs.",
)
def echoed_secret(ctx: AnalysisContext) -> Iterable[Finding]:
    findings: list[Finding] = []
    for job in ctx.pipeline.jobs:
        for step in job.steps:
            if step.run and ECHO_SECRET_RE.search(step.run):
                findings.append(
                    ctx.finding(
                        id="SECRET-ECHO",
                        title="Secret is echoed to the build log",
                        severity="high",
                        category=SECRETS,
                        job=job.name,
                        location=step.label,
                        line=step.line,
                        description="A shell command echoes a secret value, which is captured in plaintext logs.",
                        impact="Build logs are often broadly readable and retained, exposing the secret to anyone who can view runs.",
                        remediation="Never echo secrets. Use masked variables and remove debug prints before merging.",
                        confidence=0.78,
                    )
                )
                break
    return findings


@rule(
    id="SECRET-DOCKER-BUILD-ARG",
    title="Secret passed through a Docker build argument",
    category=SECRETS,
    severity="high",
    description="A secret is passed via --build-arg, which is persisted in image history.",
)
def docker_build_arg_secret(ctx: AnalysisContext) -> Iterable[Finding]:
    match = DOCKER_BUILD_ARG_SECRET_RE.search(ctx.text)
    if not match:
        return []
    return [
        ctx.finding(
            id="SECRET-DOCKER-BUILD-ARG",
            title="Secret passed through a Docker build argument",
            severity="high",
            category=SECRETS,
            location=match.group(0).strip()[:80],
            line=ctx.find_line(match.group(0).strip()[:40]),
            description="A credential is supplied as a Docker build argument.",
            impact="Build args are stored in the image layer history and can be read back from the published image.",
            remediation="Use BuildKit secret mounts (RUN --mount=type=secret) instead of build args for sensitive values.",
            safer_example="RUN --mount=type=secret,id=npm_token npm ci",
            confidence=0.82,
        )
    ]


@rule(
    id="SECRET-IN-ARTIFACT",
    title="Sensitive file may be published as an artifact",
    category=SECRETS,
    severity="high",
    description="An upload or artifact path references .env, kubeconfig, keys, or credentials.",
)
def secret_in_artifact(ctx: AnalysisContext) -> Iterable[Finding]:
    text = ctx.text
    if "artifact" not in text.lower() and "upload" not in text.lower():
        return []
    match = ENV_ARTIFACT_RE.search(text)
    if not match:
        return []
    return [
        ctx.finding(
            id="SECRET-IN-ARTIFACT",
            title="Sensitive file may be published as an artifact",
            severity="high",
            category=SECRETS,
            location=match.group(0),
            line=ctx.find_line(match.group(0)),
            description="The pipeline references a sensitive file near an artifact upload step.",
            impact="Uploading dotenv files, kubeconfigs, or keys exposes credentials to anyone who can download artifacts.",
            remediation="Exclude secret files from artifact paths and upload only the build output you intend to share.",
            confidence=0.66,
        )
    ]
