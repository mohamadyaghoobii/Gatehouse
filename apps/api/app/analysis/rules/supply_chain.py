from __future__ import annotations

import re
from typing import Iterable

from app.analysis.categories import SUPPLY_CHAIN
from app.analysis.context import AnalysisContext
from app.analysis.patterns import MUTABLE_REF_RE, PINNED_SHA_RE, REMOTE_EXEC_RE
from app.analysis.registry import rule
from app.schemas import Finding

_FIRST_PARTY = ("actions/", "github/", "docker/")
_PIP_URL_RE = re.compile(r"pip\s+install\s+[^\n]*https?://", re.I)
_NPM_REGISTRY_RE = re.compile(r"--registry[= ]https?://(?!registry\.npmjs\.org)", re.I)

_PIN_DOC = "https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"


@rule(
    id="SC-UNPINNED-ACTION",
    title="GitHub Action is not pinned to a commit SHA",
    category=SUPPLY_CHAIN,
    severity="medium",
    description="An action is referenced by a mutable tag or branch instead of a full commit SHA.",
    providers=["github_actions"],
)
def unpinned_action(ctx: AnalysisContext) -> Iterable[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for job in ctx.pipeline.jobs:
        for step in job.steps:
            uses = step.uses
            if not uses or "@" not in uses or PINNED_SHA_RE.search(uses):
                continue
            if uses in seen:
                continue
            seen.add(uses)
            ref = uses.split("@", 1)[1]
            third_party = not uses.startswith(_FIRST_PARTY)
            mutable = MUTABLE_REF_RE.search(uses) is not None
            severity = "high" if third_party and mutable else "medium"
            findings.append(
                ctx.finding(
                    id="SC-UNPINNED-ACTION",
                    title=f"{uses} is not pinned to a commit SHA",
                    severity=severity,
                    category=SUPPLY_CHAIN,
                    job=job.name,
                    field_path=f"jobs.{job.name}.steps[].uses",
                    location=uses,
                    line=step.line or ctx.find_line(uses),
                    description=f"The action {uses} uses the mutable reference '{ref}'.",
                    impact="If the tag or branch is moved, unreviewed third-party code runs with your token and secrets.",
                    remediation="Pin the action to a full 40-character commit SHA and track updates with Dependabot or Renovate.",
                    safer_example="uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1",
                    confidence=0.85,
                    references=[_PIN_DOC],
                )
            )
    return findings


@rule(
    id="SC-REMOTE-EXEC",
    title="Remote script piped directly into a shell",
    category=SUPPLY_CHAIN,
    severity="high",
    description="A script is downloaded and executed without integrity verification (curl | bash).",
)
def remote_exec(ctx: AnalysisContext) -> Iterable[Finding]:
    findings: list[Finding] = []
    for job in ctx.pipeline.jobs:
        for step in job.steps:
            body = step.run or ""
            if REMOTE_EXEC_RE.search(body):
                match = REMOTE_EXEC_RE.search(body)
                findings.append(
                    ctx.finding(
                        id="SC-REMOTE-EXEC",
                        title="Remote script piped directly into a shell",
                        severity="high",
                        category=SUPPLY_CHAIN,
                        job=job.name,
                        location=match.group(0).strip()[:80] if match else step.label,
                        line=step.line or ctx.find_line(match.group(0).strip()[:40] if match else ""),
                        description="The step downloads a remote script and pipes it straight into a shell interpreter.",
                        impact="If the endpoint or network path is tampered with, attacker code executes on the runner with full access.",
                        remediation="Download to a file, verify a published checksum or signature, then execute the verified artifact.",
                        safer_example="curl -fsSLo tool.sh https://example.com/tool.sh\nsha256sum -c tool.sh.sha256\nbash tool.sh",
                        confidence=0.86,
                    )
                )
                break
    return findings


@rule(
    id="SC-UNTRUSTED-INSTALL",
    title="Dependency installed from an arbitrary URL or registry",
    category=SUPPLY_CHAIN,
    severity="medium",
    description="pip or npm installs from an unverified URL or non-default registry.",
)
def untrusted_install(ctx: AnalysisContext) -> Iterable[Finding]:
    findings: list[Finding] = []
    for job in ctx.pipeline.jobs:
        for step in job.steps:
            body = step.run or ""
            match = _PIP_URL_RE.search(body) or _NPM_REGISTRY_RE.search(body)
            if match:
                findings.append(
                    ctx.finding(
                        id="SC-UNTRUSTED-INSTALL",
                        title="Dependency installed from an arbitrary URL or registry",
                        severity="medium",
                        category=SUPPLY_CHAIN,
                        job=job.name,
                        location=match.group(0).strip()[:80],
                        line=step.line,
                        description="A package is installed from a URL or registry that is not the trusted default.",
                        impact="Unverified package sources can serve tampered dependencies into your build.",
                        remediation="Install from trusted registries with a lockfile and verify hashes where possible.",
                        confidence=0.6,
                    )
                )
                break
    return findings


@rule(
    id="SC-MISSING-PROVENANCE",
    title="Container build has no provenance or SBOM hints",
    category=SUPPLY_CHAIN,
    severity="low",
    description="A docker build/push runs without provenance, attestations, or an SBOM step.",
)
def missing_provenance(ctx: AnalysisContext) -> Iterable[Finding]:
    text = ctx.text.lower()
    if "docker build" not in text and "docker/build-push-action" not in text:
        return []
    if any(hint in text for hint in ("provenance", "sbom", "attest", "cosign", "syft")):
        return []
    return [
        ctx.finding(
            id="SC-MISSING-PROVENANCE",
            title="Container build has no provenance or SBOM hints",
            severity="low",
            category=SUPPLY_CHAIN,
            location="docker build",
            line=ctx.find_line("docker build", "build-push-action"),
            description="Images are built without generating provenance attestations or a software bill of materials.",
            impact="Without provenance or an SBOM, downstream consumers cannot verify what went into the image.",
            remediation="Enable build provenance/attestations and generate an SBOM (for example with syft or BuildKit).",
            confidence=0.55,
        )
    ]
