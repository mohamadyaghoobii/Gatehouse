from __future__ import annotations

import re
from collections import Counter
from typing import Any
from app.schemas import Finding, PipelineJob, AnalyzeResponse
from app.services.parser import ParsedPipeline, find_line, parse_pipeline
from app.services.rules import RULES

SECRET_NAME_RE = re.compile(r"(password|passwd|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)", re.I)
SECRET_VALUE_RE = re.compile(r"(ghp_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{10,})")
PINNED_SHA_RE = re.compile(r"@[a-f0-9]{40}$", re.I)
MUTABLE_REF_RE = re.compile(r"@(main|master|dev|develop|latest|v\d+|v\d+\.\d+)$", re.I)
REMOTE_EXEC_RE = re.compile(r"(curl|wget)\s+[^\n|;&]+[|]\s*(bash|sh)|bash\s+<\s*\(\s*(curl|wget)", re.I)
DEPLOY_RE = re.compile(r"(deploy|release|production|prod|kubectl|helm|terraform apply|serverless deploy)", re.I)
DANGEROUS_RE = re.compile(r"(chmod\s+777|docker\s+login\s+.*(-p|--password)|sshpass|set\s+\+x)", re.I)


def analyze_pipeline(content: str, platform: str = "auto", project_name: str | None = None, environment: str | None = None, strict_mode: bool = False, enabled_categories: list[str] | None = None) -> AnalyzeResponse:
    parsed = parse_pipeline(content, platform)
    findings = []
    findings.extend(check_secret_patterns(parsed))
    findings.extend(check_remote_execution(parsed))
    findings.extend(check_dangerous_shell(parsed))
    if parsed.platform == "github_actions":
        findings.extend(check_github_permissions(parsed))
        findings.extend(check_github_actions_pinning(parsed))
        findings.extend(check_github_deploy_gates(parsed))
        findings.extend(check_github_timeouts(parsed))
    if parsed.platform == "gitlab_ci":
        findings.extend(check_gitlab_privileged(parsed))
        findings.extend(check_gitlab_deploy_gates(parsed))
    if parsed.platform == "jenkins":
        findings.extend(check_jenkins(parsed))
    if enabled_categories:
        allowed = {item.lower() for item in enabled_categories}
        findings = [item for item in findings if item.category.lower() in allowed]
    if strict_mode:
        findings.extend(strict_mode_findings(parsed))
    score = calculate_score(findings)
    severity_counts = Counter(item.severity for item in findings)
    category_counts = Counter(item.category for item in findings)
    jobs = [PipelineJob(name=item["name"], stage=item.get("stage"), runner=item.get("runner"), steps=item.get("steps", 0), uses_secrets=job_uses_secret(item.get("raw", {}))) for item in parsed.jobs]
    return AnalyzeResponse(
        score=score,
        grade=grade_for_score(score),
        summary=summary_for(parsed, findings, score),
        platform=parsed.platform,
        pipeline_name=parsed.name,
        jobs=jobs,
        findings=findings,
        severity_counts={key: severity_counts.get(key, 0) for key in ["critical", "high", "medium", "low", "info"]},
        category_counts=dict(category_counts),
        recommended_next_steps=next_steps(findings),
        metadata={
            "project_name": project_name,
            "environment": environment,
            "jobs_analyzed": len(parsed.jobs),
            "lines_analyzed": len(parsed.lines),
            "strict_mode": strict_mode,
        },
    )


def make_finding(id: str, title: str, severity: str, category: str, location: str, description: str, impact: str, remediation: str, line: int | None = None, safer_example: str | None = None, confidence: float = 0.82) -> Finding:
    return Finding(id=id, title=title, severity=severity, status="fail" if severity in {"critical", "high", "medium"} else "warn", category=category, location=location, line=line, description=description, impact=impact, remediation=remediation, safer_example=safer_example, confidence=confidence)


def as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(f"{k}: {as_text(v)}" for k, v in value.items())
    if isinstance(value, list):
        return "\n".join(as_text(item) for item in value)
    return str(value)


def check_secret_patterns(parsed: ParsedPipeline) -> list[Finding]:
    findings = []
    text = as_text(parsed.raw)
    for match in SECRET_NAME_RE.finditer(text):
        line = find_line(parsed.lines, match.group(0))
        findings.append(make_finding(
            "SECRET-IN-PIPELINE",
            "Secret-like variable appears in pipeline configuration",
            "critical",
            "Secrets",
            match.group(0),
            "The pipeline contains a variable, argument, or field name that looks sensitive.",
            "Secrets in pipeline files can leak through logs, pull requests, caches, artifacts, or forked workflow execution.",
            "Move sensitive values to the platform secret store and reference them only at runtime with least privilege.",
            line,
            "env:\n  NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}",
            0.78,
        ))
        break
    value_match = SECRET_VALUE_RE.search(text)
    if value_match:
        findings.append(make_finding(
            "SECRET-LITERAL-VALUE",
            "Literal credential pattern detected",
            "critical",
            "Secrets",
            "pipeline text",
            "A value in the pipeline resembles a credential or private key.",
            "A committed credential can be harvested by anyone with repository access and may remain in Git history.",
            "Revoke the credential, remove it from history if required, and move it to the CI/CD secret manager.",
            find_line(parsed.lines, value_match.group(0)),
            None,
            0.88,
        ))
    return findings


def check_remote_execution(parsed: ParsedPipeline) -> list[Finding]:
    text = as_text(parsed.raw)
    match = REMOTE_EXEC_RE.search(text)
    if not match:
        return []
    return [make_finding(
        "SCRIPT-REMOTE-EXEC",
        "Remote script is executed directly",
        "high",
        "Build Safety",
        match.group(0),
        "The pipeline downloads a remote script and pipes it into a shell.",
        "If the remote endpoint or network path is compromised, attacker-controlled code can execute in the runner.",
        "Pin downloads to a checksum, vendor trusted scripts, or use signed release artifacts with verification.",
        find_line(parsed.lines, match.group(0)),
        "curl -fsSLO https://example.com/tool.tar.gz\nsha256sum -c tool.tar.gz.sha256\ntar -xzf tool.tar.gz",
        0.86,
    )]


def check_dangerous_shell(parsed: ParsedPipeline) -> list[Finding]:
    text = as_text(parsed.raw)
    findings = []
    for match in DANGEROUS_RE.finditer(text):
        findings.append(make_finding(
            "DANGEROUS-SHELL-PATTERN",
            "Dangerous shell pattern needs review",
            "medium",
            "Build Safety",
            match.group(0),
            "A shell command contains a risky pattern often associated with weak runner hygiene.",
            "Loose permissions, password-based logins, or disabled shell protections can expose credentials and artifacts.",
            "Replace the command with a safer platform-native mechanism and restrict file permissions to the minimum needed.",
            find_line(parsed.lines, match.group(0)),
            None,
            0.74,
        ))
    return findings


def check_github_permissions(parsed: ParsedPipeline) -> list[Finding]:
    raw = parsed.raw if isinstance(parsed.raw, dict) else {}
    permissions = raw.get("permissions")
    findings = []
    if permissions == "write-all":
        findings.append(make_finding(
            "GH-PERM-WRITE-ALL",
            "Workflow grants write-all permissions",
            "high",
            "Permissions",
            "permissions",
            "The workflow grants broad write permissions to the default token.",
            "A compromised step can modify repository contents, releases, packages, or pull requests depending on repository settings.",
            "Set explicit read-only defaults and grant write permissions only to jobs that need them.",
            find_line(parsed.lines, "write-all"),
            "permissions:\n  contents: read",
            0.92,
        ))
    if isinstance(permissions, dict):
        for key, value in permissions.items():
            if str(value).lower() == "write" and key in {"contents", "pull-requests", "packages", "id-token", "actions"}:
                findings.append(make_finding(
                    "GH-BROAD-WRITE-PERMISSION",
                    f"Workflow grants {key}: write",
                    "medium" if key != "id-token" else "high",
                    "Permissions",
                    f"permissions.{key}",
                    "The workflow grants a sensitive write permission at workflow scope.",
                    "Broad workflow-scope permissions increase blast radius if any job step is compromised.",
                    "Move sensitive permissions to the specific job that requires them and use read-only defaults.",
                    find_line(parsed.lines, str(key)),
                    "permissions:\n  contents: read\n\njobs:\n  release:\n    permissions:\n      contents: write",
                    0.84,
                ))
    return findings


def check_github_actions_pinning(parsed: ParsedPipeline) -> list[Finding]:
    raw = parsed.raw if isinstance(parsed.raw, dict) else {}
    jobs = raw.get("jobs", {}) if isinstance(raw.get("jobs", {}), dict) else {}
    findings = []
    for job_name, job in jobs.items():
        steps = job.get("steps", []) if isinstance(job, dict) and isinstance(job.get("steps", []), list) else []
        for step in steps:
            if not isinstance(step, dict) or "uses" not in step:
                continue
            uses = str(step["uses"])
            if PINNED_SHA_RE.search(uses):
                continue
            if "@" not in uses or MUTABLE_REF_RE.search(uses) or re.search(r"@v\d+(\.\d+)?(\.\d+)?$", uses, re.I):
                findings.append(make_finding(
                    "SCM-UNPINNED-ACTION",
                    "GitHub Action is not pinned to a commit SHA",
                    "medium",
                    "Supply Chain",
                    f"jobs.{job_name}.steps.uses",
                    f"The action {uses} uses a mutable reference.",
                    "If the action tag or branch changes unexpectedly, unreviewed code can run in the pipeline.",
                    "Pin third-party actions to a full commit SHA and use Dependabot or Renovate to manage updates.",
                    find_line(parsed.lines, uses),
                    "uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744",
                    0.87,
                ))
    return findings


def check_github_deploy_gates(parsed: ParsedPipeline) -> list[Finding]:
    raw = parsed.raw if isinstance(parsed.raw, dict) else {}
    jobs = raw.get("jobs", {}) if isinstance(raw.get("jobs", {}), dict) else {}
    findings = []
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        text = as_text(job)
        if DEPLOY_RE.search(job_name) or DEPLOY_RE.search(text):
            if not job.get("environment"):
                findings.append(make_finding(
                    "MISSING-APPROVAL-GATE",
                    "Deployment job has no environment gate",
                    "medium",
                    "Release Safety",
                    f"jobs.{job_name}",
                    "The job looks deployment-related but does not define a GitHub environment.",
                    "Without environment protection rules, production changes may deploy without approval or branch controls.",
                    "Use protected environments with reviewers and branch restrictions for production-like deployments.",
                    find_line(parsed.lines, str(job_name)),
                    "environment:\n  name: production\n  url: https://example.com",
                    0.75,
                ))
    return findings


def check_github_timeouts(parsed: ParsedPipeline) -> list[Finding]:
    raw = parsed.raw if isinstance(parsed.raw, dict) else {}
    jobs = raw.get("jobs", {}) if isinstance(raw.get("jobs", {}), dict) else {}
    findings = []
    for job_name, job in jobs.items():
        if isinstance(job, dict) and "timeout-minutes" not in job:
            findings.append(make_finding(
                "MISSING-TIMEOUT",
                "Job has no timeout",
                "low",
                "Reliability",
                f"jobs.{job_name}",
                "The job does not define timeout-minutes.",
                "Hanging jobs can waste runner capacity and delay releases.",
                "Set a practical timeout for each job based on expected runtime.",
                find_line(parsed.lines, str(job_name)),
                "timeout-minutes: 20",
                0.7,
            ))
    return findings


def check_gitlab_privileged(parsed: ParsedPipeline) -> list[Finding]:
    text = as_text(parsed.raw)
    if "docker:dind" not in text and "privileged" not in text.lower():
        return []
    return [make_finding(
        "GITLAB-PRIVILEGED-DIND",
        "Pipeline uses Docker-in-Docker or privileged runner features",
        "high",
        "Runner Hardening",
        "services/image",
        "The pipeline appears to use Docker-in-Docker or privileged execution.",
        "Privileged runner workloads can increase breakout and credential exposure risk.",
        "Prefer rootless builders, isolated build workers, BuildKit, Kaniko, or tightly scoped privileged runners.",
        find_line(parsed.lines, "docker:dind") or find_line(parsed.lines, "privileged"),
        None,
        0.8,
    )]


def check_gitlab_deploy_gates(parsed: ParsedPipeline) -> list[Finding]:
    findings = []
    for job in parsed.jobs:
        raw = job.get("raw", {})
        text = as_text(raw)
        name = str(job.get("name", ""))
        if DEPLOY_RE.search(name) or DEPLOY_RE.search(text):
            if "when" not in raw or raw.get("when") != "manual":
                findings.append(make_finding(
                    "MISSING-APPROVAL-GATE",
                    "Deployment job is not manual gated",
                    "medium",
                    "Release Safety",
                    name,
                    "A deployment-like GitLab job does not use a visible manual gate.",
                    "Unreviewed changes may deploy automatically to sensitive environments.",
                    "Use protected environments, manual gates, approvals, or branch protections for production deploys.",
                    find_line(parsed.lines, name),
                    "when: manual\nenvironment: production",
                    0.74,
                ))
    return findings


def check_jenkins(parsed: ParsedPipeline) -> list[Finding]:
    text = as_text(parsed.raw)
    findings = []
    if "withCredentials" not in text and SECRET_NAME_RE.search(text):
        findings.append(make_finding(
            "JENKINS-SECRET-HANDLING",
            "Jenkinsfile references secrets outside withCredentials",
            "high",
            "Secrets",
            "Jenkinsfile",
            "The Jenkinsfile appears to handle sensitive values without withCredentials.",
            "Secrets may leak into logs or environment dumps if not scoped correctly.",
            "Use withCredentials and mask output from sensitive commands.",
            find_line(parsed.lines, "secret") or find_line(parsed.lines, "password"),
            "withCredentials([string(credentialsId: 'token-id', variable: 'TOKEN')]) { sh 'deploy.sh' }",
            0.76,
        ))
    if REMOTE_EXEC_RE.search(text):
        findings.extend(check_remote_execution(parsed))
    return findings


def strict_mode_findings(parsed: ParsedPipeline) -> list[Finding]:
    findings = []
    if parsed.platform == "github_actions":
        raw = parsed.raw if isinstance(parsed.raw, dict) else {}
        if "permissions" not in raw:
            findings.append(make_finding(
                "GH-MISSING-PERMISSIONS-DEFAULT",
                "Workflow does not define default token permissions",
                "low",
                "Permissions",
                "permissions",
                "The workflow does not declare default permissions.",
                "Implicit permissions can be misunderstood across repository settings.",
                "Declare explicit read-only workflow permissions at the top level.",
                None,
                "permissions:\n  contents: read",
                0.66,
            ))
    return findings


def job_uses_secret(raw: Any) -> bool:
    return bool(SECRET_NAME_RE.search(as_text(raw)))


def calculate_score(findings: list[Finding]) -> int:
    weights = {"critical": 28, "high": 18, "medium": 9, "low": 3, "info": 0}
    score = 100
    for finding in findings:
        score -= int(weights[finding.severity] * finding.confidence)
    return max(0, min(100, score))


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def summary_for(parsed: ParsedPipeline, findings: list[Finding], score: int) -> str:
    if not findings:
        return f"No major pipeline risks were detected across {len(parsed.jobs)} job(s). Score: {score}."
    high_count = sum(1 for item in findings if item.severity in {"critical", "high"})
    return f"Gatehouse reviewed {len(parsed.jobs)} job(s) in a {parsed.platform.replace('_', ' ')} pipeline and found {len(findings)} issue(s), including {high_count} critical/high item(s)."


def next_steps(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["Keep actions and build dependencies pinned.", "Maintain protected deployment environments.", "Run pipeline review on every pull request."]
    categories = {item.category for item in findings}
    steps = []
    if "Secrets" in categories:
        steps.append("Remove sensitive values from pipeline files and rotate anything that may have been committed.")
    if "Permissions" in categories:
        steps.append("Apply least-privilege token permissions and move write access to the smallest possible job scope.")
    if "Supply Chain" in categories:
        steps.append("Pin third-party actions and external dependencies to immutable versions or commit SHAs.")
    if "Release Safety" in categories:
        steps.append("Add manual approval gates or protected environments for deployment-like jobs.")
    if "Build Safety" in categories:
        steps.append("Replace direct remote script execution with verified artifacts or vendored scripts.")
    return steps[:5]
