from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from app.schemas import ExampleInfo

_CATALOG = [
    {
        "id": "github-actions-risky",
        "title": "Risky GitHub Actions release",
        "platform": "github_actions",
        "risk": "high",
        "file": "github-actions-risky.yml",
        "description": "write-all token, unpinned actions, inline password, and curl | bash on a deploy.",
    },
    {
        "id": "github-actions-deploy-risky",
        "title": "Unsafe pull_request_target deploy",
        "platform": "github_actions",
        "risk": "critical",
        "file": "github-actions-deploy-risky.yml",
        "description": "pull_request_target checks out fork code and deploys to production with broad tokens.",
    },
    {
        "id": "github-actions-hardened",
        "title": "Hardened GitHub Actions pipeline",
        "platform": "github_actions",
        "risk": "low",
        "file": "github-actions-hardened.yml",
        "description": "Read-only defaults, SHA-pinned actions, OIDC deploy, gated environment, and timeouts.",
    },
    {
        "id": "secrets-leak-workflow",
        "title": "Secret leakage workflow",
        "platform": "github_actions",
        "risk": "critical",
        "file": "secrets-leak-workflow.yml",
        "description": "Hardcoded keys, echoed secret, build-arg secret, and a .env artifact upload.",
    },
    {
        "id": "supply-chain-risk-workflow",
        "title": "Supply chain risk workflow",
        "platform": "github_actions",
        "risk": "high",
        "file": "supply-chain-risk-workflow.yml",
        "description": "Branch-pinned third-party actions, remote installers, and an unsigned image push.",
    },
    {
        "id": "gitlab-risky",
        "title": "Risky GitLab CI container deploy",
        "platform": "gitlab_ci",
        "risk": "high",
        "file": "gitlab-risky.yml",
        "description": "Docker-in-Docker, hardcoded token, password login, and curl | sh deploy.",
    },
    {
        "id": "gitlab-hardened",
        "title": "Hardened GitLab CI pipeline",
        "platform": "gitlab_ci",
        "risk": "low",
        "file": "gitlab-hardened.yml",
        "description": "Kaniko build, validated kubectl apply, manual gated production environment, and rules.",
    },
    {
        "id": "jenkins-risky",
        "title": "Risky Jenkinsfile deployment",
        "platform": "jenkins",
        "risk": "high",
        "file": "Jenkinsfile.risky",
        "description": "Remote script execution and a password handled outside withCredentials.",
    },
    {
        "id": "jenkins-hardened",
        "title": "Hardened Jenkinsfile",
        "platform": "jenkins",
        "risk": "low",
        "file": "Jenkinsfile.hardened",
        "description": "Fail-fast scripts, manual approval input, bound credentials, and post-failure handling.",
    },
]


def _examples_dir() -> Path:
    override = os.environ.get("GATEHOUSE_EXAMPLES_DIR")
    candidates = [Path(override)] if override else []
    here = Path(__file__).resolve()
    candidates += [
        Path("/app/examples"),
        here.parents[3] / "examples",  # apps/api/app/services -> repo root
        here.parents[4] / "examples",
    ]
    for path in candidates:
        if path.is_dir():
            return path
    return candidates[-1]


@lru_cache
def _load() -> dict[str, ExampleInfo]:
    directory = _examples_dir()
    examples: dict[str, ExampleInfo] = {}
    for entry in _CATALOG:
        file_path = directory / entry["file"]
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError:
            continue
        examples[entry["id"]] = ExampleInfo(
            id=entry["id"],
            title=entry["title"],
            platform=entry["platform"],
            description=entry["description"],
            risk=entry["risk"],
            content=content,
        )
    return examples


def list_examples() -> list[ExampleInfo]:
    return list(_load().values())


def get_example(example_id: str) -> ExampleInfo | None:
    return _load().get(example_id)
