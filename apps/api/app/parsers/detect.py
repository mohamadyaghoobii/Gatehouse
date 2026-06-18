from __future__ import annotations

import re

_JENKINS_HINTS = (
    re.compile(r"^\s*pipeline\s*\{", re.M),
    re.compile(r"^\s*node\s*[\({]", re.M),
    re.compile(r"\bstage\s*\(", re.M),
    re.compile(r"\bsteps\s*\{", re.M),
)
_GITHUB_HINTS = (
    re.compile(r"^\s*runs-on\s*:", re.M),
    re.compile(r"\$\{\{\s*secrets\.", re.M),
    re.compile(r"\buses\s*:", re.M),
)
_GITLAB_HINTS = (
    re.compile(r"^\s*stages\s*:", re.M),
    re.compile(r"^\s*before_script\s*:", re.M),
    re.compile(r"^\s*script\s*:", re.M),
    re.compile(r"^\s*image\s*:", re.M),
)


def detect_provider(content: str, requested: str = "auto") -> str:
    if requested and requested != "auto":
        return requested

    if any(pattern.search(content) for pattern in _JENKINS_HINTS) and "runs-on" not in content:
        return "jenkins"

    has_on = re.search(r"^\s*on\s*:", content, re.M) is not None
    has_jobs = re.search(r"^\s*jobs\s*:", content, re.M) is not None
    github_score = sum(1 for pattern in _GITHUB_HINTS if pattern.search(content)) + (2 if has_on and has_jobs else 0)
    gitlab_score = sum(1 for pattern in _GITLAB_HINTS if pattern.search(content))
    if "jobs:" in content and "runs-on" in content:
        github_score += 2
    if has_jobs is False and gitlab_score >= 1:
        gitlab_score += 1

    if github_score >= gitlab_score and github_score > 0:
        return "github_actions"
    if gitlab_score > 0:
        return "gitlab_ci"
    if any(pattern.search(content) for pattern in _JENKINS_HINTS):
        return "jenkins"
    return "github_actions"
