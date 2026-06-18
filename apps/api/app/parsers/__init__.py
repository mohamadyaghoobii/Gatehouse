from __future__ import annotations

from app.parsers.detect import detect_provider
from app.parsers.github_actions import parse_github
from app.parsers.gitlab_ci import parse_gitlab
from app.parsers.jenkins import parse_jenkins
from app.parsers.models import Job, ParsedPipeline, Step
from app.parsers.yaml_loader import load_yaml_with_lines

__all__ = [
    "Job",
    "ParsedPipeline",
    "Step",
    "detect_provider",
    "parse_pipeline",
]


def parse_pipeline(content: str, requested: str = "auto") -> ParsedPipeline:
    if not content.strip():
        raise ValueError("Pipeline content is empty.")
    provider = detect_provider(content, requested)
    lines = content.splitlines()

    if provider == "jenkins":
        return parse_jenkins(content, lines)

    raw = load_yaml_with_lines(content)
    if raw is None:
        raise ValueError("The pipeline parsed to an empty document.")
    if not isinstance(raw, dict):
        raise ValueError("The pipeline must be a YAML mapping at the top level.")

    if provider == "gitlab_ci":
        return parse_gitlab(raw, lines, content)
    return parse_github(raw, lines, content)
