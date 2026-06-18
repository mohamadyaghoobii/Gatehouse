from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
import yaml


@dataclass
class ParsedPipeline:
    platform: str
    name: str | None
    raw: Any
    jobs: list[dict[str, Any]]
    lines: list[str]


def detect_platform(content: str, requested: str = "auto") -> str:
    if requested != "auto":
        return requested
    text = content.lower()
    if "pipeline" in text and "agent" in text and "stages" in text and "jenkins" in text or "jenkinsfile" in text:
        return "jenkins"
    if "on:" in text and "jobs:" in text and ("runs-on" in text or "uses:" in text):
        return "github_actions"
    if "stages:" in text or "image:" in text and "script:" in text:
        return "gitlab_ci"
    if "node(" in text or "pipeline {" in text or "stage(" in text:
        return "jenkins"
    return "github_actions"


def parse_pipeline(content: str, requested: str = "auto") -> ParsedPipeline:
    platform = detect_platform(content, requested)
    lines = content.splitlines()
    if platform == "jenkins":
        return parse_jenkins(content, lines)
    try:
        raw = yaml.safe_load(content) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("Pipeline content must parse into a mapping")
    if platform == "gitlab_ci":
        return parse_gitlab(raw, lines)
    return parse_github(raw, lines)


def parse_github(raw: dict[str, Any], lines: list[str]) -> ParsedPipeline:
    jobs_raw = raw.get("jobs", {}) if isinstance(raw.get("jobs", {}), dict) else {}
    jobs = []
    for name, job in jobs_raw.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps", []) if isinstance(job.get("steps", []), list) else []
        jobs.append({
            "name": str(name),
            "stage": "job",
            "runner": str(job.get("runs-on", "")),
            "steps": len(steps),
            "raw": job,
        })
    return ParsedPipeline("github_actions", raw.get("name"), raw, jobs, lines)


def parse_gitlab(raw: dict[str, Any], lines: list[str]) -> ParsedPipeline:
    reserved = {"stages", "variables", "workflow", "include", "image", "services", "before_script", "after_script", "default", "cache"}
    jobs = []
    for name, value in raw.items():
        if name in reserved or not isinstance(value, dict):
            continue
        script = value.get("script", [])
        steps = len(script) if isinstance(script, list) else 1 if script else 0
        jobs.append({
            "name": str(name),
            "stage": str(value.get("stage", "job")),
            "runner": str(value.get("tags", "")),
            "steps": steps,
            "raw": value,
        })
    return ParsedPipeline("gitlab_ci", None, raw, jobs, lines)


def parse_jenkins(content: str, lines: list[str]) -> ParsedPipeline:
    names = re.findall(r"stage\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", content)
    jobs = [{"name": item, "stage": "stage", "runner": "jenkins", "steps": 0, "raw": {}} for item in names]
    return ParsedPipeline("jenkins", "Jenkinsfile", content, jobs, lines)


def find_line(lines: list[str], needle: str) -> int | None:
    compact = needle.strip()
    if not compact:
        return None
    for index, line in enumerate(lines, start=1):
        if compact in line:
            return index
    return None
