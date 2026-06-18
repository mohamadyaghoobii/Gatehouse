from __future__ import annotations

from typing import Any

from app.parsers.models import Job, ParsedPipeline, Step
from app.parsers.yaml_loader import LineDict, line_of


def _normalize_triggers(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, dict):
        return [str(key) for key in value.keys()]
    return [str(value)]


def _step_from_raw(index: int, raw: Any) -> Step:
    if not isinstance(raw, dict):
        return Step(index=index, run=str(raw), line=line_of(raw))
    return Step(
        index=index,
        name=raw.get("name"),
        uses=raw.get("uses"),
        run=raw.get("run"),
        shell=raw.get("shell"),
        env=raw.get("env") if isinstance(raw.get("env"), dict) else {},
        with_args=raw.get("with") if isinstance(raw.get("with"), dict) else {},
        raw=raw,
        line=line_of(raw),
    )


def parse_github(raw: dict[str, Any], lines: list[str], text: str) -> ParsedPipeline:
    jobs_raw = raw.get("jobs") if isinstance(raw.get("jobs"), dict) else {}
    jobs: list[Job] = []
    for name, job in jobs_raw.items():
        if not isinstance(job, dict):
            continue
        steps_raw = job.get("steps") if isinstance(job.get("steps"), list) else []
        steps = [_step_from_raw(index, step) for index, step in enumerate(steps_raw)]
        jobs.append(
            Job(
                name=str(name),
                stage="job",
                runner=_stringify_runner(job.get("runs-on")),
                steps=steps,
                env=job.get("env") if isinstance(job.get("env"), dict) else {},
                permissions=job.get("permissions"),
                environment=job.get("environment"),
                needs=_as_list(job.get("needs")),
                timeout=job.get("timeout-minutes"),
                raw=job,
                line=line_of(jobs_raw, name) if isinstance(jobs_raw, LineDict) else line_of(job),
            )
        )
    return ParsedPipeline(
        provider="github_actions",
        name=raw.get("name"),
        raw=raw,
        jobs=jobs,
        lines=lines,
        text=text,
        triggers=_normalize_triggers(raw.get("on")),
        permissions=raw.get("permissions"),
        notes={"concurrency": "concurrency" in raw},
    )


def _stringify_runner(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return str(value.get("group") or value.get("labels") or value)
    return str(value)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]
