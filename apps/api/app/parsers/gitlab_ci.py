from __future__ import annotations

from typing import Any

from app.parsers.models import Job, ParsedPipeline, Step
from app.parsers.yaml_loader import LineDict, line_of

RESERVED_KEYS = {
    "stages",
    "variables",
    "workflow",
    "include",
    "image",
    "services",
    "before_script",
    "after_script",
    "default",
    "cache",
    "pages",
}


def _script_steps(value: Any, kind: str) -> list[Step]:
    if value is None:
        return []
    commands = value if isinstance(value, list) else [value]
    return [Step(index=index, name=kind, run=str(command), line=line_of(value)) for index, command in enumerate(commands)]


def parse_gitlab(raw: dict[str, Any], lines: list[str], text: str) -> ParsedPipeline:
    jobs: list[Job] = []
    stages = raw.get("stages") if isinstance(raw.get("stages"), list) else []
    for name, value in raw.items():
        if name in RESERVED_KEYS or str(name).startswith(".") or not isinstance(value, dict):
            continue
        steps: list[Step] = []
        steps.extend(_script_steps(value.get("before_script"), "before_script"))
        steps.extend(_script_steps(value.get("script"), "script"))
        steps.extend(_script_steps(value.get("after_script"), "after_script"))
        for index, step in enumerate(steps):
            step.index = index
        jobs.append(
            Job(
                name=str(name),
                stage=str(value.get("stage")) if value.get("stage") is not None else None,
                runner=_tags(value.get("tags")),
                steps=steps,
                env=value.get("variables") if isinstance(value.get("variables"), dict) else {},
                environment=value.get("environment"),
                when=str(value.get("when")) if value.get("when") is not None else None,
                needs=value.get("needs") if isinstance(value.get("needs"), list) else [],
                raw=value,
                line=line_of(raw, name) if isinstance(raw, LineDict) else line_of(value),
            )
        )
    return ParsedPipeline(
        provider="gitlab_ci",
        name=None,
        raw=raw,
        jobs=jobs,
        lines=lines,
        text=text,
        stages=[str(stage) for stage in stages],
        variables=raw.get("variables") if isinstance(raw.get("variables"), dict) else {},
        notes={"global_image": raw.get("image"), "services": raw.get("services")},
    )


def _tags(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)
