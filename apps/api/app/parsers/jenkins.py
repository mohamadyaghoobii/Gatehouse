from __future__ import annotations

import re

from app.parsers.models import Job, ParsedPipeline, Step

_STAGE_RE = re.compile(r"stage\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
_SHELL_RE = re.compile(r"\b(sh|bat|powershell|pwsh)\b\s*[\(]?\s*(?P<q>['\"]{1,3})(?P<body>.*?)(?P=q)", re.S)
_AGENT_RE = re.compile(r"agent\s*\{?\s*(\w+)")


def _line_of_index(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def parse_jenkins(content: str, lines: list[str]) -> ParsedPipeline:
    jobs: list[Job] = []
    stage_positions = [(match.group(1), match.start()) for match in _STAGE_RE.finditer(content)]
    shell_steps = [
        (match.group("body").strip(), _line_of_index(content, match.start()))
        for match in _SHELL_RE.finditer(content)
    ]

    for order, (stage_name, start) in enumerate(stage_positions):
        end = stage_positions[order + 1][1] if order + 1 < len(stage_positions) else len(content)
        steps = [
            Step(index=index, name="sh", run=body, line=line)
            for index, (body, line) in enumerate(
                (body, line) for body, line in shell_steps if start <= _char_index_for_line(content, line) < end
            )
        ]
        jobs.append(
            Job(
                name=stage_name,
                stage="stage",
                runner="jenkins",
                steps=steps,
                raw={"name": stage_name},
                line=_line_of_index(content, start),
            )
        )

    if not jobs and shell_steps:
        jobs.append(
            Job(
                name="pipeline",
                stage="stage",
                runner="jenkins",
                steps=[Step(index=index, name="sh", run=body, line=line) for index, (body, line) in enumerate(shell_steps)],
                raw={"name": "pipeline"},
                line=1,
            )
        )

    agent_match = _AGENT_RE.search(content)
    declarative = bool(re.search(r"\bpipeline\s*\{", content))
    return ParsedPipeline(
        provider="jenkins",
        name="Jenkinsfile",
        raw=content,
        jobs=jobs,
        lines=lines,
        text=content,
        notes={
            "agent": agent_match.group(1) if agent_match else None,
            "declarative": declarative,
            "has_input": "input " in content or "input(" in content,
            "has_post": re.search(r"\bpost\s*\{", content) is not None,
            "uses_withCredentials": "withCredentials" in content,
        },
    )


def _char_index_for_line(content: str, line: int) -> int:
    parts = content.split("\n")
    return sum(len(part) + 1 for part in parts[: line - 1])
