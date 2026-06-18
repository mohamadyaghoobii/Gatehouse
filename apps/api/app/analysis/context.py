from __future__ import annotations

from dataclasses import dataclass, field

from app.parsers import ParsedPipeline
from app.schemas import Finding, Severity

_FAIL_SEVERITIES = {"critical", "high", "medium"}


@dataclass
class AnalysisContext:
    pipeline: ParsedPipeline
    strict_mode: bool = False
    repository: str | None = None
    environment: str | None = None
    checks_run: set[str] = field(default_factory=set)

    @property
    def provider(self) -> str:
        return self.pipeline.provider

    @property
    def text(self) -> str:
        return self.pipeline.text

    def find_line(self, *needles: str) -> int | None:
        for needle in needles:
            compact = (needle or "").strip()
            if not compact:
                continue
            for index, line in enumerate(self.pipeline.lines, start=1):
                if compact in line:
                    return index
        return None

    def finding(
        self,
        *,
        id: str,
        title: str,
        severity: Severity,
        category: str,
        description: str,
        impact: str,
        remediation: str,
        location: str,
        job: str | None = None,
        field_path: str | None = None,
        line: int | None = None,
        safer_example: str | None = None,
        confidence: float = 0.82,
        references: list[str] | None = None,
        status: str | None = None,
    ) -> Finding:
        resolved_status = status or ("fail" if severity in _FAIL_SEVERITIES else "warn")
        return Finding(
            id=id,
            title=title,
            severity=severity,
            status=resolved_status,
            category=category,
            provider=self.provider,
            job=job,
            field_path=field_path,
            location=location,
            line=line,
            description=description,
            impact=impact,
            remediation=remediation,
            safer_example=safer_example,
            confidence=confidence,
            references=references or [],
        )
