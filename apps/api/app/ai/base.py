from __future__ import annotations

from typing import Protocol

from app.schemas import AIResponse, AnalyzeResponse


class AIProvider(Protocol):
    name: str
    enabled: bool

    def summarize(self, analysis: AnalyzeResponse) -> AIResponse: ...

    def remediate(self, analysis: AnalyzeResponse, finding_id: str | None) -> AIResponse: ...
