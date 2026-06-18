from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["fail", "warn", "pass", "info"]
PipelinePlatform = Literal["auto", "github_actions", "gitlab_ci", "jenkins"]


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1)
    platform: PipelinePlatform = "auto"
    project_name: str | None = None
    environment: str | None = None
    strict_mode: bool = False
    enabled_categories: list[str] | None = None


class PipelineJob(BaseModel):
    name: str
    stage: str | None = None
    runner: str | None = None
    steps: int = 0
    uses_secrets: bool = False


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    status: FindingStatus
    category: str
    location: str
    line: int | None = None
    description: str
    impact: str
    remediation: str
    safer_example: str | None = None
    confidence: float = 0.8
    references: list[str] = []


class AnalyzeResponse(BaseModel):
    score: int
    grade: str
    summary: str
    platform: str
    pipeline_name: str | None = None
    jobs: list[PipelineJob]
    findings: list[Finding]
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    recommended_next_steps: list[str]
    metadata: dict[str, Any]


class RuleInfo(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    description: str


class ExampleInfo(BaseModel):
    id: str
    title: str
    platform: str
    description: str
    content: str
