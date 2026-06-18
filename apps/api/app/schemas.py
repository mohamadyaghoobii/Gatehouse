from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["fail", "warn", "pass", "info"]
PipelinePlatform = Literal["auto", "github_actions", "gitlab_ci", "jenkins"]


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, description="Raw pipeline definition text.")
    platform: PipelinePlatform = "auto"
    project_name: str | None = None
    repository: str | None = None
    environment: str | None = None
    strict_mode: bool = False
    enabled_categories: list[str] | None = None


class PipelineJob(BaseModel):
    name: str
    stage: str | None = None
    runner: str | None = None
    steps: int = 0
    uses_secrets: bool = False
    line: int | None = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    status: FindingStatus
    category: str
    provider: str
    job: str | None = None
    field_path: str | None = None
    location: str
    line: int | None = None
    description: str
    impact: str
    remediation: str
    safer_example: str | None = None
    confidence: float = 0.8
    references: list[str] = Field(default_factory=list)


class PermissionEntry(BaseModel):
    scope: str
    access: str


class ScoreBreakdown(BaseModel):
    score: int
    grade: str
    explanation: str
    checks_passed: int
    checks_failed: int


class AnalyzeResponse(BaseModel):
    schema_version: str = "1.0"
    score: int
    grade: str
    score_breakdown: ScoreBreakdown
    summary: str
    provider: str
    platform: str
    pipeline_name: str | None = None
    triggers: list[str] = Field(default_factory=list)
    stages: list[str] = Field(default_factory=list)
    jobs: list[PipelineJob]
    permissions_summary: list[PermissionEntry] = Field(default_factory=list)
    secret_exposure_count: int = 0
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
    providers: list[str]
    description: str


class ExampleInfo(BaseModel):
    id: str
    title: str
    platform: str
    description: str
    risk: str
    content: str


class AISummaryRequest(BaseModel):
    content: str = Field(min_length=1)
    platform: PipelinePlatform = "auto"


class AIRemediateRequest(BaseModel):
    content: str = Field(min_length=1)
    platform: PipelinePlatform = "auto"
    finding_id: str | None = None


class AIResponse(BaseModel):
    provider: str
    enabled: bool
    title: str
    content: str
    disclaimer: str | None = None
