from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.ai import get_provider
from app.analysis import analyze_pipeline, rule_catalog
from app.core.settings import get_settings
from app.schemas import (
    AIRemediateRequest,
    AIResponse,
    AISummaryRequest,
    AnalyzeRequest,
    AnalyzeResponse,
    ExampleInfo,
    RuleInfo,
)
from app.services.examples import get_example, list_examples

router = APIRouter()


@router.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "gatehouse"}


@router.get("/ready", tags=["system"])
def ready() -> dict[str, object]:
    settings = get_settings()
    return {"status": "ready", "ai_provider": settings.ai_provider, "rules": len(rule_catalog())}


@router.get("/api/rules", response_model=list[RuleInfo], tags=["catalog"])
def rules() -> list[RuleInfo]:
    return [RuleInfo(**item) for item in rule_catalog()]


@router.get("/api/examples", response_model=list[ExampleInfo], tags=["catalog"])
def examples() -> list[ExampleInfo]:
    return list_examples()


@router.get("/api/examples/{example_id}", response_model=ExampleInfo, tags=["catalog"])
def example(example_id: str) -> ExampleInfo:
    item = get_example(example_id)
    if not item:
        raise HTTPException(status_code=404, detail="Example not found")
    return item


@router.post("/api/analyze", response_model=AnalyzeResponse, tags=["analysis"])
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    try:
        return analyze_pipeline(
            content=request.content,
            platform=request.platform,
            project_name=request.project_name,
            repository=request.repository,
            environment=request.environment,
            strict_mode=request.strict_mode,
            enabled_categories=request.enabled_categories,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/api/ai/summarize", response_model=AIResponse, tags=["ai"])
def ai_summarize(request: AISummaryRequest) -> AIResponse:
    analysis = _safe_analyze(request.content, request.platform)
    provider = get_provider(get_settings().ai_provider)
    return provider.summarize(analysis)


@router.post("/api/ai/remediate", response_model=AIResponse, tags=["ai"])
def ai_remediate(request: AIRemediateRequest) -> AIResponse:
    analysis = _safe_analyze(request.content, request.platform)
    provider = get_provider(get_settings().ai_provider)
    return provider.remediate(analysis, request.finding_id)


def _safe_analyze(content: str, platform: str) -> AnalyzeResponse:
    try:
        return analyze_pipeline(content=content, platform=platform)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
