from fastapi import APIRouter, HTTPException
from app.schemas import AnalyzeRequest, AnalyzeResponse, RuleInfo, ExampleInfo
from app.services.analyzer import analyze_pipeline
from app.services.examples import get_example, list_examples
from app.services.rules import RULES

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "gatehouse"}


@router.get("/ready")
def ready() -> dict[str, str]:
    return {"status": "ready"}


@router.get("/api/rules", response_model=list[RuleInfo])
def rules() -> list[RuleInfo]:
    return [RuleInfo(**item) for item in RULES]


@router.get("/api/examples", response_model=list[ExampleInfo])
def examples() -> list[ExampleInfo]:
    return list_examples()


@router.get("/api/examples/{example_id}", response_model=ExampleInfo)
def example(example_id: str) -> ExampleInfo:
    item = get_example(example_id)
    if not item:
        raise HTTPException(status_code=404, detail="Example not found")
    return item


@router.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    try:
        return analyze_pipeline(
            content=request.content,
            platform=request.platform,
            project_name=request.project_name,
            environment=request.environment,
            strict_mode=request.strict_mode,
            enabled_categories=request.enabled_categories,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
