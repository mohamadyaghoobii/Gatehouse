from __future__ import annotations

from app.schemas import Finding, ScoreBreakdown

SEVERITY_WEIGHTS = {"critical": 28, "high": 18, "medium": 9, "low": 3, "info": 0}


def compute_score(findings: list[Finding], checks_run: int) -> ScoreBreakdown:
    score = 100
    deductions: dict[str, int] = {}
    for finding in findings:
        weight = int(round(SEVERITY_WEIGHTS[finding.severity] * max(0.4, min(1.0, finding.confidence))))
        score -= weight
        deductions[finding.severity] = deductions.get(finding.severity, 0) + weight
    score = max(0, min(100, score))

    failed = len({finding.id for finding in findings})
    passed = max(0, checks_run - failed)

    if not findings:
        explanation = "No risks were detected by the enabled checks, so the pipeline keeps a perfect score."
    else:
        parts = [f"-{points} {severity}" for severity, points in deductions.items() if points]
        explanation = "Started at 100, then applied " + ", ".join(parts) + f" for a final score of {score}."

    return ScoreBreakdown(
        score=score,
        grade=grade_for_score(score),
        explanation=explanation,
        checks_passed=passed,
        checks_failed=failed,
    )


def grade_for_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"
