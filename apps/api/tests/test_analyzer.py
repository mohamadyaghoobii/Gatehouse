from app.analysis import analyze_pipeline
from app.analysis.scoring import compute_score, grade_for_score
from app.schemas import Finding


def _finding(severity: str, confidence: float = 1.0) -> Finding:
    return Finding(
        id="X",
        title="t",
        severity=severity,
        status="fail",
        category="Secrets",
        provider="github_actions",
        location="l",
        description="d",
        impact="i",
        remediation="r",
        confidence=confidence,
    )


def test_score_starts_at_100():
    breakdown = compute_score([], checks_run=10)
    assert breakdown.score == 100
    assert breakdown.grade == "A"
    assert breakdown.checks_passed == 10


def test_score_decreases_with_severity():
    breakdown = compute_score([_finding("critical")], checks_run=10)
    assert breakdown.score == 72
    assert breakdown.checks_failed == 1


def test_score_floor_is_zero():
    findings = [_finding("critical") for _ in range(20)]
    assert compute_score(findings, checks_run=20).score == 0


def test_grades():
    assert grade_for_score(95) == "A"
    assert grade_for_score(80) == "B"
    assert grade_for_score(65) == "C"
    assert grade_for_score(45) == "D"
    assert grade_for_score(10) == "F"


def test_hardcoded_secret_is_critical():
    content = """name: x
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      DEPLOY_TOKEN: real-hardcoded-token-value
    steps:
      - run: echo hi
"""
    result = analyze_pipeline(content, "github_actions")
    ids = {finding.id for finding in result.findings}
    assert "SECRET-HARDCODED-VALUE" in ids
    assert result.severity_counts["critical"] >= 1


def test_unpinned_action_detected():
    content = """name: x
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: third-party/action@v1
"""
    result = analyze_pipeline(content, "github_actions")
    assert any(finding.id == "SC-UNPINNED-ACTION" for finding in result.findings)


def test_sha_pinned_action_is_clean():
    content = """name: x
on: [push]
permissions:
  contents: read
concurrency:
  group: x
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        name: checkout
"""
    result = analyze_pipeline(content, "github_actions")
    assert not any(finding.id == "SC-UNPINNED-ACTION" for finding in result.findings)


def test_category_counts_only_present_categories():
    content = "name: x\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: echo hi\n"
    result = analyze_pipeline(content, "github_actions")
    assert all(count > 0 for count in result.category_counts.values())
