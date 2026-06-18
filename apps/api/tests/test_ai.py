from app.ai import get_provider
from app.analysis import analyze_pipeline
from app.services.examples import get_example


def _analysis():
    example = get_example("github-actions-risky")
    return analyze_pipeline(example.content, example.platform)


def test_none_provider_is_disabled():
    provider = get_provider("none")
    response = provider.summarize(_analysis())
    assert response.enabled is False


def test_deterministic_summary_is_useful():
    provider = get_provider("deterministic")
    response = provider.summarize(_analysis())
    assert response.enabled is True
    assert "score" in response.content.lower()
    assert response.disclaimer


def test_deterministic_remediation_targets_finding():
    analysis = _analysis()
    provider = get_provider("deterministic")
    target = analysis.findings[0]
    response = provider.remediate(analysis, target.id)
    assert target.title in response.title
    assert "How to fix" in response.content
