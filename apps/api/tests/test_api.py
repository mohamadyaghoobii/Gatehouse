from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_ready_reports_rules():
    response = client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["rules"] > 10


def test_rules_catalog():
    response = client.get("/api/rules")
    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 20
    assert {"id", "title", "category", "severity", "providers"} <= set(body[0])


def test_examples_list():
    response = client.get("/api/examples")
    assert response.status_code == 200
    ids = {item["id"] for item in response.json()}
    assert {"github-actions-risky", "gitlab-hardened", "jenkins-hardened"} <= ids


def test_example_not_found():
    assert client.get("/api/examples/does-not-exist").status_code == 404


def test_analyze_risky_github_actions():
    example = client.get("/api/examples/github-actions-risky").json()
    response = client.post("/api/analyze", json={"content": example["content"], "platform": "github_actions"})
    assert response.status_code == 200
    body = response.json()
    assert body["score"] < 60
    assert body["severity_counts"]["critical"] >= 1
    assert len(body["findings"]) >= 4
    assert body["score_breakdown"]["checks_failed"] >= 1


def test_analyze_hardened_scores_higher_than_risky():
    risky = client.post("/api/analyze", json={"content": client.get("/api/examples/github-actions-risky").json()["content"]}).json()
    hardened = client.post("/api/analyze", json={"content": client.get("/api/examples/github-actions-hardened").json()["content"]}).json()
    assert hardened["score"] > risky["score"]
    assert hardened["score"] >= 90
    assert hardened["metadata"]["jobs_analyzed"] == 2


def test_analyze_invalid_yaml_returns_422():
    response = client.post("/api/analyze", json={"content": "name: [unclosed", "platform": "github_actions"})
    assert response.status_code == 422


def test_analyze_category_filter():
    example = client.get("/api/examples/github-actions-risky").json()
    response = client.post(
        "/api/analyze",
        json={"content": example["content"], "enabled_categories": ["Secrets"]},
    )
    body = response.json()
    assert body["findings"]
    assert {finding["category"] for finding in body["findings"]} == {"Secrets"}


def test_pull_request_target_is_detected():
    example = client.get("/api/examples/github-actions-deploy-risky").json()
    body = client.post("/api/analyze", json={"content": example["content"]}).json()
    assert "pull_request_target" in body["triggers"]
    assert any(finding["id"] == "TRIG-PR-TARGET" for finding in body["findings"])


def test_ai_disabled_by_default():
    example = client.get("/api/examples/github-actions-risky").json()
    response = client.post("/api/ai/summarize", json={"content": example["content"]})
    assert response.status_code == 200
    assert response.json()["enabled"] is False
