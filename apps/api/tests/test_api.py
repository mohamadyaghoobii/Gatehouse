from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_rules():
    response = client.get("/api/rules")
    assert response.status_code == 200
    assert len(response.json()) >= 5


def test_examples():
    response = client.get("/api/examples")
    assert response.status_code == 200
    assert any(item["id"] == "github-actions-risky" for item in response.json())


def test_analyze_risky_github_actions():
    example = client.get("/api/examples/github-actions-risky").json()
    response = client.post("/api/analyze", json={"content": example["content"], "platform": "github_actions"})
    assert response.status_code == 200
    body = response.json()
    assert body["score"] < 80
    assert body["severity_counts"]["critical"] >= 1
    assert len(body["findings"]) >= 3


def test_analyze_hardened_github_actions():
    example = client.get("/api/examples/github-actions-hardened").json()
    response = client.post("/api/analyze", json={"content": example["content"], "platform": "github_actions"})
    assert response.status_code == 200
    body = response.json()
    assert body["score"] >= 70
    assert body["metadata"]["jobs_analyzed"] == 2
