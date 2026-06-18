# Integration contract

Gatehouse is a standalone product, but it is built to plug into the broader
**OpsDeck** DevSecOps platform without OpsDeck needing to know anything about the
internal rule engine. The contract is the `POST /api/analyze` response.

## Stable run schema

The response is versioned via `schema_version` (currently `1.0`). A consumer should
treat unknown fields as additive and pin behavior to the major version.

```jsonc
{
  "schema_version": "1.0",
  "score": 14,
  "grade": "F",
  "score_breakdown": {
    "score": 14,
    "grade": "F",
    "explanation": "Started at 100, then applied ...",
    "checks_passed": 28,
    "checks_failed": 9
  },
  "summary": "Reviewed 1 github actions job(s) ...",
  "provider": "github_actions",
  "platform": "github_actions",
  "pipeline_name": "risky-release",
  "triggers": ["push"],
  "stages": [],
  "jobs": [
    { "name": "deploy", "stage": "job", "runner": "ubuntu-latest", "steps": 3, "uses_secrets": true, "line": 7 }
  ],
  "permissions_summary": [{ "scope": "*", "access": "write" }],
  "secret_exposure_count": 1,
  "findings": [
    {
      "id": "SECRET-HARDCODED-VALUE",
      "title": "Hardcoded secret assigned to DEPLOY_TOKEN",
      "severity": "critical",
      "status": "fail",
      "category": "Secrets",
      "provider": "github_actions",
      "job": "deploy",
      "field_path": "DEPLOY_TOKEN",
      "location": "...",
      "line": 7,
      "description": "...",
      "impact": "...",
      "remediation": "...",
      "safer_example": "...",
      "confidence": 0.8,
      "references": []
    }
  ],
  "severity_counts": { "critical": 1, "high": 2, "medium": 4, "low": 0, "info": 2 },
  "category_counts": { "Secrets": 3, "Supply Chain": 2 },
  "recommended_next_steps": ["..."],
  "metadata": {
    "project_name": null,
    "repository": null,
    "environment": null,
    "jobs_analyzed": 1,
    "stages_analyzed": 0,
    "lines_analyzed": 11,
    "checks_run": 37,
    "strict_mode": false
  }
}
```

## Field guarantees

- `severity` is one of `critical | high | medium | low | info`.
- `status` is one of `fail | warn | pass | info`.
- `category` is one of the nine fixed categories (see the Rules page).
- `id` is stable per rule and safe to use as a dedupe key together with `job` and `line`.
- `score` is always `0..100`; `grade` is `A..F`.

## How OpsDeck ingests a run

1. OpsDeck sends pipeline text plus optional `repository`, `environment`, and
   `project_name` to `POST /api/analyze`.
2. The response is stored as a **module run** keyed by `(repository, provider, commit)`.
3. OpsDeck rolls up `severity_counts` and `score` across modules
   (Podscope, Dockyard, Gatehouse) into a single posture view.

## Future connectors (not built here)

- GitHub / GitLab merge-request comment writer.
- SARIF export for code scanning dashboards.
- Webhook push of completed runs to the OpsDeck ingestion endpoint.
