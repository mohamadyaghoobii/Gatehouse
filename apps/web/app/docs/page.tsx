const CATEGORIES = [
  ["Permissions", "Least-privilege tokens, write-all, id-token, scope creep."],
  ["Secrets", "Hardcoded credentials, echoed secrets, build-arg leaks, secret artifacts."],
  ["Supply Chain", "Unpinned actions, remote installers, untrusted registries, missing provenance."],
  ["Trigger Safety", "pull_request_target, unscoped branches, privileged scheduled runs."],
  ["Deployment Safety", "Approval gates, kubectl/terraform validation, unsafe SSH deploys."],
  ["Artifacts & Cache", "Broad paths, long retention, cache poisoning surface."],
  ["Runtime Scripts", "chmod 777, inline docker passwords, docker socket, privileged mode."],
  ["Reliability", "Job timeouts, concurrency control, test gate before deploy."]
];

const ENDPOINTS = [
  ["GET", "/health", "Liveness probe."],
  ["GET", "/ready", "Readiness probe with rule count and AI provider."],
  ["GET", "/api/rules", "Full rule catalog."],
  ["GET", "/api/examples", "Demo pipelines."],
  ["POST", "/api/analyze", "Analyze a pipeline and return score, findings, and metadata."],
  ["POST", "/api/ai/summarize", "Optional AI risk summary (off unless a provider is set)."],
  ["POST", "/api/ai/remediate", "Optional AI remediation for a finding."]
];

export default function DocsPage() {
  return (
    <>
      <div className="topbar">
        <div>
          <span className="kicker">Reference</span>
          <h1>Docs</h1>
          <p>How Gatehouse scores pipelines, what it checks, and how it plugs into a larger platform.</p>
        </div>
      </div>

      <div className="section" style={{ marginTop: 4 }}>
        <div className="card">
          <div className="card-head">
            <h2>Scoring model</h2>
          </div>
          <div className="card-body">
            <p style={{ color: "var(--muted)" }}>
              Every pipeline starts at <b style={{ color: "var(--text)" }}>100</b>. Each finding subtracts points weighted by severity
              (critical 28, high 18, medium 9, low 3) scaled by confidence. The score is floored at 0 and mapped to a letter grade
              A–F. The response also includes checks passed/failed, severity counts, and category counts so the score is fully
              explainable.
            </p>
          </div>
        </div>
      </div>

      <div className="section">
        <div className="section-head">
          <h2 style={{ fontSize: 15 }}>What it checks</h2>
        </div>
        <div className="example-grid">
          {CATEGORIES.map(([title, body]) => (
            <div className="example" key={title} style={{ cursor: "default" }}>
              <h3>{title}</h3>
              <p>{body}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="section">
        <div className="card rules-card">
          <div className="card-head">
            <h2>API endpoints</h2>
          </div>
          <div className="card-body">
            {ENDPOINTS.map(([method, path, desc]) => (
              <div className="rule-row" key={path} style={{ gridTemplateColumns: "70px 220px 1fr" }}>
                <span className="access read" style={{ justifySelf: "start" }}>
                  {method}
                </span>
                <code>{path}</code>
                <p style={{ color: "var(--muted)", fontSize: 13 }}>{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="section">
        <div className="card">
          <div className="card-head">
            <h2>OpsDeck integration</h2>
          </div>
          <div className="card-body">
            <p style={{ color: "var(--muted)" }}>
              The <code style={{ fontFamily: "var(--mono)", color: "var(--accent)" }}>/api/analyze</code> response is a stable,
              versioned schema (<code style={{ fontFamily: "var(--mono)", color: "var(--accent)" }}>schema_version</code>) containing
              the score breakdown, findings, permissions summary, and metadata. OpsDeck can ingest it as a module run result without
              knowing anything about Gatehouse internals.
            </p>
          </div>
        </div>
      </div>
    </>
  );
}
