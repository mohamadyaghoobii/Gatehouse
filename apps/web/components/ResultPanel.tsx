"use client";

import type { AnalyzeResult } from "../lib/api";
import { SEVERITY_META, SEVERITY_ORDER, gradeColor, providerLabel } from "../lib/ui";

function SeverityBar({ counts }: { counts: AnalyzeResult["severity_counts"] }) {
  const total = SEVERITY_ORDER.reduce((sum, key) => sum + (counts[key] || 0), 0);
  return (
    <div>
      <div className="sev-bar">
        {total === 0 ? (
          <span style={{ width: "100%", background: "var(--sev-low)" }} />
        ) : (
          SEVERITY_ORDER.map((key) =>
            counts[key] ? (
              <span
                key={key}
                style={{ width: `${(counts[key] / total) * 100}%`, background: SEVERITY_META[key].color }}
                title={`${SEVERITY_META[key].label}: ${counts[key]}`}
              />
            ) : null
          )
        )}
      </div>
      <div className="sev-legend">
        {SEVERITY_ORDER.map((key) => (
          <div className="item" key={key}>
            <span className="dot" style={{ background: SEVERITY_META[key].color }} />
            {SEVERITY_META[key].label} <b>{counts[key] || 0}</b>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ResultPanel({ result }: { result: AnalyzeResult }) {
  const grade = gradeColor(result.grade);
  return (
    <div className="result-stack">
      <div className="card score-card">
        <div className="ring" style={{ ["--val" as string]: result.score, ["--col" as string]: grade }}>
          <div>
            <div className="score-num">{result.score}</div>
            <div className="score-max">of 100</div>
          </div>
        </div>
        <div className="score-meta">
          <span className="grade" style={{ background: grade }}>
            {result.grade}
          </span>
          <p className="summary">{result.summary}</p>
          <p className="explain">{result.score_breakdown.explanation}</p>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h3>Severity breakdown</h3>
          <span className="chip">{result.findings.length} findings</span>
        </div>
        <div className="card-body">
          <SeverityBar counts={result.severity_counts} />
        </div>
      </div>

      <div className="card">
        <div className="card-body">
          <div className="metric-grid">
            <div className="metric">
              <div className="label">Provider</div>
              <div className="value sm">{providerLabel(result.provider)}</div>
            </div>
            <div className="metric">
              <div className="label">Jobs / Stages</div>
              <div className="value">
                {result.jobs.length}
                {result.stages.length ? ` · ${result.stages.length}` : ""}
              </div>
            </div>
            <div className="metric">
              <div className="label">Checks failed</div>
              <div className="value">{result.score_breakdown.checks_failed}</div>
            </div>
            <div className="metric">
              <div className="label">Secret exposure</div>
              <div className="value" style={{ color: result.secret_exposure_count ? "var(--sev-critical)" : "var(--sev-low)" }}>
                {result.secret_exposure_count}
              </div>
            </div>
          </div>
        </div>
      </div>

      {result.permissions_summary.length ? (
        <div className="card">
          <div className="card-head">
            <h3>Token permissions</h3>
          </div>
          <div className="card-body">
            {result.permissions_summary.map((entry) => (
              <div className="kv" key={entry.scope}>
                <span className="scope">{entry.scope}</span>
                <span className={`access ${entry.access.includes("write") ? "write" : "read"}`}>{entry.access}</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {result.recommended_next_steps.length ? (
        <div className="card">
          <div className="card-head">
            <h3>What to fix first</h3>
          </div>
          <div className="card-body">
            <ol className="next-steps">
              {result.recommended_next_steps.map((step, index) => (
                <li key={step}>
                  <span className="num">{index + 1}</span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function JobsCard({ result }: { result: AnalyzeResult }) {
  if (!result.jobs.length) return null;
  return (
    <div className="card">
      <div className="card-head">
        <h3>Pipeline jobs</h3>
        <span className="chip">{result.triggers.length ? `triggers: ${result.triggers.join(", ")}` : "no triggers"}</span>
      </div>
      <div className="card-body">
        <table className="jobs-table">
          <thead>
            <tr>
              <th>Job</th>
              <th>Stage</th>
              <th>Runner</th>
              <th>Steps</th>
              <th>Secrets</th>
            </tr>
          </thead>
          <tbody>
            {result.jobs.map((job) => (
              <tr key={job.name}>
                <td>
                  <span className="name">{job.name}</span>
                </td>
                <td className="tag">{job.stage || "—"}</td>
                <td className="tag">{job.runner || "—"}</td>
                <td>{job.steps}</td>
                <td>
                  <span className="access" style={{ color: job.uses_secrets ? "var(--sev-high)" : "var(--faint)", background: "transparent" }}>
                    {job.uses_secrets ? "yes" : "no"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
