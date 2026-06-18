import type { Finding } from "../lib/api";

export function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className={`finding ${finding.severity}`}>
      <div className="findingTop">
        <div>
          <span className="pill">{finding.category}</span>
          <h3>{finding.title}</h3>
        </div>
        <span className="severity">{finding.severity}</span>
      </div>
      <p>{finding.description}</p>
      <div className="findingGrid">
        <div>
          <span>Impact</span>
          <p>{finding.impact}</p>
        </div>
        <div>
          <span>Remediation</span>
          <p>{finding.remediation}</p>
        </div>
      </div>
      {finding.safer_example ? <pre>{finding.safer_example}</pre> : null}
      <footer>{finding.location}{finding.line ? ` · line ${finding.line}` : ""}</footer>
    </article>
  );
}
