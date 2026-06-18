"use client";

import { useState } from "react";
import type { Finding } from "../lib/api";
import { SEVERITY_META } from "../lib/ui";
import { CopyButton } from "./CopyButton";

export function FindingCard({ finding, defaultOpen = false }: { finding: Finding; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const meta = SEVERITY_META[finding.severity];

  return (
    <article className={`finding ${open ? "open" : ""}`} style={{ ["--sev-color" as string]: meta.color }}>
      <div className="finding-head" onClick={() => setOpen((value) => !value)}>
        <span className="sev-badge" style={{ color: meta.color, background: meta.soft }}>
          {meta.label}
        </span>
        <div className="ft">
          <h3>{finding.title}</h3>
          <div className="meta">
            <span>{finding.category}</span>
            <span>
              <code>{finding.id}</code>
            </span>
            {finding.job ? <span>job: {finding.job}</span> : null}
            <span>{finding.location}{finding.line ? ` · line ${finding.line}` : ""}</span>
            <span>{Math.round(finding.confidence * 100)}% confidence</span>
          </div>
        </div>
        <span className="caret" />
      </div>

      {open ? (
        <div className="finding-body">
          <p style={{ color: "var(--muted)", fontSize: 13 }}>{finding.description}</p>
          <div className="fb-grid">
            <div className="fb-block">
              <div className="lbl">Impact</div>
              <p>{finding.impact}</p>
            </div>
            <div className="fb-block">
              <div className="lbl">Remediation</div>
              <p>{finding.remediation}</p>
            </div>
          </div>

          {finding.safer_example ? (
            <div className="snippet">
              <div className="snip-head">
                <span>Safer example</span>
                <CopyButton text={finding.safer_example} label="Copy snippet" />
              </div>
              <pre>{finding.safer_example}</pre>
            </div>
          ) : null}

          {finding.references.length ? (
            <div className="fb-block">
              <div className="lbl">References</div>
              <div className="ref-row">
                {finding.references.map((ref) => (
                  <a key={ref} href={ref} target="_blank" rel="noreferrer">
                    {new URL(ref).hostname.replace("www.", "")}
                  </a>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}
