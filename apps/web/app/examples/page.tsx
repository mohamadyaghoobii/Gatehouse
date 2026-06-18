"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { fetchExamples, type ExampleInfo } from "../../lib/api";
import { SEVERITY_META, providerLabel } from "../../lib/ui";

const RISK_COLOR: Record<string, { color: string; soft: string }> = {
  critical: SEVERITY_META.critical,
  high: SEVERITY_META.high,
  medium: SEVERITY_META.medium,
  low: SEVERITY_META.low
};

export default function ExamplesPage() {
  const [examples, setExamples] = useState<ExampleInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    fetchExamples()
      .then(setExamples)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load examples"));
  }, []);

  function open(example: ExampleInfo) {
    sessionStorage.setItem("gatehouse:example", JSON.stringify({ content: example.content, platform: example.platform }));
    router.push("/");
  }

  return (
    <>
      <div className="topbar">
        <div>
          <span className="kicker">Demo pipelines</span>
          <h1>Examples</h1>
          <p>Safe, realistic pipelines that show what Gatehouse flags. Open one to run it in the analyzer.</p>
        </div>
      </div>

      {error ? <div className="error-box">{error}</div> : null}

      <div className="example-grid">
        {examples.map((example) => {
          const risk = RISK_COLOR[example.risk] ?? SEVERITY_META.info;
          return (
            <button className="example" key={example.id} onClick={() => open(example)}>
              <div className="top">
                <span className="chip">{providerLabel(example.platform)}</span>
                <span className="risk" style={{ color: risk.color, background: risk.soft }}>
                  {example.risk}
                </span>
              </div>
              <h3>{example.title}</h3>
              <p>{example.description}</p>
              <span className="copy-btn" style={{ marginTop: "auto" }}>
                Open in analyzer →
              </span>
            </button>
          );
        })}
      </div>
    </>
  );
}
