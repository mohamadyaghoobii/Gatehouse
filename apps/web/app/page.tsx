"use client";

import { useEffect, useMemo, useState } from "react";
import { Shell } from "../components/Shell";
import { MetricCard } from "../components/MetricCard";
import { FindingCard } from "../components/FindingCard";
import { analyzePipeline, fetchExamples, type AnalyzeResult, type ExampleInfo } from "../lib/api";

const fallbackPipeline = `name: risky-release
on:
  push:
    branches: [main]
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install deploy tool
        run: curl -fsSL https://example.com/install.sh | bash
      - name: Deploy
        run: kubectl apply -f k8s/
`;

export default function Home() {
  const [content, setContent] = useState(fallbackPipeline);
  const [platform, setPlatform] = useState("auto");
  const [examples, setExamples] = useState<ExampleInfo[]>([]);
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchExamples().then(setExamples).catch(() => setExamples([]));
  }, []);

  async function runAnalysis() {
    setLoading(true);
    setError(null);
    try {
      const data = await analyzePipeline(content, platform);
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  }

  function loadExample(item: ExampleInfo) {
    setContent(item.content);
    setPlatform(item.platform);
    setResult(null);
    setError(null);
  }

  const orderedFindings = useMemo(() => {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return [...(result?.findings || [])].sort((a, b) => order[a.severity] - order[b.severity]);
  }, [result]);

  return (
    <Shell>
      <section className="hero">
        <div>
          <span className="eyebrow">CI/CD guardrails before merge</span>
          <h1>Review pipelines before they become production risk.</h1>
          <p>Gatehouse checks GitHub Actions, GitLab CI, and Jenkins pipeline patterns for broad permissions, unpinned actions, leaked secrets, weak deployment gates, and unsafe shell execution.</p>
        </div>
        <div className="heroPanel">
          <span>Current module</span>
          <strong>Pipeline Auditor</strong>
          <p>Standalone now. OpsDeck connector later.</p>
        </div>
      </section>

      <section className="workspace">
        <div className="editorPanel">
          <div className="panelHeader">
            <div>
              <h2>Pipeline input</h2>
              <p>Paste workflow YAML or Jenkinsfile content.</p>
            </div>
            <select value={platform} onChange={(event) => setPlatform(event.target.value)}>
              <option value="auto">Auto detect</option>
              <option value="github_actions">GitHub Actions</option>
              <option value="gitlab_ci">GitLab CI</option>
              <option value="jenkins">Jenkins</option>
            </select>
          </div>
          <textarea value={content} onChange={(event) => setContent(event.target.value)} spellCheck={false} />
          <div className="actions">
            <button onClick={runAnalysis} disabled={loading}>{loading ? "Analyzing..." : "Analyze pipeline"}</button>
            <span>{content.split("\n").length} lines</span>
          </div>
          {error ? <div className="errorBox">{error}</div> : null}
        </div>

        <div className="resultPanel">
          {result ? (
            <>
              <div className="scoreRing">
                <span>Score</span>
                <strong>{result.score}</strong>
                <em>Grade {result.grade}</em>
              </div>
              <p className="summary">{result.summary}</p>
              <div className="metricGrid">
                <MetricCard label="Findings" value={result.findings.length} detail="Total issues detected" />
                <MetricCard label="Jobs" value={result.jobs.length} detail="Pipeline jobs reviewed" />
                <MetricCard label="Platform" value={result.platform.replace("_", " ")} detail="Detected pipeline type" />
              </div>
              <div className="counts">
                {Object.entries(result.severity_counts).map(([key, value]) => <span key={key}>{key}: {value}</span>)}
              </div>
            </>
          ) : (
            <div className="emptyState">
              <strong>No analysis yet</strong>
              <p>Run a review to see score, findings, and deployment guardrails.</p>
            </div>
          )}
        </div>
      </section>

      <section className="examples">
        <div className="sectionHeader">
          <h2>Examples</h2>
          <p>Load realistic pipelines to see how Gatehouse behaves.</p>
        </div>
        <div className="exampleGrid">
          {examples.map((item) => (
            <button key={item.id} onClick={() => loadExample(item)}>
              <span>{item.platform.replace("_", " ")}</span>
              <strong>{item.title}</strong>
              <p>{item.description}</p>
            </button>
          ))}
        </div>
      </section>

      <section className="findingsSection">
        <div className="sectionHeader">
          <h2>Findings</h2>
          <p>Grouped by severity with practical remediation.</p>
        </div>
        {orderedFindings.length ? <div className="findingList">{orderedFindings.map((finding, index) => <FindingCard key={`${finding.id}-${index}`} finding={finding} />)}</div> : <div className="emptyLine">Run an analysis to populate findings.</div>}
      </section>
    </Shell>
  );
}
