"use client";

import { useEffect, useMemo, useState } from "react";
import { Editor } from "../components/Editor";
import { FindingCard } from "../components/FindingCard";
import { JobsCard, ResultPanel } from "../components/ResultPanel";
import { EmptyState, ErrorState, LoadingState } from "../components/States";
import {
  analyzePipeline,
  fetchExamples,
  summarizePipeline,
  type AIResult,
  type AnalyzeResult,
  type ExampleInfo,
  type Severity
} from "../lib/api";
import { SEVERITY_META, SEVERITY_ORDER, detectProvider, providerLabel } from "../lib/ui";

const STARTER = `name: risky-release
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
        run: curl -fsSL https://get.example.com/install.sh | bash
      - name: Deploy
        run: kubectl apply -f k8s/
`;

export default function AnalyzePage() {
  const [content, setContent] = useState(STARTER);
  const [platform, setPlatform] = useState("auto");
  const [examples, setExamples] = useState<ExampleInfo[]>([]);
  const [result, setResult] = useState<AnalyzeResult | null>(null);
  const [ai, setAi] = useState<AIResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [filter, setFilter] = useState<Severity | "all">("all");

  useEffect(() => {
    fetchExamples().then(setExamples).catch(() => setExamples([]));
    try {
      const pending = sessionStorage.getItem("gatehouse:example");
      if (pending) {
        const parsed = JSON.parse(pending) as { content: string; platform: string };
        setContent(parsed.content);
        setPlatform(parsed.platform);
        sessionStorage.removeItem("gatehouse:example");
      }
    } catch {
      /* ignore */
    }
  }, []);

  async function runAnalysis() {
    setLoading(true);
    setError(null);
    setAi(null);
    try {
      setResult(await analyzePipeline(content, platform));
      setFilter("all");
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  }

  async function runSummary() {
    setAiLoading(true);
    try {
      setAi(await summarizePipeline(content, platform));
    } catch (err) {
      setAi(null);
      setError(err instanceof Error ? err.message : "AI summary failed");
    } finally {
      setAiLoading(false);
    }
  }

  function loadExample(example: ExampleInfo) {
    setContent(example.content);
    setPlatform(example.platform);
    setResult(null);
    setAi(null);
    setError(null);
  }

  const detected = platform === "auto" ? detectProvider(content) : platform;

  const filtered = useMemo(() => {
    const findings = result?.findings ?? [];
    if (filter === "all") return findings;
    return findings.filter((finding) => finding.severity === filter);
  }, [result, filter]);

  return (
    <>
      <div className="topbar">
        <div>
          <span className="kicker">CI/CD security review</span>
          <h1>Analyze pipeline</h1>
          <p>Catch risky permissions, leaked secrets, supply chain gaps, and weak deploy gates before they reach production.</p>
        </div>
        <div className="topbar-actions">
          <div className="select">
            <select value={platform} onChange={(event) => setPlatform(event.target.value)}>
              <option value="auto">Auto detect</option>
              <option value="github_actions">GitHub Actions</option>
              <option value="gitlab_ci">GitLab CI</option>
              <option value="jenkins">Jenkins</option>
            </select>
          </div>
          <button className="btn btn-primary" onClick={runAnalysis} disabled={loading || !content.trim()}>
            {loading ? "Analyzing…" : "Analyze pipeline"}
          </button>
        </div>
      </div>

      <div className="workspace">
        <div className="card editor-card">
          <div className="editor-toolbar">
            <div className="left">
              <span className="chip">
                <span className="chip-dot" style={{ background: "var(--accent)" }} />
                {providerLabel(detected)}
              </span>
            </div>
            <div className="select">
              <select
                value=""
                onChange={(event) => {
                  const example = examples.find((item) => item.id === event.target.value);
                  if (example) loadExample(example);
                }}
              >
                <option value="">Load sample…</option>
                {examples.map((example) => (
                  <option key={example.id} value={example.id}>
                    {example.title}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <Editor value={content} onChange={setContent} />
          <div className="editor-foot">
            <span>{content.split("\n").length} lines · {content.length} chars</span>
            <button className="btn btn-ghost" onClick={runSummary} disabled={aiLoading || !content.trim()}>
              {aiLoading ? "Summarizing…" : "AI summary"}
            </button>
          </div>
        </div>

        <div>
          {loading ? <LoadingState /> : null}
          {!loading && error ? <ErrorState message={error} /> : null}
          {!loading && !error && result ? <ResultPanel result={result} /> : null}
          {!loading && !error && !result ? <EmptyState /> : null}
        </div>
      </div>

      {ai ? (
        <div className="section">
          <div className="card ai-panel">
            <div className="card-head">
              <div>
                <h2>{ai.title}</h2>
                <div className="sub">{ai.enabled ? `Generated by ${ai.provider}` : "AI assistant disabled"}</div>
              </div>
              <button className="copy-btn" onClick={() => setAi(null)}>
                Dismiss
              </button>
            </div>
            <div className="card-body">
              {ai.enabled ? (
                <pre>{ai.content}</pre>
              ) : (
                <div className="ai-disabled">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none" }}>
                    <circle cx="12" cy="12" r="10" />
                    <path d="M12 16v-4M12 8h.01" />
                  </svg>
                  <span>{ai.content}</span>
                </div>
              )}
              {ai.disclaimer ? <p style={{ color: "var(--faint)", fontSize: 12, marginTop: 12 }}>{ai.disclaimer}</p> : null}
            </div>
          </div>
        </div>
      ) : null}

      {result && result.jobs.length ? (
        <div className="section">
          <JobsCard result={result} />
        </div>
      ) : null}

      {result ? (
        <div className="section">
          <div className="section-head">
            <h2>Findings</h2>
            <div className="filter-row">
              <button className={`filter-pill ${filter === "all" ? "active" : ""}`} onClick={() => setFilter("all")}>
                All {result.findings.length}
              </button>
              {SEVERITY_ORDER.map((severity) =>
                result.severity_counts[severity] ? (
                  <button
                    key={severity}
                    className={`filter-pill ${filter === severity ? "active" : ""}`}
                    onClick={() => setFilter(severity)}
                    style={filter === severity ? { color: SEVERITY_META[severity].color } : undefined}
                  >
                    {SEVERITY_META[severity].label} {result.severity_counts[severity]}
                  </button>
                ) : null
              )}
            </div>
          </div>
          {filtered.length ? (
            <div className="finding-list">
              {filtered.map((finding, index) => (
                <FindingCard key={`${finding.id}-${index}`} finding={finding} defaultOpen={index === 0 && filter === "all"} />
              ))}
            </div>
          ) : (
            <div className="card">
              <div className="empty">
                <strong>No findings in this view</strong>
                <p>{result.findings.length ? "No findings match the selected severity." : "This pipeline passed every enabled check. Nicely hardened."}</p>
              </div>
            </div>
          )}
        </div>
      ) : null}
    </>
  );
}
