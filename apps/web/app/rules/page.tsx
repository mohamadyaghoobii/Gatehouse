"use client";

import { useEffect, useMemo, useState } from "react";
import { fetchRules, type RuleInfo } from "../../lib/api";
import { SEVERITY_META, providerLabel } from "../../lib/ui";

export default function RulesPage() {
  const [rules, setRules] = useState<RuleInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState<string>("all");

  useEffect(() => {
    fetchRules()
      .then(setRules)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load rules"));
  }, []);

  const categories = useMemo(() => Array.from(new Set(rules.map((rule) => rule.category))).sort(), [rules]);
  const visible = active === "all" ? rules : rules.filter((rule) => rule.category === active);
  const grouped = useMemo(() => {
    const map = new Map<string, RuleInfo[]>();
    for (const rule of visible) {
      const list = map.get(rule.category) ?? [];
      list.push(rule);
      map.set(rule.category, list);
    }
    return Array.from(map.entries());
  }, [visible]);

  return (
    <>
      <div className="topbar">
        <div>
          <span className="kicker">Detection catalog</span>
          <h1>Rules</h1>
          <p>{rules.length} checks across permissions, secrets, supply chain, triggers, deployment, runtime, and reliability.</p>
        </div>
      </div>

      {error ? <div className="error-box">{error}</div> : null}

      <div className="filter-row" style={{ marginBottom: 16 }}>
        <button className={`filter-pill ${active === "all" ? "active" : ""}`} onClick={() => setActive("all")}>
          All
        </button>
        {categories.map((category) => (
          <button key={category} className={`filter-pill ${active === category ? "active" : ""}`} onClick={() => setActive(category)}>
            {category}
          </button>
        ))}
      </div>

      {grouped.map(([category, items]) => (
        <div className="section" key={category} style={{ marginTop: 18 }}>
          <div className="section-head">
            <h2 style={{ fontSize: 15 }}>{category}</h2>
            <span className="chip">{items.length}</span>
          </div>
          <div className="card rules-card">
            <div className="card-body">
              {items.map((rule) => {
                const meta = SEVERITY_META[rule.severity];
                return (
                  <div className="rule-row" key={rule.id}>
                    <div>
                      <code>{rule.id}</code>
                      <div className="rule-cat">{rule.providers.map(providerLabel).join(", ")}</div>
                    </div>
                    <div className="rt">
                      <strong>{rule.title}</strong>
                      <p>{rule.description}</p>
                    </div>
                    <span className="sev-badge" style={{ color: meta.color, background: meta.soft }}>
                      {meta.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ))}
    </>
  );
}
