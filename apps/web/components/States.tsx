export function EmptyState() {
  return (
    <div className="card">
      <div className="empty">
        <div className="icon">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M11 3 4 7v6c0 5 3 7 7 9 4-2 7-4 7-9V7l-7-4z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
        </div>
        <strong>No analysis yet</strong>
        <p>Paste a pipeline or load an example, then run a review to see the risk score, findings, and remediation.</p>
      </div>
    </div>
  );
}

export function LoadingState() {
  return (
    <div className="result-stack">
      <div className="card" style={{ padding: 20 }}>
        <div className="loading-state" style={{ border: 0, padding: 16 }}>
          <div className="spinner" />
          <p>Reviewing pipeline…</p>
        </div>
      </div>
      <div className="card skeleton" style={{ height: 120 }} />
      <div className="card skeleton" style={{ height: 160 }} />
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="error-box">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none", marginTop: 1 }}>
        <circle cx="12" cy="12" r="10" />
        <path d="M12 8v4M12 16h.01" />
      </svg>
      <div>
        <strong style={{ display: "block", marginBottom: 4, color: "#ffd9de" }}>Analysis failed</strong>
        {message}
      </div>
    </div>
  );
}
