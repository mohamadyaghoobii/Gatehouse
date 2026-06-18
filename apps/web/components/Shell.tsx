export function Shell({ children }: { children: React.ReactNode }) {
  const items = ["Overview", "Analyze", "Rules", "Examples", "Findings", "Integrations"];
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brandMark">G</div>
          <div>
            <strong>Gatehouse</strong>
            <span>Pipeline review</span>
          </div>
        </div>
        <nav>
          {items.map((item) => (
            <a key={item} className={item === "Analyze" ? "active" : ""}>{item}</a>
          ))}
        </nav>
        <div className="sideCard">
          <span>OpsDeck ready</span>
          <strong>Stable JSON contract</strong>
          <p>Designed to export review results into a central DevSecOps control room.</p>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}
