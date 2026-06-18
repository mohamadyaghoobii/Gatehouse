import type { Severity } from "./api";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_META: Record<Severity, { label: string; color: string; soft: string }> = {
  critical: { label: "Critical", color: "var(--sev-critical)", soft: "var(--sev-critical-soft)" },
  high: { label: "High", color: "var(--sev-high)", soft: "var(--sev-high-soft)" },
  medium: { label: "Medium", color: "var(--sev-medium)", soft: "var(--sev-medium-soft)" },
  low: { label: "Low", color: "var(--sev-low)", soft: "var(--sev-low-soft)" },
  info: { label: "Info", color: "var(--sev-info)", soft: "var(--sev-info-soft)" }
};

export const PROVIDER_LABEL: Record<string, string> = {
  github_actions: "GitHub Actions",
  gitlab_ci: "GitLab CI",
  jenkins: "Jenkins",
  auto: "Auto detect"
};

export function providerLabel(value: string): string {
  return PROVIDER_LABEL[value] ?? value.replace(/_/g, " ");
}

export function gradeColor(grade: string): string {
  if (grade === "A") return "var(--sev-low)";
  if (grade === "B") return "var(--accent)";
  if (grade === "C") return "var(--sev-medium)";
  if (grade === "D") return "var(--sev-high)";
  return "var(--sev-critical)";
}

export function detectProvider(content: string): string {
  const text = content.toLowerCase();
  if (/^\s*pipeline\s*\{/m.test(content) || /\bstage\s*\(/.test(content)) {
    if (!text.includes("runs-on")) return "jenkins";
  }
  if (/^\s*on\s*:/m.test(content) && /^\s*jobs\s*:/m.test(content)) return "github_actions";
  if (/^\s*stages\s*:/m.test(content) || /^\s*script\s*:/m.test(content)) return "gitlab_ci";
  return "github_actions";
}
