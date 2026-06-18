export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  status: string;
  category: string;
  location: string;
  line?: number | null;
  description: string;
  impact: string;
  remediation: string;
  safer_example?: string | null;
  confidence: number;
  references: string[];
};

export type ExampleInfo = {
  id: string;
  title: string;
  platform: string;
  description: string;
  content: string;
};

export type AnalyzeResult = {
  score: number;
  grade: string;
  summary: string;
  platform: string;
  pipeline_name?: string | null;
  jobs: Array<{ name: string; stage?: string | null; runner?: string | null; steps: number; uses_secrets: boolean }>;
  findings: Finding[];
  severity_counts: Record<Severity, number>;
  category_counts: Record<string, number>;
  recommended_next_steps: string[];
  metadata: Record<string, unknown>;
};

const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export async function fetchExamples(): Promise<ExampleInfo[]> {
  const response = await fetch(`${baseUrl}/api/examples`, { cache: "no-store" });
  if (!response.ok) throw new Error("Failed to load examples");
  return response.json();
}

export async function analyzePipeline(content: string, platform: string): Promise<AnalyzeResult> {
  const response = await fetch(`${baseUrl}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ content, platform })
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || "Analysis failed");
  }
  return response.json();
}
