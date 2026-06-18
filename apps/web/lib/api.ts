export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "fail" | "warn" | "pass" | "info";

export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  category: string;
  provider: string;
  job?: string | null;
  field_path?: string | null;
  location: string;
  line?: number | null;
  description: string;
  impact: string;
  remediation: string;
  safer_example?: string | null;
  confidence: number;
  references: string[];
};

export type PipelineJob = {
  name: string;
  stage?: string | null;
  runner?: string | null;
  steps: number;
  uses_secrets: boolean;
  line?: number | null;
};

export type PermissionEntry = { scope: string; access: string };

export type ScoreBreakdown = {
  score: number;
  grade: string;
  explanation: string;
  checks_passed: number;
  checks_failed: number;
};

export type AnalyzeResult = {
  schema_version: string;
  score: number;
  grade: string;
  score_breakdown: ScoreBreakdown;
  summary: string;
  provider: string;
  platform: string;
  pipeline_name?: string | null;
  triggers: string[];
  stages: string[];
  jobs: PipelineJob[];
  permissions_summary: PermissionEntry[];
  secret_exposure_count: number;
  findings: Finding[];
  severity_counts: Record<Severity, number>;
  category_counts: Record<string, number>;
  recommended_next_steps: string[];
  metadata: Record<string, unknown>;
};

export type ExampleInfo = {
  id: string;
  title: string;
  platform: string;
  description: string;
  risk: string;
  content: string;
};

export type RuleInfo = {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  providers: string[];
  description: string;
};

export type AIResult = {
  provider: string;
  enabled: boolean;
  title: string;
  content: string;
  disclaimer?: string | null;
};

const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

async function asJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch {
      /* keep default */
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

export async function fetchExamples(): Promise<ExampleInfo[]> {
  return asJson(await fetch(`${baseUrl}/api/examples`, { cache: "no-store" }));
}

export async function fetchRules(): Promise<RuleInfo[]> {
  return asJson(await fetch(`${baseUrl}/api/rules`, { cache: "no-store" }));
}

export async function analyzePipeline(content: string, platform: string): Promise<AnalyzeResult> {
  return asJson(
    await fetch(`${baseUrl}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, platform })
    })
  );
}

export async function summarizePipeline(content: string, platform: string): Promise<AIResult> {
  return asJson(
    await fetch(`${baseUrl}/api/ai/summarize`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, platform })
    })
  );
}
