/** Mirrors server/schemas.py - the FastAPI response shapes for the overview
 * and per-stage endpoints. */

export interface StageMeta {
  stage: number;
  key: string;
  title: string;
}

export interface StageHealth {
  stage: number;
  name: string;
  status: string;
  level: string;
  sub_metric: string;
  error?: string | null;
}

export interface MetricItem {
  label: string;
  value: string;
  level: string;
}

export interface RiskBreakdownRow {
  stage: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface FindingRow {
  stage: string;
  severity: string;
  summary: string;
}

export interface OverviewResponse {
  pipeline_label: string;
  pipeline_level: string;
  triage_total: number;
  triage_level: string;
  deepest_level: string;
  stage_health: StageHealth[];
  critical_metrics: MetricItem[];
  findings_volume: Record<string, number>;
  risk_breakdown: RiskBreakdownRow[];
  top_findings: FindingRow[];
  errors: Record<string, string>;
}

export interface RemediateResponse {
  status: "committed" | "not_auto_fixable" | "error";
  file_path?: string | null;
  line_number?: number | null;
  branch?: string | null;
  commit_hash?: string | null;
  summary?: string | null;
  diff?: string | null;
  reason?: string | null;
}

/** Per-stage payloads are heterogeneous (each stageN engine owns its own
 * shape); the API only guarantees the stable envelope fields documented in
 * server/schemas.py, so we type stage data generically here and let
 * StageGrid pick out list-shaped fields to render at runtime. */
export type StageData = Record<string, unknown>;

export const STAGE_TITLES: Record<number, string> = {
  1: "Pre-Commit Feature Collection",
  2: "Semgrep Vulnerability Scan",
  3: "Predictive Risk Analytics",
  4: "Automated Mitigation",
  5: "Entropy & SLSA Attestation",
  6: "Runtime Syscall Monitoring",
  7: "Compliance Tracking & Governance",
  8: "Supply Chain Security & SLSA Provenance",
  9: "Final Policy Gate & Executive Reporting",
};
