/** Mirrors server/risk.py - keep the vocabulary in sync if it changes there. */

export type RiskLevel = "neutral" | "low" | "medium" | "high" | "critical";

export const LEVEL_RANK: Record<RiskLevel, number> = {
  neutral: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Mirrors the Badge component's Tailwind palette (red-500/amber-500/
 * emerald-400/blue-400) for non-Tailwind contexts like Recharts fills and
 * inline severity-text coloring. */
export const LEVEL_COLOR: Record<RiskLevel, string> = {
  neutral: "#60A5FA", // blue-400
  low: "#34D399", // emerald-400
  medium: "#F59E0B", // amber-500
  high: "#EF4444", // red-500
  critical: "#EF4444", // red-500
};

const VALUE_TO_LEVEL: Record<string, RiskLevel> = {
  critical: "critical", p0: "critical", blocked: "critical", block: "critical",
  quarantine_and_terminate: "critical", lockdown: "critical", fail: "critical", false: "critical",
  high: "high", p1: "high", quarantine: "high", quarantined: "high",
  elevated_alert: "high", elevated: "high", risk: "high", denied: "high",
  medium: "medium", moderate: "medium", p2: "medium", review: "medium", caution: "medium",
  low: "low", p3: "low", allow: "low", allowed: "low", trusted: "low",
  log: "low", pass: "low", true: "low", valid: "low", ok: "low", operational: "low",
  skip: "low", mitigate: "high",
};

export function levelFor(value: unknown): RiskLevel {
  if (value === null || value === undefined) return "neutral";
  if (typeof value === "boolean") return value ? "low" : "critical";
  return VALUE_TO_LEVEL[String(value).trim().toLowerCase()] ?? "neutral";
}

export function colorFor(value: unknown): string {
  return LEVEL_COLOR[levelFor(value)];
}

export function deepestLevel(values: unknown[]): RiskLevel {
  const levels = values.filter((v) => v !== null && v !== undefined).map(levelFor);
  if (levels.length === 0) return "neutral";
  return levels.reduce((deepest, lvl) => (LEVEL_RANK[lvl] > LEVEL_RANK[deepest] ? lvl : deepest), "neutral" as RiskLevel);
}
