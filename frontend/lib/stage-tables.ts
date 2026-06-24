/** Stage payloads are heterogeneous JSON owned by 9 different stage engines
 * (see server/schemas.py for the rationale). Rather than hand-build a
 * bespoke table per stage, walk the response and surface every array of
 * objects as its own grid, with the rest shown as raw JSON for full fidelity. */

export interface TableBlock {
  label: string;
  rows: Record<string, unknown>[];
  severityColumn?: string;
}

const SEVERITY_CANDIDATES = [
  "severity",
  "severity_band",
  "trust_category",
  "classification",
  "confidence",
  "decision_action",
  "should_mitigate",
  "policy_action",
];

function isPlainObjectArray(value: unknown): value is Record<string, unknown>[] {
  return Array.isArray(value) && value.length > 0 && value.every((v) => v !== null && typeof v === "object" && !Array.isArray(v));
}

function detectSeverityColumn(rows: Record<string, unknown>[]): string | undefined {
  const keys = new Set(Object.keys(rows[0] ?? {}));
  return SEVERITY_CANDIDATES.find((c) => keys.has(c));
}

export function collectTables(data: unknown, prefix = "", depth = 3): TableBlock[] {
  if (depth < 0 || data === null || typeof data !== "object") return [];

  const blocks: TableBlock[] = [];

  if (isPlainObjectArray(data)) {
    blocks.push({ label: prefix || "data", rows: data, severityColumn: detectSeverityColumn(data) });
    return blocks;
  }

  if (Array.isArray(data)) return blocks;

  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    const label = prefix ? `${prefix}.${key}` : key;
    if (isPlainObjectArray(value)) {
      blocks.push({ label, rows: value, severityColumn: detectSeverityColumn(value) });
    } else if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      blocks.push(...collectTables(value, label, depth - 1));
    }
  }
  return blocks;
}

export function topLevelStrings(data: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(data)) {
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out[key] = String(value);
    }
  }
  return out;
}
