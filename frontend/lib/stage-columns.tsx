"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { Badge } from "@/components/ui/badge";
import { KvList } from "@/components/ui/kv-list";
import { TagList } from "@/components/ui/tag";
import { cn } from "@/lib/utils";
import type { TableBlock } from "@/lib/stage-tables";

type Row = Record<string, unknown>;
type Cols = ColumnDef<Row>[];

function mono(value: unknown, className = "") {
  return <span className={cn("font-mono text-[13px] font-medium text-white truncate block", className)}>{String(value ?? "—")}</span>;
}

function get(row: Row, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, key) => (acc && typeof acc === "object" ? (acc as Row)[key] : undefined), row);
}

function ruleName(checkId: string): string {
  const parts = checkId.split(".");
  return parts[parts.length - 1] ?? checkId;
}

/** Shared by Stage 2 (full Semgrep scan) and Stage 3 (the subset of those
 * findings that landed in recently-modified files) - both render the exact
 * same SemgrepFinding shape from server/schemas.py. */
export const semgrepFindingsColumns: Cols = [
  {
    accessorKey: "severity",
    header: "severity",
    cell: (i) => <Badge value={i.getValue()}>{String(i.getValue())}</Badge>,
  },
  {
    accessorKey: "finding_id",
    header: "rule",
    meta: { width: 260 },
    cell: (i) => {
      const checkId = String(i.getValue());
      return (
        <span className="font-mono text-[13px] font-medium text-white truncate block" title={checkId}>
          {ruleName(checkId)}
        </span>
      );
    },
  },
  {
    id: "location",
    header: "location",
    meta: { width: 280 },
    cell: (i) => {
      const row = i.row.original;
      return mono(`${row.file_path}:${row.line_number}`, "hover:text-brand-light cursor-default");
    },
  },
  {
    accessorKey: "message",
    header: "finding",
    meta: { width: 360 },
    cell: (i) => <span className="text-[13px] text-slate-300">{String(i.getValue())}</span>,
  },
  {
    accessorKey: "cwe",
    header: "cwe",
    meta: { width: 180 },
    cell: (i) => <TagList items={(i.getValue() as string[]) ?? []} />,
  },
];

/** Stage 7's compliance violations - mapped findings from Stage 2/5/6 onto
 * OWASP Top 10 / SOC 2 controls (see server/compliance_engine.py). */
export const complianceViolationColumns: Cols = [
  {
    accessorKey: "severity",
    header: "severity",
    cell: (i) => <Badge value={i.getValue()}>{String(i.getValue())}</Badge>,
  },
  {
    id: "control",
    header: "control",
    meta: { width: 220 },
    cell: (i) => {
      const row = i.row.original;
      return (
        <div>
          <span className="font-mono text-[13px] font-medium text-white block">{String(row.control_id)}</span>
          <span className="text-[11px] text-slate-500">{String(row.framework)}</span>
        </div>
      );
    },
  },
  {
    accessorKey: "summary",
    header: "violation",
    meta: { width: 380 },
    cell: (i) => <span className="text-[13px] text-slate-300">{String(i.getValue())}</span>,
  },
  {
    id: "location",
    header: "location",
    meta: { width: 240 },
    cell: (i) => {
      const row = i.row.original;
      return row.file_path ? mono(`${row.file_path}:${row.line_number ?? "?"}`) : mono(`stage ${row.source_stage}`);
    },
  },
  {
    accessorKey: "timestamp",
    header: "detected",
    meta: { width: 170 },
    cell: (i) => mono(String(i.getValue()).replace("T", " ").slice(0, 19)),
  },
];

const stage5SbomComponents: Cols = [
  { accessorKey: "type", header: "type", cell: (i) => mono(i.getValue()) },
  { accessorKey: "name", header: "name", cell: (i) => mono(i.getValue(), "font-semibold") },
  { accessorKey: "version", header: "version", cell: (i) => mono(i.getValue()) },
  { accessorKey: "purl", header: "purl", meta: { width: 240 }, cell: (i) => mono(i.getValue()) },
  {
    id: "licenses",
    header: "licenses",
    meta: { width: 180 },
    cell: (i) => {
      const raw = (i.row.original.licenses as Array<Record<string, unknown>> | undefined) ?? [];
      const names = raw.map((l) => {
        const lic = (l.license ?? l) as Record<string, unknown>;
        return String(lic.id ?? lic.name ?? "license");
      });
      return <TagList items={names} />;
    },
  },
  {
    id: "hashes",
    header: "hashes",
    cell: (i) => {
      const raw = (i.row.original.hashes as unknown[] | undefined) ?? [];
      return mono(raw.length ? `${raw.length} hash(es)` : "—");
    },
  },
];

/** Stage 8's full dependency/SBOM list (see server/supply_chain_monitor.py). */
export const supplyChainDependencyColumns: Cols = [
  {
    accessorKey: "verified",
    header: "verified",
    cell: (i) => <Badge level={i.getValue() ? "low" : "medium"}>{i.getValue() ? "verified" : "unpinned"}</Badge>,
  },
  { accessorKey: "ecosystem", header: "ecosystem", cell: (i) => mono(i.getValue()) },
  { accessorKey: "name", header: "package", meta: { width: 220 }, cell: (i) => mono(i.getValue(), "font-semibold") },
  { accessorKey: "version", header: "version", cell: (i) => mono(i.getValue()) },
  { accessorKey: "purl", header: "purl", meta: { width: 280 }, cell: (i) => mono(i.getValue()) },
  {
    accessorKey: "sha256",
    header: "sha-256",
    meta: { width: 160 },
    cell: (i) => mono(String(i.getValue()).slice(0, 16) + "…"),
  },
];

/** stageNum -> tableLabel (from lib/stage-tables.ts) -> explicit columns.
 * Anything not listed here falls back to DataGrid's auto-derived columns. */
const CUSTOM_COLUMNS: Record<number, Record<string, Cols>> = {
  5: { "slsa.sbom.components": stage5SbomComponents },
};

export function getCustomColumns(stageNum: number, tableLabel: string): Cols | undefined {
  return CUSTOM_COLUMNS[stageNum]?.[tableLabel];
}

/** Stage 8's API surface (spec.operations) is a dict keyed by operation_id,
 * not an array, so the generic array-walking collectTables() never surfaces
 * it as a table - synthesize it explicitly here. */
export function getExtraTables(stageNum: number, data: unknown): TableBlock[] {
  if (stageNum !== 8) return [];
  const operations = (data as Record<string, unknown> | undefined)?.["spec"] as Record<string, unknown> | undefined;
  const ops = operations?.["operations"] as Record<string, Record<string, unknown>> | undefined;
  if (!ops || Object.keys(ops).length === 0) return [];
  return [{ label: "spec.operations", rows: Object.values(ops) }];
}
