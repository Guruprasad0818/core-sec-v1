"use client";

import { useMemo } from "react";
import { ShieldAlert } from "lucide-react";
import { Card, CardSub, CardTitle, CardValue } from "@/components/ui/card";
import { TagList } from "@/components/ui/tag";
import { DataGrid } from "@/components/data-grid";
import { semgrepFindingsColumns } from "@/lib/stage-columns";
import type { StageData } from "@/lib/types";

interface SemgrepFinding {
  finding_id: string;
  severity: string;
  message: string;
  file_path: string;
  line_number: number;
  end_line: number;
  owasp: string[];
  cwe: string[];
}

type Row = Record<string, unknown>;

const COUNT_CARDS: { key: string; label: string; level: "critical" | "high" | "medium" | "low" }[] = [
  { key: "critical_count", label: "Critical", level: "critical" },
  { key: "high_count", label: "High", level: "high" },
  { key: "medium_count", label: "Medium", level: "medium" },
  { key: "low_count", label: "Low", level: "low" },
];

const COUNT_TEXT_COLOR: Record<string, string> = {
  critical: "text-red-500",
  high: "text-red-500",
  medium: "text-amber-500",
  low: "text-emerald-400",
};

export function Stage2View({ data }: { data: StageData }) {
  const findings = (data.findings as SemgrepFinding[]) ?? [];
  const totalIssues = Number(data.total_issues ?? 0);
  const configs = (data.configs as string[]) ?? [];
  const scanErrors = (data.scan_errors as string[]) ?? [];

  const rows = useMemo(() => findings as unknown as Row[], [findings]);

  return (
    <div className="space-y-5">
      <Card className="flex flex-wrap items-center gap-3 p-4">
        <span className="inline-flex items-center gap-2 rounded-full border border-brand/30 bg-brand/10 px-3 py-1 shadow-glow-brand">
          <ShieldAlert size={14} className="text-brand-light" />
          <span className="text-sm font-semibold text-brand-light">Semgrep scan</span>
        </span>
        <TagList items={configs} />
        <span className="text-xs font-mono text-slate-400 ml-auto truncate" title={String(data.repo_path ?? "")}>
          {String(data.repo_path ?? "")}
        </span>
      </Card>

      {scanErrors.length > 0 && (
        <Card glow="critical" className="border-red-500/20">
          <CardTitle>Scan reported errors</CardTitle>
          {scanErrors.map((e, i) => (
            <CardSub key={i} className="font-mono text-red-500">{e}</CardSub>
          ))}
        </Card>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
        <Card>
          <CardTitle>Total issues</CardTitle>
          <CardValue className="tabular-nums mt-1">{totalIssues}</CardValue>
        </Card>
        {COUNT_CARDS.map(({ key, label, level }) => (
          <Card key={key} glow={level === "critical" ? "critical" : undefined}>
            <CardTitle>{label}</CardTitle>
            <CardValue className={`tabular-nums mt-1 ${COUNT_TEXT_COLOR[level]}`}>{Number(data[key] ?? 0)}</CardValue>
          </Card>
        ))}
      </div>

      <div>
        <CardTitle className="mb-2">Active vulnerabilities</CardTitle>
        {findings.length === 0 ? (
          <Card>
            <p className="text-sm text-slate-400">No issues found by the last scan.</p>
          </Card>
        ) : (
          <DataGrid data={rows} columns={semgrepFindingsColumns} maxHeight={480} />
        )}
      </div>
    </div>
  );
}
