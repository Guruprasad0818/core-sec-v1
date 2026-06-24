"use client";

import { useMemo } from "react";
import { Activity, GitCommit } from "lucide-react";
import { Card, CardSub, CardTitle, CardValue } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataGrid } from "@/components/data-grid";
import { Sparkline } from "@/components/charts/sparkline";
import { semgrepFindingsColumns } from "@/lib/stage-columns";
import { levelFor, LEVEL_COLOR } from "@/lib/risk";
import type { StageData } from "@/lib/types";

interface RiskHistoryPoint {
  timestamp: string;
  commit_hash: string;
  risk_score: number;
}

interface SemgrepFinding {
  finding_id: string;
  severity: string;
  message: string;
  file_path: string;
  line_number: number;
}

type Row = Record<string, unknown>;

const COUNT_CARDS: { key: string; label: string; level: "critical" | "high" | "medium" | "low" }[] = [
  { key: "critical", label: "Critical", level: "critical" },
  { key: "high", label: "High", level: "high" },
  { key: "medium", label: "Medium", level: "medium" },
  { key: "low", label: "Low", level: "low" },
];

const COUNT_TEXT_COLOR: Record<string, string> = {
  critical: "text-red-500",
  high: "text-red-500",
  medium: "text-amber-500",
  low: "text-emerald-400",
};

export function Stage3View({ data }: { data: StageData }) {
  const riskScore = Number(data.risk_score ?? 0);
  const riskBand = String(data.risk_band ?? "n/a");
  const history = (data.history as RiskHistoryPoint[]) ?? [];
  const breakdown = (data.findings_in_recent_files as Record<string, number>) ?? {};
  const matchedFindings = (data.matched_findings as SemgrepFinding[]) ?? [];
  const recentFilesCount = Number(data.recent_files_count ?? 0);
  const scoreColor = LEVEL_COLOR[levelFor(riskBand)];

  const sparklineData = useMemo(
    () => history.map((h) => ({ label: h.commit_hash, value: h.risk_score })),
    [history]
  );
  const findingsRows = useMemo(() => matchedFindings as unknown as Row[], [matchedFindings]);

  return (
    <div className="space-y-5">
      <Card className="flex flex-col md:flex-row items-stretch gap-6 p-6">
        <div className="flex flex-col items-center justify-center md:w-48 shrink-0">
          <span className="font-mono text-[2.75rem] font-bold leading-none" style={{ color: scoreColor }}>
            {riskScore}
          </span>
          <span className="text-[10px] uppercase tracking-widest text-slate-400 mt-1.5">risk score / 100</span>
          <Badge value={riskBand} className="mt-3">{riskBand}</Badge>
        </div>
        <div className="flex-1 space-y-3">
          <div className="flex items-center justify-between">
            <CardTitle>Risk trend (by commit)</CardTitle>
            <span className="text-[11px] font-mono text-slate-400">{history.length} point(s)</span>
          </div>
          <Sparkline data={sparklineData} color={scoreColor} />
          <div className="flex flex-wrap gap-4 pt-1">
            <span className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400">
              <GitCommit size={12} className="text-brand-light" />
              HEAD <span className="text-white">{String(data.commit_hash ?? "n/a")}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400">
              <Activity size={12} className="text-brand-light" />
              {recentFilesCount} recently modified file(s) correlated
            </span>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        {COUNT_CARDS.map(({ key, label, level }) => (
          <Card key={key} glow={level === "critical" ? "critical" : undefined}>
            <CardTitle>{label} in recent files</CardTitle>
            <CardValue className={`tabular-nums mt-1 ${COUNT_TEXT_COLOR[level]}`}>{breakdown[key] ?? 0}</CardValue>
          </Card>
        ))}
      </div>

      <div>
        <CardTitle className="mb-2">Vulnerabilities in recently modified files</CardTitle>
        <CardSub className="mb-3">
          Semgrep findings (Stage 2) whose file path was touched by a recent commit (Stage 1) - the basis of the risk score above.
        </CardSub>
        {matchedFindings.length === 0 ? (
          <Card>
            <p className="text-sm text-slate-400">No open findings in recently modified files.</p>
          </Card>
        ) : (
          <DataGrid data={findingsRows} columns={semgrepFindingsColumns} maxHeight={420} />
        )}
      </div>
    </div>
  );
}
