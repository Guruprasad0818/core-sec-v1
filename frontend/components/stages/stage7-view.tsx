"use client";

import { useMemo, useState } from "react";
import { ShieldCheck, ScrollText } from "lucide-react";
import { Card, CardSub, CardTitle, CardValue } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataGrid } from "@/components/data-grid";
import { complianceViolationColumns } from "@/lib/stage-columns";
import { cn } from "@/lib/utils";
import type { StageData } from "@/lib/types";

interface ControlStatus {
  control_id: string;
  title: string;
  description: string;
  status: "PASS" | "FAIL";
  violation_count: number;
  highest_severity: string | null;
}

interface FrameworkBlock {
  framework: string;
  controls: ControlStatus[];
  passed: number;
  total: number;
  readiness_pct: number;
}

interface Violation {
  control_id: string;
  framework: string;
  control_title: string;
  source_stage: number;
  severity: string;
  summary: string;
  file_path?: string | null;
  line_number?: number | null;
  finding_ref?: string | null;
  timestamp: string;
}

type Row = Record<string, unknown>;

const SEVERITY_FILTERS = ["all", "critical", "high", "medium", "low"] as const;

function ReadinessBar({ pct }: { pct: number }) {
  const color = pct >= 80 ? "bg-emerald-400" : pct >= 50 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="h-2 w-full rounded-full bg-white/10 overflow-hidden">
      <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${Math.max(2, pct)}%` }} />
    </div>
  );
}

function FrameworkScorecard({ block }: { block: FrameworkBlock }) {
  return (
    <Card glow={block.readiness_pct < 50 ? "critical" : undefined}>
      <div className="flex items-center justify-between mb-1">
        <CardTitle>{block.framework}</CardTitle>
        <span className="font-mono text-xs text-slate-400">
          {block.passed}/{block.total} controls passing
        </span>
      </div>
      <CardValue className="tabular-nums mb-2">{block.readiness_pct.toFixed(1)}%</CardValue>
      <ReadinessBar pct={block.readiness_pct} />
      <div className="mt-3 divide-y divide-white/5">
        {block.controls.map((c) => (
          <div key={c.control_id} className="flex items-center justify-between gap-3 py-2">
            <div className="min-w-0">
              <span className="font-mono text-[12px] font-medium text-white">{c.control_id}</span>{" "}
              <span className="text-[12px] text-slate-400">{c.title}</span>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {c.violation_count > 0 && <span className="text-[11px] font-mono text-slate-500">{c.violation_count}</span>}
              <Badge level={c.status === "PASS" ? "low" : "critical"}>{c.status}</Badge>
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

export function Stage7View({ data }: { data: StageData }) {
  const owasp = data.owasp as FrameworkBlock | undefined;
  const soc2 = data.soc2 as FrameworkBlock | undefined;
  const violations = (data.violations as Violation[]) ?? [];
  const rulesPassed = Number(data.rules_passed ?? 0);
  const rulesFailed = Number(data.rules_failed ?? 0);

  const [frameworkFilter, setFrameworkFilter] = useState<"all" | string>("all");
  const [severityFilter, setSeverityFilter] = useState<(typeof SEVERITY_FILTERS)[number]>("all");

  const frameworks = useMemo(() => Array.from(new Set(violations.map((v) => v.framework))), [violations]);

  const filtered = useMemo(
    () =>
      violations.filter(
        (v) =>
          (frameworkFilter === "all" || v.framework === frameworkFilter) &&
          (severityFilter === "all" || v.severity === severityFilter)
      ),
    [violations, frameworkFilter, severityFilter]
  );

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="inline-flex items-center gap-2 rounded-full border border-brand/30 bg-brand/10 px-3 py-1 shadow-glow-brand">
          <ShieldCheck size={14} className="text-brand-light" />
          <span className="text-sm font-semibold text-brand-light">Live compliance mapping</span>
        </span>
        <span className="text-xs font-mono text-slate-400">
          Stages 2 (Semgrep), 5 (entropy/secrets), 6 (runtime monitor) mapped onto OWASP Top 10 + SOC 2 CC6
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <Card>
          <CardTitle>Rules passed</CardTitle>
          <CardValue className="tabular-nums mt-1 text-emerald-400">{rulesPassed}</CardValue>
        </Card>
        <Card glow={rulesFailed > 0 ? "critical" : undefined}>
          <CardTitle>Rules failed</CardTitle>
          <CardValue className="tabular-nums mt-1 text-red-500">{rulesFailed}</CardValue>
        </Card>
        <Card>
          <CardTitle>Total violations</CardTitle>
          <CardValue className="tabular-nums mt-1">{violations.length}</CardValue>
        </Card>
        <Card>
          <CardTitle>SOC 2 readiness</CardTitle>
          <CardValue className="tabular-nums mt-1">{soc2 ? soc2.readiness_pct.toFixed(1) : "0.0"}%</CardValue>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {owasp && <FrameworkScorecard block={owasp} />}
        {soc2 && <FrameworkScorecard block={soc2} />}
      </div>

      <div>
        <div className="flex items-center justify-between gap-3 flex-wrap mb-2.5">
          <div className="flex items-center gap-2">
            <ScrollText size={14} className="text-brand-light" />
            <CardTitle className="!text-sm !text-white !font-semibold !normal-case">Audit log: mapped violations</CardTitle>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex rounded-full border border-white/10 overflow-hidden text-[11px] font-mono">
              {(["all", ...frameworks] as const).map((fw) => (
                <button
                  key={fw}
                  onClick={() => setFrameworkFilter(fw)}
                  className={cn(
                    "px-2.5 py-1 transition-colors",
                    frameworkFilter === fw ? "bg-brand text-white" : "text-slate-400 hover:text-white hover:bg-white/5"
                  )}
                >
                  {fw === "all" ? "All frameworks" : fw}
                </button>
              ))}
            </div>
            <div className="flex rounded-full border border-white/10 overflow-hidden text-[11px] font-mono uppercase">
              {SEVERITY_FILTERS.map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={cn(
                    "px-2.5 py-1 transition-colors",
                    severityFilter === sev ? "bg-brand text-white" : "text-slate-400 hover:text-white hover:bg-white/5"
                  )}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>
        </div>
        <CardSub className="mb-2">
          Showing {filtered.length} of {violations.length} mapped violations.
        </CardSub>
        <DataGrid data={filtered as unknown as Row[]} columns={complianceViolationColumns} maxHeight={480} />
      </div>
    </div>
  );
}
