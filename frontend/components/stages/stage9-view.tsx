"use client";

import { CheckCircle2, ListChecks, Quote, Terminal, XOctagon } from "lucide-react";
import { Card, CardSub, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { StageData } from "@/lib/types";

interface PolicyCondition {
  condition_id: string;
  label: string;
  passed: boolean;
  detail: string;
}

export function Stage9View({ data }: { data: StageData }) {
  const deploymentStatus = String(data.deployment_status ?? "BLOCKED");
  const conditions = (data.conditions as PolicyCondition[]) ?? [];
  const failureReasons = (data.failure_reasons as string[]) ?? [];
  const executiveSummary = String(data.executive_summary ?? "");
  const generatedAt = String(data.generated_at ?? "");

  const approved = deploymentStatus === "APPROVED";
  const passedCount = conditions.filter((c) => c.passed).length;

  return (
    <div className="space-y-5">
      {/* Massive high-contrast deployment status terminal */}
      <div
        className={cn(
          "relative overflow-hidden rounded-2xl border-2 p-8 sm:p-12 text-center",
          approved
            ? "border-emerald-500/40 bg-emerald-500/[0.04] shadow-[0_0_60px_rgba(16,185,129,0.15)]"
            : "border-red-500/40 bg-red-500/[0.04] shadow-[0_0_60px_rgba(239,68,68,0.18)]"
        )}
      >
        <div className="flex items-center justify-center gap-2 text-[11px] font-mono uppercase tracking-[0.2em] text-slate-500 mb-5">
          <Terminal size={13} />
          <span>cbad-pipeline / final-policy-gate --verdict</span>
        </div>

        {approved ? (
          <CheckCircle2 size={56} className="mx-auto text-emerald-400 mb-4" strokeWidth={1.5} />
        ) : (
          <XOctagon size={56} className="mx-auto text-red-500 mb-4" strokeWidth={1.5} />
        )}

        <div
          className={cn(
            "font-mono font-black tracking-tight leading-none text-5xl sm:text-7xl",
            approved ? "text-emerald-400" : "text-red-500"
          )}
        >
          {approved ? "APPROVED" : "BLOCKED"}
        </div>

        <div className="mt-4 flex items-center justify-center gap-3 flex-wrap">
          {approved ? (
            <span className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-4 py-1.5 text-sm font-semibold text-emerald-400">
              Ready for production
            </span>
          ) : (
            <span className="inline-flex items-center gap-2 rounded-full border border-red-500/30 bg-red-500/10 px-4 py-1.5 text-sm font-semibold text-red-500">
              Deployment halted
            </span>
          )}
          <span className="text-xs font-mono text-slate-500">
            {passedCount}/{conditions.length} governance gates passed
          </span>
        </div>

        {generatedAt && (
          <div className="mt-5 text-[11px] font-mono text-slate-600">evaluated {generatedAt.replace("T", " ").slice(0, 19)} UTC</div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card glow={approved ? undefined : "critical"}>
          <div className="flex items-center gap-2 mb-3">
            <ListChecks size={14} className="text-brand-light" />
            <CardTitle className="!text-sm !text-white !font-semibold !normal-case">Governance gate checklist</CardTitle>
          </div>
          <div className="divide-y divide-white/5">
            {conditions.map((c) => (
              <div key={c.condition_id} className="flex items-start justify-between gap-3 py-2.5">
                <div className="min-w-0">
                  <p className="text-[13px] font-medium text-white">{c.label}</p>
                  <p className="text-[12px] text-slate-400 mt-0.5">{c.detail}</p>
                </div>
                <Badge level={c.passed ? "low" : "critical"} className="shrink-0 mt-0.5">
                  {c.passed ? "pass" : "fail"}
                </Badge>
              </div>
            ))}
            {conditions.length === 0 && <p className="text-sm text-slate-400 py-2">No conditions evaluated.</p>}
          </div>
        </Card>

        <Card>
          <div className="flex items-center gap-2 mb-3">
            <Quote size={14} className="text-brand-light" />
            <CardTitle className="!text-sm !text-white !font-semibold !normal-case">Executive summary</CardTitle>
          </div>
          <blockquote className={cn("border-l-2 pl-4 text-[13px] leading-relaxed text-slate-300", approved ? "border-emerald-500/40" : "border-red-500/40")}>
            {executiveSummary}
          </blockquote>

          {!approved && failureReasons.length > 0 && (
            <div className="mt-4">
              <CardSub className="!text-slate-500 mb-1.5">Blocking conditions</CardSub>
              <ul className="space-y-1">
                {failureReasons.map((reason, i) => (
                  <li key={i} className="text-[12px] font-mono text-red-400 flex gap-2">
                    <span className="text-red-500/60">✕</span>
                    <span>{reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
