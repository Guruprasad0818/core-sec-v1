"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Wrench, Loader2, CheckCircle2, AlertTriangle, GitBranch, GitCommit } from "lucide-react";
import { Card, CardSub, CardTitle, CardValue } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TagList } from "@/components/ui/tag";
import { Button } from "@/components/ui/button";
import { remediateFinding } from "@/lib/api";
import type { RemediateResponse, StageData } from "@/lib/types";

interface RemediableFinding {
  instance_id: string;
  finding_id: string;
  severity: string;
  message: string;
  file_path: string;
  line_number: number;
  cwe: string[];
  is_auto_fixable: boolean;
}

type RowState =
  | { phase: "idle" }
  | { phase: "loading" }
  | { phase: "done"; result: RemediateResponse };

function ruleName(checkId: string): string {
  const parts = checkId.split(".");
  return parts[parts.length - 1] ?? checkId;
}

function FindingRow({ finding }: { finding: RemediableFinding }) {
  const router = useRouter();
  const [state, setState] = useState<RowState>({ phase: "idle" });

  async function onRemediate() {
    setState({ phase: "loading" });
    try {
      const result = await remediateFinding(finding.instance_id);
      setState({ phase: "done", result });
    } catch (err) {
      setState({
        phase: "done",
        result: { status: "error", reason: err instanceof Error ? err.message : String(err) },
      });
    } finally {
      // Stage 2/3's cache was invalidated server-side on a successful fix -
      // refresh this page so a now-resolved finding drops out of the list.
      router.refresh();
    }
  }

  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex-1 min-w-0 space-y-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge value={finding.severity}>{finding.severity}</Badge>
            <span className="font-mono text-[13px] font-medium text-white truncate" title={finding.finding_id}>
              {ruleName(finding.finding_id)}
            </span>
          </div>
          <div className="font-mono text-xs text-slate-400">
            {finding.file_path}:{finding.line_number}
          </div>
          <p className="text-sm text-slate-300">{finding.message}</p>
          <TagList items={finding.cwe} />
        </div>

        <div className="shrink-0">
          {state.phase === "idle" && finding.is_auto_fixable && (
            <Button onClick={onRemediate} className="gap-2">
              <Wrench size={14} />
              Remediate
            </Button>
          )}
          {state.phase === "idle" && !finding.is_auto_fixable && (
            <span className="text-xs text-slate-400 italic">Manual fix required</span>
          )}
          {state.phase === "loading" && (
            <Button disabled className="gap-2">
              <Loader2 size={14} className="animate-spin" />
              Fixing...
            </Button>
          )}
        </div>
      </div>

      {state.phase === "done" && (
        <div className="mt-3 pt-3 border-t border-white/10">
          {state.result.status === "committed" && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium">
                <CheckCircle2 size={15} />
                Fix committed
              </div>
              <p className="text-xs text-slate-300">{state.result.summary}</p>
              <div className="flex flex-wrap gap-4 text-xs font-mono text-slate-400">
                <span className="inline-flex items-center gap-1.5">
                  <GitBranch size={12} className="text-brand-light" />
                  {state.result.branch}
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <GitCommit size={12} className="text-brand-light" />
                  {state.result.commit_hash}
                </span>
              </div>
              {state.result.diff && (
                <pre className="font-mono text-[11px] text-slate-300 whitespace-pre-wrap overflow-auto max-h-48 bg-black/30 rounded-lg p-2.5 border border-white/5">
                  {state.result.diff}
                </pre>
              )}
            </div>
          )}
          {state.result.status === "not_auto_fixable" && (
            <div className="flex items-start gap-2 text-amber-500 text-sm">
              <AlertTriangle size={15} className="shrink-0 mt-0.5" />
              <span>{state.result.reason}</span>
            </div>
          )}
          {state.result.status === "error" && (
            <div className="flex items-start gap-2 text-red-500 text-sm">
              <AlertTriangle size={15} className="shrink-0 mt-0.5" />
              <span>{state.result.reason}</span>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

export function Stage4View({ data }: { data: StageData }) {
  const findings = (data.remediable_findings as RemediableFinding[]) ?? [];
  const fixableCount = Number(data.fixable_count ?? 0);
  const totalCount = Number(data.total_count ?? 0);

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-2.5">
        <Card>
          <CardTitle>Auto-fixable</CardTitle>
          <CardValue className="tabular-nums mt-1 text-emerald-400">{fixableCount}</CardValue>
          <CardSub>hardcoded secrets -&gt; env var placeholder</CardSub>
        </Card>
        <Card>
          <CardTitle>Total findings</CardTitle>
          <CardValue className="tabular-nums mt-1">{totalCount}</CardValue>
          <CardSub>from Stage 2's live Semgrep scan</CardSub>
        </Card>
      </div>

      <div className="space-y-2.5">
        <CardTitle>Remediation queue</CardTitle>
        {findings.length === 0 ? (
          <Card>
            <p className="text-sm text-slate-400">No findings to remediate.</p>
          </Card>
        ) : (
          findings.map((f) => <FindingRow key={f.instance_id} finding={f} />)
        )}
      </div>
    </div>
  );
}
