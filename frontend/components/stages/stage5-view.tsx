"use client";

import { useMemo, useState } from "react";
import { KeyRound, ShieldCheck } from "lucide-react";
import { Card, CardSub, CardTitle, CardValue } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataGrid } from "@/components/data-grid";
import { getCustomColumns } from "@/lib/stage-columns";
import { EntropyHistogram, type EntropyHistogramBucket } from "@/components/charts/entropy-histogram";
import type { StageData } from "@/lib/types";

interface EntropyFinding {
  file_path: string;
  line_number: number;
  rule_id: string;
  category: string;
  charset?: string;
  entropy: number;
  confidence: "high" | "medium";
  masked_value?: string;
}

const RENDER_CAP = 200;

export function Stage5View({ data }: { data: StageData }) {
  const entropy = (data.entropy as Record<string, unknown>) ?? {};
  const slsa = (data.slsa as Record<string, unknown>) ?? {};
  const slsaSummary = (slsa.summary as Record<string, unknown>) ?? {};

  const allFindings = (entropy.findings as EntropyFinding[]) ?? [];
  const distribution = (entropy.entropy_distribution as EntropyHistogramBucket[]) ?? [];
  const totalFindings = Number(entropy.total_findings ?? allFindings.length);
  const highCount = Number(entropy.high_confidence_count ?? 0);
  const mediumCount = Number(entropy.medium_confidence_count ?? 0);

  const minEntropy = allFindings.length ? Math.min(...allFindings.map((f) => f.entropy)) : 3;
  const maxEntropy = allFindings.length ? Math.max(...allFindings.map((f) => f.entropy)) : 6;

  // Default just above the typical near-threshold noise cluster (most repos
  // have a long tail of borderline medium-confidence matches - see
  // server/entropy_monitor.py) so the first paint isn't hundreds of rows.
  const [threshold, setThreshold] = useState(() => Math.min(4.5, Math.max(minEntropy, (minEntropy + maxEntropy) / 2)));

  const visibleFindings = useMemo(
    () => allFindings.filter((f) => f.entropy >= threshold).sort((a, b) => b.entropy - a.entropy),
    [allFindings, threshold]
  );

  const sbomColumns = getCustomColumns(5, "slsa.sbom.components");
  const components = ((slsa.sbom as Record<string, unknown> | undefined)?.components as Record<string, unknown>[] | undefined) ?? [];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="inline-flex items-center gap-2 rounded-full border border-brand/30 bg-brand/10 px-3 py-1 shadow-glow-brand">
          <KeyRound size={14} className="text-brand-light" />
          <span className="text-sm font-semibold text-brand-light">Live entropy + secrets scan</span>
        </span>
        <span className="text-xs font-mono text-slate-400 truncate" title={String(entropy.repo_path ?? "")}>
          {String(entropy.repo_path ?? "")}
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <Card>
          <CardTitle>Total violations</CardTitle>
          <CardValue className="tabular-nums mt-1">{totalFindings}</CardValue>
        </Card>
        <Card glow={highCount > 0 ? "critical" : undefined}>
          <CardTitle>High confidence</CardTitle>
          <CardValue className="tabular-nums mt-1 text-red-500">{highCount}</CardValue>
        </Card>
        <Card>
          <CardTitle>Medium confidence</CardTitle>
          <CardValue className="tabular-nums mt-1 text-amber-500">{mediumCount}</CardValue>
        </Card>
        <Card>
          <CardTitle>SLSA level</CardTitle>
          <CardValue className="tabular-nums mt-1">{String(slsaSummary.slsa_level ?? "n/a")}</CardValue>
          <CardSub className="flex items-center gap-1">
            <ShieldCheck size={11} className={slsaSummary.provenance_signature_valid ? "text-emerald-400" : "text-red-500"} />
            {String(slsa.source ?? "")}
          </CardSub>
        </Card>
      </div>

      <Card>
        <div className="flex items-center justify-between mb-1">
          <CardTitle>Entropy score distribution</CardTitle>
          <span className="text-xs font-mono text-slate-400">{visibleFindings.length} above current threshold</span>
        </div>
        <EntropyHistogram data={distribution} />
      </Card>

      <Card>
        <div className="flex items-center justify-between gap-4 flex-wrap mb-1.5">
          <CardTitle>Sensitivity threshold</CardTitle>
          <span className="font-mono text-sm text-brand-light tabular-nums">{threshold.toFixed(2)} bits/char</span>
        </div>
        <input
          type="range"
          min={minEntropy}
          max={maxEntropy}
          step={0.05}
          value={threshold}
          onChange={(e) => setThreshold(Number(e.target.value))}
          className="w-full accent-brand"
        />
        <div className="flex justify-between text-[11px] text-slate-500 mt-1">
          <span>{minEntropy.toFixed(1)} - more matches, more noise</span>
          <span>{maxEntropy.toFixed(1)} - fewer, higher-confidence only</span>
        </div>
        <CardSub className="mt-2">
          Showing {visibleFindings.length} of {allFindings.length} findings at or above this threshold.
        </CardSub>
      </Card>

      <div>
        <CardTitle className="mb-2">Violations</CardTitle>
        {visibleFindings.length === 0 ? (
          <Card>
            <p className="text-sm text-slate-400">No findings at this sensitivity threshold.</p>
          </Card>
        ) : (
          <div className="space-y-2">
            {visibleFindings.slice(0, RENDER_CAP).map((f, i) => (
              <Card key={`${f.file_path}-${f.line_number}-${f.rule_id}-${i}`} className="p-3.5">
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge value={f.confidence}>{f.confidence}</Badge>
                      <span className="font-mono text-[13px] font-medium text-white">{f.rule_id}</span>
                      <span className="text-[11px] text-slate-500">{f.category}</span>
                    </div>
                    <div className="font-mono text-xs text-slate-400">
                      {f.file_path}:{f.line_number}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="font-mono text-sm text-red-400">{f.masked_value}</div>
                    <div className="font-mono text-[11px] text-slate-500">
                      {f.entropy.toFixed(3)} bits/char{f.charset ? ` (${f.charset})` : ""}
                    </div>
                  </div>
                </div>
              </Card>
            ))}
            {visibleFindings.length > RENDER_CAP && (
              <CardSub>...and {visibleFindings.length - RENDER_CAP} more. Raise the sensitivity threshold to narrow this down.</CardSub>
            )}
          </div>
        )}
      </div>

      {components.length > 0 && sbomColumns && (
        <div>
          <CardTitle className="mb-2">SBOM components (SLSA attestation)</CardTitle>
          <DataGrid data={components} columns={sbomColumns} maxHeight={360} />
        </div>
      )}
    </div>
  );
}
