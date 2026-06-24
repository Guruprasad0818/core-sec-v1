"use client";

import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, FileSearch, GitBranch, ShieldCheck, Signature } from "lucide-react";
import { Card, CardSub, CardTitle, CardValue } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataGrid } from "@/components/data-grid";
import { supplyChainDependencyColumns } from "@/lib/stage-columns";
import { cn } from "@/lib/utils";
import type { StageData } from "@/lib/types";

interface Dependency {
  name: string;
  version: string;
  ecosystem: string;
  purl?: string | null;
  sha256: string;
  verified: boolean;
}

interface TreeNode {
  name: string;
  version?: string;
  verified?: boolean;
  children?: TreeNode[];
}

interface SignatureLogEntry {
  timestamp: string;
  method: string;
  artifact_digest: string;
  verified: boolean;
  reason: string;
  subject_identity: Record<string, string>;
  rekor_uuid?: string | null;
  rekor_log_index?: number | null;
}

type Row = Record<string, unknown>;

function DependencyTreeView({ node, depth = 0 }: { node: TreeNode; depth?: number }) {
  const [expanded, setExpanded] = useState(depth < 1);
  const hasChildren = !!node.children?.length;

  return (
    <div>
      <button
        onClick={() => hasChildren && setExpanded((e) => !e)}
        className={cn(
          "flex items-center gap-1.5 py-1 w-full text-left rounded hover:bg-white/5",
          depth === 0 && "font-semibold text-white",
          !hasChildren && "cursor-default"
        )}
        style={{ paddingLeft: depth * 18 }}
      >
        {hasChildren ? (
          expanded ? (
            <ChevronDown size={13} className="text-slate-400 shrink-0" />
          ) : (
            <ChevronRight size={13} className="text-slate-400 shrink-0" />
          )
        ) : (
          <span className="w-[13px] shrink-0" />
        )}
        <span className={cn("font-mono text-[13px]", depth === 0 ? "text-white" : "text-slate-300")}>{node.name}</span>
        {node.version && <span className="font-mono text-[11px] text-slate-500">@{node.version}</span>}
        {hasChildren && <span className="text-[11px] text-slate-500 ml-1">({node.children!.length})</span>}
        {node.verified === false && <Badge level="medium">unpinned</Badge>}
      </button>
      {hasChildren && expanded && (
        <div>
          {node.children!.map((child, i) => (
            <DependencyTreeView key={`${child.name}-${i}`} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

export function Stage8View({ data }: { data: StageData }) {
  const attestationStatus = String(data.attestation_status ?? "FAILED");
  const slsaLevel = Number(data.slsa_level ?? 0);
  const slsaTarget = Number(data.slsa_level_target ?? 3);
  const artifactDigest = String(data.artifact_digest ?? "");
  const sbomCompleteness = Number(data.sbom_completeness_pct ?? 0);
  const dependencies = (data.dependencies as Dependency[]) ?? [];
  const tree = data.dependency_tree as TreeNode | undefined;
  const signatureLog = (data.signature_log as SignatureLogEntry[]) ?? [];
  const rekorChainIntact = Boolean(data.rekor_chain_intact);

  const [search, setSearch] = useState("");
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return dependencies;
    return dependencies.filter((d) => d.name.toLowerCase().includes(q) || d.purl?.toLowerCase().includes(q) || d.ecosystem.toLowerCase().includes(q));
  }, [dependencies, search]);

  const passed = attestationStatus === "PASSED";

  return (
    <div className="space-y-5">
      <Card glow={passed ? "emerald" : "critical"} className={cn("border", passed ? "border-emerald-500/30" : "border-red-500/30")}>
        <div className="flex flex-wrap items-center gap-4">
          <ShieldCheck size={28} className={passed ? "text-emerald-400" : "text-red-500"} />
          <div>
            <CardTitle>SLSA verification</CardTitle>
            <div className="flex items-baseline gap-2 mt-0.5">
              <span className={cn("text-2xl font-bold tracking-tight", passed ? "text-emerald-400" : "text-red-500")}>
                {attestationStatus}
              </span>
              <span className="text-sm font-mono text-slate-400">
                SLSA Level {slsaLevel}/{slsaTarget}
              </span>
            </div>
          </div>
          <div className="ml-auto text-right">
            <CardSub>artifact digest</CardSub>
            <span className="font-mono text-xs text-slate-300" title={artifactDigest}>
              {artifactDigest.slice(0, 24)}…
            </span>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <Card>
          <CardTitle>SBOM completeness</CardTitle>
          <CardValue className="tabular-nums mt-1">{sbomCompleteness.toFixed(1)}%</CardValue>
        </Card>
        <Card>
          <CardTitle>Dependencies</CardTitle>
          <CardValue className="tabular-nums mt-1">{dependencies.length}</CardValue>
        </Card>
        <Card>
          <CardTitle>Transparency log entries</CardTitle>
          <CardValue className="tabular-nums mt-1">{Number(data.transparency_log_entries ?? 0)}</CardValue>
        </Card>
        <Card glow={rekorChainIntact ? undefined : "critical"}>
          <CardTitle>Rekor chain</CardTitle>
          <CardValue className={cn("tabular-nums mt-1", rekorChainIntact ? "text-emerald-400" : "text-red-500")}>
            {rekorChainIntact ? "INTACT" : "BROKEN"}
          </CardValue>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <Card>
          <div className="flex items-center gap-2 mb-2.5">
            <GitBranch size={14} className="text-brand-light" />
            <CardTitle className="!text-sm !text-white !font-semibold !normal-case">Dependency tree</CardTitle>
          </div>
          {tree ? <DependencyTreeView node={tree} /> : <p className="text-sm text-slate-400">No dependency data.</p>}
        </Card>

        <Card>
          <div className="flex items-center gap-2 mb-2.5">
            <Signature size={14} className="text-brand-light" />
            <CardTitle className="!text-sm !text-white !font-semibold !normal-case">Signature verification log</CardTitle>
          </div>
          <div className="space-y-2.5">
            {signatureLog.map((entry, i) => (
              <div key={i} className="rounded-lg border border-white/10 p-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[12px] text-white">{entry.method}</span>
                  <Badge level={entry.verified ? "low" : "critical"}>{entry.verified ? "verified" : "failed"}</Badge>
                </div>
                <p className="text-[12px] text-slate-400 mt-1">{entry.reason}</p>
                <div className="flex flex-wrap gap-3 mt-1.5 text-[11px] font-mono text-slate-500">
                  <span>{entry.timestamp.replace("T", " ").slice(0, 19)}</span>
                  {entry.rekor_uuid && <span>rekor={entry.rekor_uuid.slice(0, 8)}…</span>}
                </div>
              </div>
            ))}
            {signatureLog.length === 0 && <p className="text-sm text-slate-400">No signature events recorded.</p>}
          </div>
        </Card>
      </div>

      <div>
        <div className="flex items-center justify-between gap-3 flex-wrap mb-2.5">
          <CardTitle className="!text-sm !text-white !font-semibold !normal-case">Container image SBOM layers</CardTitle>
          <div className="relative">
            <FileSearch size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search package, purl, ecosystem..."
              className="bg-white/5 border border-white/10 rounded-full pl-8 pr-3 py-1.5 text-xs text-white placeholder:text-slate-500 outline-none focus:border-brand/50 w-64"
            />
          </div>
        </div>
        <CardSub className="mb-2">
          Showing {filtered.length} of {dependencies.length} SBOM components.
        </CardSub>
        <DataGrid data={filtered as unknown as Row[]} columns={supplyChainDependencyColumns} maxHeight={420} />
      </div>
    </div>
  );
}
