"use client";

import { useMemo } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { GitBranch, GitCommit } from "lucide-react";
import { Card, CardSub, CardTitle, CardValue } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataGrid } from "@/components/data-grid";
import type { StageData } from "@/lib/types";

interface CommitRow {
  hash: string;
  author: string;
  message: string;
  timestamp: string;
  insertions: number;
  deletions: number;
  files_changed: number;
}

type Row = Record<string, unknown>;

/** Explicit en-US/UTC formatting (not the runtime's default locale) so the
 * server-rendered HTML and the client hydration pass always agree. */
function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(d);
}

function HashTag({ hash }: { hash: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-brand/30 bg-brand/10 px-2.5 py-0.5 shadow-glow-brand">
      <GitCommit size={11} className="text-brand-light" />
      <span className="font-mono text-[12px] font-semibold text-brand-light tabular-nums">{hash}</span>
    </span>
  );
}

const columns: ColumnDef<Row>[] = [
  {
    accessorKey: "hash",
    header: "commit",
    cell: (info) => <HashTag hash={info.getValue() as string} />,
  },
  {
    accessorKey: "message",
    header: "message",
    meta: { width: 320 },
    cell: (info) => <span className="text-[13px] font-medium text-white truncate block">{String(info.getValue())}</span>,
  },
  {
    accessorKey: "author",
    header: "author",
    cell: (info) => <span className="text-[13px] text-slate-300 truncate block">{String(info.getValue())}</span>,
  },
  {
    accessorKey: "timestamp",
    header: "when",
    meta: { width: 180 },
    cell: (info) => <span className="font-mono text-xs text-slate-400 whitespace-nowrap">{formatTimestamp(info.getValue() as string)}</span>,
  },
  {
    accessorKey: "insertions",
    header: "+",
    cell: (info) => (
      <span className="font-mono text-[13px] font-semibold text-emerald-400 tabular-nums">+{info.getValue() as number}</span>
    ),
  },
  {
    accessorKey: "deletions",
    header: "-",
    cell: (info) => (
      <span className="font-mono text-[13px] font-semibold text-red-500 tabular-nums">-{info.getValue() as number}</span>
    ),
  },
  {
    accessorKey: "files_changed",
    header: "files",
    cell: (info) => <span className="font-mono text-[13px] text-slate-300 tabular-nums">{info.getValue() as number}</span>,
  },
];

export function Stage1View({ data }: { data: StageData }) {
  const activeBranch = String(data.active_branch ?? "n/a");
  const isDirty = Boolean(data.is_dirty);
  const commits = (data.commits as CommitRow[]) ?? [];
  const totalInsertions = Number(data.total_insertions ?? 0);
  const totalDeletions = Number(data.total_deletions ?? 0);
  const netChurn = totalInsertions - totalDeletions;

  const rows = useMemo(() => commits as unknown as Row[], [commits]);

  if (commits.length === 0) {
    return (
      <Card>
        <CardTitle>No git history available</CardTitle>
        <p className="text-sm text-slate-400 mt-2">
          Could not read any commits from <span className="font-mono text-slate-300">{String(data.repo_path ?? "this repository")}</span>.
        </p>
      </Card>
    );
  }

  return (
    <div className="space-y-5">
      <Card className="flex flex-wrap items-center gap-3 p-4">
        <span className="inline-flex items-center gap-2 rounded-full border border-brand/30 bg-brand/10 px-3 py-1 shadow-glow-brand">
          <GitBranch size={14} className="text-brand-light" />
          <span className="font-mono text-sm font-semibold text-brand-light">{activeBranch}</span>
        </span>
        <Badge level={isDirty ? "medium" : "low"}>{isDirty ? "uncommitted changes" : "clean working tree"}</Badge>
        <span className="text-xs font-mono text-slate-400 ml-auto truncate" title={String(data.repo_path ?? "")}>
          {String(data.repo_path ?? "")}
        </span>
      </Card>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <Card>
          <CardTitle>Commits analyzed</CardTitle>
          <CardValue className="tabular-nums mt-1">{commits.length}</CardValue>
        </Card>
        <Card>
          <CardTitle>Lines added</CardTitle>
          <CardValue className="tabular-nums mt-1 text-emerald-400">+{totalInsertions}</CardValue>
        </Card>
        <Card>
          <CardTitle>Lines removed</CardTitle>
          <CardValue className="tabular-nums mt-1 text-red-500">-{totalDeletions}</CardValue>
        </Card>
        <Card>
          <CardTitle>Net churn</CardTitle>
          <CardValue className={`tabular-nums mt-1 ${netChurn >= 0 ? "text-emerald-400" : "text-red-500"}`}>
            {netChurn >= 0 ? "+" : ""}
            {netChurn}
          </CardValue>
          <CardSub>insertions minus deletions</CardSub>
        </Card>
      </div>

      <div>
        <CardTitle className="mb-2">Last {commits.length} commits</CardTitle>
        <DataGrid data={rows} columns={columns} maxHeight={420} />
      </div>
    </div>
  );
}
