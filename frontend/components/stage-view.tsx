"use client";

import { useMemo, useState } from "react";
import { Card } from "@/components/ui/card";
import { DataGrid } from "@/components/data-grid";
import { collectTables } from "@/lib/stage-tables";
import { getCustomColumns, getExtraTables } from "@/lib/stage-columns";
import type { StageData } from "@/lib/types";

export function StageView({ data, stageNum }: { data: StageData; stageNum: number }) {
  const tables = useMemo(() => {
    const extra = getExtraTables(stageNum, data);
    return [...extra, ...collectTables(data)];
  }, [data, stageNum]);
  const [tab, setTab] = useState(0);

  if (tables.length === 0) {
    return (
      <Card>
        <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap overflow-auto max-h-[60vh]">
          {JSON.stringify(data, null, 2)}
        </pre>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-1.5 flex-wrap">
        {tables.map((t, i) => (
          <button
            key={t.label}
            onClick={() => setTab(i)}
            className={`px-3 py-1.5 rounded-xl text-xs font-mono border transition-colors ${
              i === tab
                ? "bg-brand/10 border-brand/30 text-white"
                : "bg-transparent border-white/10 text-slate-300 hover:text-white hover:bg-white/10"
            }`}
          >
            {t.label} <span className="text-slate-400">({t.rows.length})</span>
          </button>
        ))}
      </div>
      <DataGrid
        data={tables[tab].rows}
        severityColumn={tables[tab].severityColumn}
        columns={getCustomColumns(stageNum, tables[tab].label)}
        maxHeight={480}
      />

      <details className="mt-2">
        <summary className="cursor-pointer text-xs text-slate-400 hover:text-slate-200">Raw JSON response</summary>
        <Card className="mt-2">
          <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap overflow-auto max-h-[50vh]">
            {JSON.stringify(data, null, 2)}
          </pre>
        </Card>
      </details>
    </div>
  );
}
