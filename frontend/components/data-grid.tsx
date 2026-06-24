"use client";

import * as React from "react";
import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  type RowData,
  type SortingState,
  useReactTable,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { colorFor } from "@/lib/risk";

declare module "@tanstack/react-table" {
  interface ColumnMeta<TData extends RowData, TValue> {
    /** Fixed pixel width for columns with custom (non-truncated) cell content. */
    width?: number;
  }
}

type Row = Record<string, unknown>;

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(3);
  return String(value);
}

export function DataGrid({
  data,
  severityColumn,
  columns: columnsOverride,
  maxHeight = 420,
}: {
  data: Row[];
  severityColumn?: string;
  /** Bypass auto-derived columns entirely - used by per-stage views that need
   * custom cell renderers (badges, extracted nested fields, etc.) instead of
   * raw key/value stringification. */
  columns?: ColumnDef<Row>[];
  maxHeight?: number;
}) {
  const [sorting, setSorting] = React.useState<SortingState>([]);

  const autoColumns = React.useMemo<ColumnDef<Row>[]>(() => {
    if (data.length === 0) return [];
    return Object.keys(data[0]).map((key) => ({
      accessorKey: key,
      header: key.replace(/_/g, " "),
      cell: (info) => {
        const value = info.getValue();
        const isSeverity = key === severityColumn;
        return (
          <span
            className={cn("block truncate font-mono text-[13px] font-medium", !isSeverity && "text-white")}
            style={isSeverity ? { color: colorFor(value), fontWeight: 700 } : undefined}
          >
            {formatCell(value)}
          </span>
        );
      },
    }));
  }, [data, severityColumn]);

  const columns = columnsOverride ?? autoColumns;

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  if (data.length === 0) {
    return <div className="text-sm text-slate-400 py-6 text-center">No rows to display.</div>;
  }

  return (
    <div className="rounded-xl border border-white/10 overflow-hidden bg-slate-900">
      <div className="overflow-auto" style={{ maxHeight }}>
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur-md">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id} className="border-b border-white/10">
                {headerGroup.headers.map((header) => {
                  const sortDir = header.column.getIsSorted();
                  return (
                    <th
                      key={header.id}
                      onClick={header.column.getToggleSortingHandler()}
                      className="px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400 whitespace-nowrap cursor-pointer select-none"
                    >
                      <span className="inline-flex items-center gap-1">
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        {sortDir === "asc" && <ArrowUp size={11} />}
                        {sortDir === "desc" && <ArrowDown size={11} />}
                        {!sortDir && <ArrowUpDown size={11} className="opacity-30" />}
                      </span>
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr key={row.id} className="border-b border-white/5 align-top hover:bg-white/10 transition-colors">
                {row.getVisibleCells().map((cell) => {
                  const width = cell.column.columnDef.meta?.width;
                  return (
                    <td
                      key={cell.id}
                      className={cn("px-3 py-1.5", !width && "max-w-[320px]")}
                      style={width ? { width, maxWidth: width } : undefined}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
