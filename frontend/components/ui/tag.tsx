import * as React from "react";
import { cn } from "@/lib/utils";

/** Neutral inline pill for non-severity metadata (tags, requirements,
 * narrative reasons) - visually distinct from the risk-colored Badge. */
export function Tag({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border border-white/10 bg-white/10 px-2 py-0.5",
        "text-[11px] font-mono text-slate-300 whitespace-nowrap",
        className
      )}
      {...props}
    />
  );
}

export function TagList({ items, emptyText = "—" }: { items: string[]; emptyText?: string }) {
  if (items.length === 0) return <span className="text-slate-400 text-xs">{emptyText}</span>;
  return (
    <div className="flex flex-wrap gap-1 py-0.5">
      {items.map((item, i) => (
        <Tag key={`${item}-${i}`}>{item}</Tag>
      ))}
    </div>
  );
}
