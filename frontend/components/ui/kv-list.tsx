/** Compact multi-line key:value rendering for small nested score/metric
 * objects (e.g. Stage 2's component_scores) instead of raw JSON stringify. */
export function KvList({ entries }: { entries: Record<string, unknown> }) {
  const pairs = Object.entries(entries);
  if (pairs.length === 0) return <span className="text-slate-400 text-xs">—</span>;
  return (
    <div className="font-mono text-[11px] leading-[1.45] text-slate-300 whitespace-normal py-0.5">
      {pairs.map(([key, value]) => (
        <div key={key} className="flex gap-1.5">
          <span className="text-slate-400">{key}</span>
          <span className="text-white font-medium">{typeof value === "number" ? value.toFixed(2) : String(value)}</span>
        </div>
      ))}
    </div>
  );
}
