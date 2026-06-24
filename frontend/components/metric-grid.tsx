/** Dense grid of muted-label/mono-value metric cards for flat scalar
 * payloads (Stage 1's behavioral telemetry, Stage 3's feature vector) -
 * shared so both layouts stay visually consistent. */
function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(3).replace(/0+$/, "").replace(/\.$/, "");
  }
  return String(value);
}

export function MetricGrid({ entries }: { entries: Record<string, unknown> }) {
  const items = Object.entries(entries);
  if (items.length === 0) {
    return <div className="text-sm text-slate-400 py-4">No metrics available.</div>;
  }
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2">
      {items.map(([key, value]) => (
        <div key={key} className="glass-card rounded-xl px-3 py-2.5">
          <div className="font-mono text-[13px] font-semibold text-white truncate" title={formatValue(value)}>
            {formatValue(value)}
          </div>
          <div className="text-[10px] text-slate-400 uppercase tracking-wider mt-1 truncate" title={key}>
            {key.replace(/_/g, " ")}
          </div>
        </div>
      ))}
    </div>
  );
}
