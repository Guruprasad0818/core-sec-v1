import { cn } from "@/lib/utils";

type FalcoMatch = Record<string, unknown>;

const PRIORITY_STYLE: Record<string, string> = {
  emergency: "text-red-500 bg-red-500/10 border-red-500/20",
  alert: "text-red-500 bg-red-500/10 border-red-500/20",
  critical: "text-red-500 bg-red-500/10 border-red-500/20",
  error: "text-red-500 bg-red-500/10 border-red-500/20",
  warning: "text-amber-500 bg-amber-500/10 border-amber-500/20",
  notice: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  informational: "text-blue-400 bg-blue-400/10 border-blue-400/20",
  debug: "text-slate-400 bg-white/10 border-white/10",
};

/** Stage 6's falco_matches arrive as [{rule_id, priority, output, tags, ...}]
 * - render each as a compact inline warning pill instead of raw JSON. */
export function FalcoBadges({ matches }: { matches: FalcoMatch[] }) {
  if (!matches || matches.length === 0) {
    return <span className="text-slate-400 text-xs">clear</span>;
  }
  return (
    <div className="flex flex-wrap gap-1 py-0.5">
      {matches.map((m, i) => {
        const style = PRIORITY_STYLE[String(m.priority ?? "").toLowerCase()] ?? PRIORITY_STYLE.notice;
        return (
          <span
            key={`${String(m.rule_id ?? "rule")}-${i}`}
            title={typeof m.output === "string" ? m.output : undefined}
            className={cn(
              "inline-flex items-center rounded-full border px-2 py-0.5 text-[0.68rem] font-bold uppercase tracking-wide whitespace-nowrap",
              style
            )}
          >
            {String(m.rule_id ?? "rule")}
          </span>
        );
      })}
    </div>
  );
}
