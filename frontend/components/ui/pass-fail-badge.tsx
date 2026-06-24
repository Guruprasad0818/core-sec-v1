import { Check, X } from "lucide-react";
import { cn } from "@/lib/utils";

/** Bright green/red pass-fail indicator for binary verdicts (Stage 7's
 * cosign/admission checks) - a boolean-driven sibling of Badge, using the
 * same red/emerald recipe rather than the levelFor() string vocabulary. */
export function PassFailBadge({
  pass,
  passText = "PASS",
  failText = "FAIL",
}: {
  pass: boolean;
  passText?: string;
  failText?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[0.7rem] font-bold uppercase tracking-wider whitespace-nowrap",
        pass ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" : "text-red-500 bg-red-500/10 border-red-500/20"
      )}
    >
      {pass ? <Check size={12} /> : <X size={12} />}
      {pass ? passText : failText}
    </span>
  );
}
