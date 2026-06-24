import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";
import { levelFor, type RiskLevel } from "@/lib/risk";

/** High-signal status badge: dark translucent fill, bright text, thin border.
 * critical/high -> red (FAIL/DENIED/CRITICAL), low -> emerald (PASS/ALLOWED/
 * TRUSTED), medium -> amber (WARNING), neutral -> electric blue (info/no-signal). */
const badgeVariants = cva(
  "inline-flex items-center whitespace-nowrap rounded-full px-2.5 py-0.5 text-[0.7rem] font-bold uppercase tracking-wider border",
  {
    variants: {
      level: {
        critical: "text-red-500 bg-red-500/10 border-red-500/20",
        high: "text-red-500 bg-red-500/10 border-red-500/20",
        medium: "text-amber-500 bg-amber-500/10 border-amber-500/20",
        low: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
        neutral: "text-blue-400 bg-blue-400/10 border-blue-400/20",
      } satisfies Record<RiskLevel, string>,
    },
    defaultVariants: {
      level: "neutral",
    },
  }
);

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {
  value?: unknown;
}

export function Badge({ className, level, value, children, ...props }: BadgeProps) {
  const resolved = level ?? (value !== undefined ? levelFor(value) : "neutral");
  return (
    <span className={cn(badgeVariants({ level: resolved }), className)} {...props}>
      {children}
    </span>
  );
}
