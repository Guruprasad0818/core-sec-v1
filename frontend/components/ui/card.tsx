import * as React from "react";
import { cn } from "@/lib/utils";

export function Card({
  className,
  glow,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { glow?: "critical" | "emerald" }) {
  return (
    <div
      className={cn(
        "glass-card rounded-2xl p-4 h-full",
        glow === "critical" && "border-red-500/30 shadow-[0_0_15px_rgba(239,68,68,0.2)]",
        glow === "emerald" && "border-emerald-500/30 shadow-glow-emerald",
        className
      )}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("flex items-center justify-between mb-2.5", className)} {...props} />;
}

export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("text-[10px] font-semibold uppercase tracking-wider text-slate-400", className)} {...props} />;
}

export function CardValue({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("font-mono text-[1.75rem] font-semibold leading-tight text-white", className)} {...props} />;
}

export function CardSub({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("text-xs mt-1 text-slate-400", className)} {...props} />;
}
