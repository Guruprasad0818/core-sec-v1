"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard } from "lucide-react";
import { cn } from "@/lib/utils";
import { STAGE_TITLES } from "@/lib/types";

const STAGES = Object.entries(STAGE_TITLES).map(([num, title]) => ({
  num: Number(num),
  title,
}));

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 shrink-0 sticky top-0 h-screen overflow-y-auto border-r border-white/10 bg-slate-950/80 backdrop-blur-lg shadow-2xl shadow-black/40 p-4 flex flex-col gap-1">
      <div className="flex items-center gap-2 mb-1 px-1">
        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 inline-block shadow-[0_0_8px_rgba(52,211,153,0.6)]" />
        <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Live</span>
      </div>
      <div className="text-[1.05rem] font-bold text-white px-1 mb-4 tracking-tight">CBAD Command Center</div>

      <Link
        href="/"
        className={cn(
          "flex items-center gap-2.5 rounded-xl px-3 py-2 text-sm font-medium transition-colors",
          pathname === "/" ? "bg-brand/10 text-white" : "text-slate-300 hover:bg-white/10 hover:text-white"
        )}
      >
        <LayoutDashboard size={16} className={pathname === "/" ? "text-brand-light" : undefined} />
        Overview
      </Link>

      <div className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 mt-5 mb-1 px-3">
        Pipeline Stages
      </div>
      {STAGES.map(({ num, title }) => {
        const href = `/stage/${num}`;
        const active = pathname === href;
        return (
          <Link
            key={num}
            href={href}
            className={cn(
              "flex items-center gap-2.5 rounded-xl px-3 py-2 text-sm transition-colors relative",
              active ? "bg-brand/10 text-white font-medium" : "text-slate-300 hover:bg-white/10 hover:text-white"
            )}
          >
            {active && <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-full bg-brand shadow-glow-brand" />}
            <span className={cn("font-mono text-[10px] w-5", active ? "text-brand-light" : "text-slate-400")}>
              {String(num).padStart(2, "0")}
            </span>
            <span className="truncate">{title}</span>
          </Link>
        );
      })}
    </aside>
  );
}
