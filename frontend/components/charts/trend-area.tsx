"use client";

import { useId } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const ACCENT = "#6366F1"; // brand indigo-500 - this is a volume trend, not a severity signal, so it uses the brand accent rather than red
const GRID = "rgba(255,255,255,0.1)";
const MUTED = "#94A3B8"; // slate-400

export function TrendArea({ data, height = 320 }: { data: { name: string; value: number }[]; height?: number }) {
  const gradientId = useId();
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 8, left: 0 }}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={ACCENT} stopOpacity={0.4} />
            <stop offset="100%" stopColor={ACCENT} stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="name" tick={{ fill: MUTED, fontSize: 11, fontFamily: "monospace" }} axisLine={{ stroke: GRID }} tickLine={false} />
        <YAxis tick={{ fill: MUTED, fontSize: 11, fontFamily: "monospace" }} axisLine={{ stroke: GRID }} tickLine={false} />
        <Tooltip
          contentStyle={{ background: "#1E293B", border: `1px solid rgba(255,255,255,0.15)`, borderRadius: 12, fontSize: 12 }}
          labelStyle={{ color: "#FFFFFF" }}
          itemStyle={{ color: ACCENT }}
        />
        <Area
          type="monotone"
          dataKey="value"
          stroke={ACCENT}
          strokeWidth={2.5}
          fill={`url(#${gradientId})`}
          dot={{ stroke: ACCENT, strokeWidth: 2, r: 3, fill: "#0F172A" }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
