"use client";

import { useId } from "react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, YAxis } from "recharts";

export function Sparkline({
  data,
  color = "#6366F1",
  height = 64,
}: {
  data: { label: string; value: number }[];
  color?: string;
  height?: number;
}) {
  const gradientId = useId();

  if (data.length === 0) {
    return <div style={{ height }} className="flex items-center text-xs text-slate-400">No history yet.</div>;
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.35} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <YAxis domain={[0, 100]} hide />
        <Tooltip
          contentStyle={{ background: "#1E293B", border: "1px solid rgba(255,255,255,0.15)", borderRadius: 10, fontSize: 11, padding: "4px 8px" }}
          labelStyle={{ color: "#FFFFFF", fontSize: 11 }}
          itemStyle={{ color, fontSize: 11 }}
          formatter={(value: number) => [`${value}/100`, "risk score"]}
        />
        <Area
          type="monotone"
          dataKey="value"
          stroke={color}
          strokeWidth={2}
          fill={`url(#${gradientId})`}
          dot={{ r: 2.5, stroke: color, strokeWidth: 1, fill: "#0F172A" }}
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
