"use client";

import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { RiskBreakdownRow } from "@/lib/types";

const GRID = "rgba(255,255,255,0.1)";
const MUTED = "#94A3B8"; // slate-400

const STACK_COLORS: Record<string, string> = {
  critical: "#EF4444", // red-500
  high: "#EF4444",
  medium: "#F59E0B", // amber-500
  low: "#334155", // slate-700
};

export function RiskStackedBar({ data, height = 380 }: { data: RiskBreakdownRow[]; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 8, right: 16, bottom: 8, left: 8 }}>
        <CartesianGrid stroke={GRID} horizontal={false} />
        <XAxis type="number" tick={{ fill: MUTED, fontSize: 11, fontFamily: "monospace" }} axisLine={{ stroke: GRID }} tickLine={false} />
        <YAxis
          type="category"
          dataKey="stage"
          width={110}
          tick={{ fill: MUTED, fontSize: 11, fontFamily: "monospace" }}
          axisLine={{ stroke: GRID }}
          tickLine={false}
        />
        <Tooltip contentStyle={{ background: "#1E293B", border: `1px solid rgba(255,255,255,0.15)`, borderRadius: 12, fontSize: 12 }} labelStyle={{ color: "#FFFFFF" }} />
        <Legend wrapperStyle={{ fontSize: 11, color: MUTED }} />
        <Bar dataKey="critical" name="Critical" stackId="risk" fill={STACK_COLORS.critical} />
        <Bar dataKey="high" name="High" stackId="risk" fill={STACK_COLORS.high} />
        <Bar dataKey="medium" name="Medium" stackId="risk" fill={STACK_COLORS.medium} />
        <Bar dataKey="low" name="Low" stackId="risk" fill={STACK_COLORS.low} radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
