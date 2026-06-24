"use client";

import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const GRID = "rgba(255,255,255,0.1)";
const MUTED = "#94A3B8"; // slate-400

export interface EntropyHistogramBucket {
  bucket: string;
  count: number;
}

// Low buckets sit just above the engine's charset-relative threshold (mostly
// borderline/noisy matches); high buckets are rare and far more likely to be
// a genuine credential - color ramps from muted amber to critical red to
// carry that signal at a glance, consistent with the rest of the app's
// severity palette.
const BUCKET_COLORS = ["#F59E0B", "#F59E0B", "#FB923C", "#FB923C", "#EF4444", "#EF4444", "#EF4444"];

export function EntropyHistogram({ data, height = 220 }: { data: EntropyHistogramBucket[]; height?: number }) {
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis
          dataKey="bucket"
          tick={{ fill: MUTED, fontSize: 11, fontFamily: "monospace" }}
          axisLine={{ stroke: GRID }}
          tickLine={false}
        />
        <YAxis tick={{ fill: MUTED, fontSize: 11, fontFamily: "monospace" }} axisLine={{ stroke: GRID }} tickLine={false} allowDecimals={false} />
        <Tooltip
          contentStyle={{ background: "#1E293B", border: "1px solid rgba(255,255,255,0.15)", borderRadius: 12, fontSize: 12 }}
          labelStyle={{ color: "#FFFFFF" }}
          formatter={(value: number) => [value, "findings"]}
          labelFormatter={(label) => `${label} bits/char`}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {data.map((entry, i) => (
            <Cell key={entry.bucket} fill={BUCKET_COLORS[i % BUCKET_COLORS.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
