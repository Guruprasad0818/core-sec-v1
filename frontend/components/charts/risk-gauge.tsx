"use client";

import { useId } from "react";
import { RadialBar, RadialBarChart, PolarAngleAxis } from "recharts";

export function RiskGauge({
  score,
  label,
  color,
  size = 220,
}: {
  /** 0..1 */
  score: number;
  label: string;
  color: string;
  size?: number;
}) {
  const gradientId = useId();
  const pct = Math.max(0, Math.min(1, score)) * 100;
  const data = [{ name: "risk", value: pct }];

  return (
    <div className="relative inline-block" style={{ width: size, height: size }}>
      <RadialBarChart
        width={size}
        height={size}
        innerRadius="72%"
        outerRadius="100%"
        data={data}
        startAngle={90}
        endAngle={-270}
      >
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={1} />
            <stop offset="100%" stopColor={color} stopOpacity={0.25} />
          </linearGradient>
        </defs>
        <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
        <RadialBar
          background={{ fill: "rgba(255,255,255,0.1)" }}
          dataKey="value"
          cornerRadius={10}
          fill={`url(#${gradientId})`}
        />
      </RadialBarChart>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="font-mono text-[2rem] font-bold leading-none" style={{ color }}>
          {pct.toFixed(1)}%
        </span>
        <span className="text-[10px] uppercase tracking-widest text-slate-400 mt-1.5">{label}</span>
      </div>
    </div>
  );
}
