"use client";

import { useEffect, useRef, useState } from "react";
import { TerminalSquare } from "lucide-react";
import { Card, CardTitle, CardValue } from "@/components/ui/card";
import { FalcoBadges } from "@/components/ui/falco-badges";
import { clientApiBase } from "@/lib/api";
import type { StageData } from "@/lib/types";

interface RuntimeEvent {
  event: {
    event_id: string;
    timestamp: string;
    container_id: string;
    pid: number;
    comm: string;
    syscall: string;
    args: Record<string, string>;
  };
  score: number;
  classification: "log" | "elevated" | "lockdown";
  falco_matches: Array<Record<string, unknown>>;
  is_anomalous: boolean;
}

const MAX_LINES = 300;
const RATE_WINDOW_MS = 5000;
const AUTO_SCROLL_THRESHOLD_PX = 120;

function formatArgs(args: Record<string, string>): string {
  return Object.entries(args ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(" ");
}

export function Stage6View({ data }: { data: StageData }) {
  const seed = (data.recent_events as RuntimeEvent[] | undefined) ?? [];
  const [lines, setLines] = useState<RuntimeEvent[]>(seed);
  const [connected, setConnected] = useState(false);
  const [eventsPerSec, setEventsPerSec] = useState(Number(data.events_per_sec ?? 0));
  const scrollRef = useRef<HTMLDivElement>(null);
  const arrivalsRef = useRef<number[]>([]);

  useEffect(() => {
    const es = new EventSource(`${clientApiBase()}/api/v1/stage/6/stream`);
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (msg) => {
      let payload: RuntimeEvent;
      try {
        payload = JSON.parse(msg.data) as RuntimeEvent;
      } catch {
        return;
      }
      arrivalsRef.current.push(Date.now());
      setLines((prev) => {
        const next = [...prev, payload];
        return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
      });
    };
    return () => es.close();
  }, []);

  useEffect(() => {
    const id = setInterval(() => {
      const now = Date.now();
      arrivalsRef.current = arrivalsRef.current.filter((t) => now - t <= RATE_WINDOW_MS);
      setEventsPerSec(Math.round((arrivalsRef.current.length / (RATE_WINDOW_MS / 1000)) * 10) / 10);
    }, 500);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    if (distanceFromBottom < AUTO_SCROLL_THRESHOLD_PX) {
      el.scrollTop = el.scrollHeight;
    }
  }, [lines]);

  const visibleAnomalies = lines.filter((l) => l.is_anomalous).length;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <Card glow={connected ? undefined : "critical"}>
          <CardTitle>Connection</CardTitle>
          <CardValue className={connected ? "text-emerald-400" : "text-red-500"}>
            {connected ? "LIVE" : "DISCONNECTED"}
          </CardValue>
        </Card>
        <Card>
          <CardTitle>Events / sec</CardTitle>
          <CardValue className="tabular-nums text-brand-light">{eventsPerSec.toFixed(1)}</CardValue>
        </Card>
        <Card glow={visibleAnomalies > 0 ? "critical" : undefined}>
          <CardTitle>Anomalous (visible)</CardTitle>
          <CardValue className="tabular-nums text-red-500">{visibleAnomalies}</CardValue>
        </Card>
        <Card>
          <CardTitle>Buffered lines</CardTitle>
          <CardValue className="tabular-nums">{lines.length}</CardValue>
        </Card>
      </div>

      <Card className="p-0 overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/10 bg-white/5">
          <TerminalSquare size={14} className="text-brand-light" />
          <span className="text-xs font-mono text-slate-300">stage6 :: runtime-syscall-monitor</span>
          <span
            className={`ml-auto h-1.5 w-1.5 rounded-full ${
              connected ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]" : "bg-red-500"
            }`}
          />
        </div>
        <div
          ref={scrollRef}
          className="font-mono text-[12px] leading-relaxed h-[480px] overflow-y-auto px-4 py-3 bg-black/40"
        >
          {lines.length === 0 && <div className="text-slate-500">Waiting for events...</div>}
          {lines.map((l) => (
            <div
              key={l.event.event_id}
              className={
                l.is_anomalous
                  ? "text-red-400 bg-red-500/10 px-1.5 py-0.5 -mx-1.5 rounded shadow-[0_0_8px_rgba(239,68,68,0.15)]"
                  : "text-slate-500"
              }
            >
              <span className="text-slate-600">{l.event.timestamp.slice(11, 19)}</span>{" "}
              <span className={l.is_anomalous ? "text-red-300 font-semibold" : "text-slate-400"}>
                {l.event.syscall}
              </span>{" "}
              <span>
                pid={l.event.pid} comm={l.event.comm}
              </span>{" "}
              <span>{formatArgs(l.event.args)}</span>
              {l.falco_matches.length > 0 && (
                <span className="ml-2 inline-block align-middle">
                  <FalcoBadges matches={l.falco_matches} />
                </span>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
