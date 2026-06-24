import type { OverviewResponse, RemediateResponse, StageData, StageMeta } from "./types";

// Two different base URLs are required in Docker: this file's Server
// Component callers (getOverview/getStages/getStage) execute inside the
// Next.js container's own Node process, which must reach the backend over
// the internal Docker network (http://backend:8000 - "backend" only
// resolves via Docker's internal DNS). The "use client" caller
// (remediateFinding) executes in the user's actual browser on the host
// machine, which has no knowledge of that network and must use the port
// published to the host (http://localhost:8000). NEXT_PUBLIC_* vars are the
// only ones visible client-side, so INTERNAL_API_BASE is deliberately not
// prefixed - referencing it from client code would just be undefined.
const SERVER_API_BASE = process.env.INTERNAL_API_BASE ?? process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";
const CLIENT_API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

function apiBase(): string {
  return typeof window === "undefined" ? SERVER_API_BASE : CLIENT_API_BASE;
}

// For client components that need to build a URL by hand (Stage 6's
// EventSource can't go through getJSON/postJSON) rather than duplicating
// the localhost fallback default inline.
export function clientApiBase(): string {
  return CLIENT_API_BASE;
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${apiBase()}${path}`, { cache: "no-store" });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${body}`);
  }
  return res.json() as Promise<T>;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${apiBase()}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export function getOverview(): Promise<OverviewResponse> {
  return getJSON<OverviewResponse>("/api/v1/overview");
}

export function getStages(): Promise<StageMeta[]> {
  return getJSON<StageMeta[]>("/api/v1/stages");
}

export function getStage(stageNum: number): Promise<StageData> {
  return getJSON<StageData>(`/api/v1/stage/${stageNum}`);
}

export function remediateFinding(instanceId: string): Promise<RemediateResponse> {
  return postJSON<RemediateResponse>("/api/v1/stage/4/remediate", { instance_id: instanceId });
}
