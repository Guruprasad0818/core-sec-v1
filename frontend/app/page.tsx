import { getOverview } from "@/lib/api";
import { Card, CardHeader, CardSub, CardTitle, CardValue } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { TrendArea } from "@/components/charts/trend-area";
import { RiskStackedBar } from "@/components/charts/risk-stacked-bar";
import { DataGrid } from "@/components/data-grid";

export const dynamic = "force-dynamic";

const ALERT_LEVELS = new Set(["high", "critical"]);

function SectionHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="mt-1 mb-3.5 pb-2 border-b border-white/10">
      <h3 className="text-base font-bold text-white">{title}</h3>
      {subtitle && <div className="text-[13px] text-slate-400 mt-0.5">{subtitle}</div>}
    </div>
  );
}

export default async function OverviewPage() {
  let overview;
  let loadError: string | null = null;
  try {
    overview = await getOverview();
  } catch (err) {
    loadError = err instanceof Error ? err.message : String(err);
  }

  if (loadError || !overview) {
    return (
      <div className="space-y-2">
        <h1 className="text-2xl font-bold text-white">Unified Security Posture</h1>
        <Card glow="critical" className="border-red-500/20">
          <CardTitle>API unreachable</CardTitle>
          <CardSub className="mt-2 text-slate-300">
            Could not reach the CBAD API at <code className="font-mono">{process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000"}</code>.
            Make sure the FastAPI server is running (<code className="font-mono">uvicorn main:app --port 8000</code> from server/).
          </CardSub>
          <CardSub className="mt-2 font-mono text-red-500">{loadError}</CardSub>
        </Card>
      </div>
    );
  }

  const trendData = Object.entries(overview.findings_volume).map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-[1.85rem] font-bold tracking-tight text-white">Unified Security Posture</h1>
        <p className="text-slate-400 text-[13px] mt-1">
          Single pane of glass across Stage 1 &mdash; Stage 9 of the CBAD DevSecOps pipeline.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
        <Card glow={ALERT_LEVELS.has(overview.pipeline_level) ? "critical" : undefined}>
          <CardHeader>
            <Badge level={overview.pipeline_level as any}>{overview.pipeline_level}</Badge>
          </CardHeader>
          <CardValue>{overview.pipeline_label}</CardValue>
          <CardTitle className="mt-2">Global Pipeline Status</CardTitle>
        </Card>
        <Card glow={ALERT_LEVELS.has(overview.triage_level) ? "critical" : undefined}>
          <CardHeader>
            <Badge level={overview.triage_level as any}>{overview.triage_level}</Badge>
          </CardHeader>
          <CardValue>{overview.triage_total}</CardValue>
          <CardTitle className="mt-2">Total Vulnerabilities - Triage Queue</CardTitle>
          <CardSub>open items requiring review</CardSub>
        </Card>
        <Card glow={ALERT_LEVELS.has(overview.deepest_level) ? "critical" : undefined}>
          <CardHeader>
            <Badge level={overview.deepest_level as any}>{overview.deepest_level}</Badge>
          </CardHeader>
          <CardValue>{overview.deepest_level.toUpperCase()}</CardValue>
          <CardTitle className="mt-2">Deepest Mitigation Risk Band</CardTitle>
        </Card>
      </div>

      <section>
        <SectionHeader title="Stage Health Matrix" subtitle="Live status and key signal for every loader in the pipeline" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-2.5">
          {overview.stage_health.map((s) => (
            <Card key={s.stage} className="p-3.5" glow={ALERT_LEVELS.has(s.level) ? "critical" : undefined}>
              <div className="flex items-center justify-between mb-2">
                <span className="font-mono text-[10px] font-bold text-slate-400 tracking-wide">STAGE {s.stage}</span>
                <Badge level={s.level as any}>{s.status}</Badge>
              </div>
              <div className="text-[0.85rem] font-semibold text-white mb-1 min-h-[2.2em]">{s.name}</div>
              <div className="font-mono text-[13px] font-medium text-slate-300">{s.error ?? s.sub_metric}</div>
            </Card>
          ))}
        </div>
      </section>

      <section>
        <SectionHeader
          title="Critical Findings Across the Pipeline"
          subtitle="Aggregated from SAST, secrets, SBOM, syscalls, dependencies, and admission control"
        />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {overview.critical_metrics.map((m) => (
            <Card key={m.label} className="p-3.5" glow={ALERT_LEVELS.has(m.level) ? "critical" : undefined}>
              <CardHeader>
                <Badge level={m.level as any}>{m.level}</Badge>
              </CardHeader>
              <CardValue>{m.value}</CardValue>
              <CardTitle className="mt-2">{m.label}</CardTitle>
            </Card>
          ))}
        </div>
      </section>

      <section>
        <SectionHeader title="Vulnerability Ingestion Trend" subtitle="Telemetry volume captured at each stage of the pipeline" />
        <Card>
          <TrendArea data={trendData} />
        </Card>
      </section>

      <section>
        <SectionHeader title="Risk Breakdown by Stage" subtitle="Critical / High / Medium / Low composition of classified findings" />
        {overview.risk_breakdown.length === 0 ? (
          <Card className="text-sm text-emerald-400">
            No severity-classified findings across SAST, secrets, SBOM, syscalls, dependencies, or admission control.
          </Card>
        ) : (
          <Card>
            <RiskStackedBar data={overview.risk_breakdown} height={120 + 60 * overview.risk_breakdown.length} />
          </Card>
        )}
      </section>

      <section>
        <SectionHeader title="Highest-Severity Findings (Combined)" />
        {overview.top_findings.length === 0 ? (
          <Card className="text-sm text-emerald-400">No critical/high-severity findings in the currently loaded telemetry.</Card>
        ) : (
          <DataGrid data={overview.top_findings as unknown as Record<string, unknown>[]} severityColumn="severity" maxHeight={420} />
        )}
      </section>

      {Object.keys(overview.errors).length > 0 && (
        <Card glow="critical" className="border-red-500/20">
          <CardTitle>{Object.keys(overview.errors).length} stage(s) failed to load</CardTitle>
          <div className="mt-2 space-y-1">
            {Object.entries(overview.errors).map(([stage, err]) => (
              <div key={stage} className="text-sm text-red-500 font-mono">
                Stage {stage}: {err}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
