"""Overview aggregation: ports the KPI/stage-health/findings-volume/risk
breakdown computations from dashboard/app.py into framework-free Python so
the API can serve the same executive summary to the Next.js frontend.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict

from risk import LEVEL_RANK, deepest_level, level_for
from schemas import FindingRow, MetricItem, OverviewResponse, RiskBreakdownRow, StageHealth

STAGE_META = {
    1: "Pre-Commit Feature Collection",
    2: "Semgrep Vulnerability Scan",
    3: "Predictive Risk Analytics",
    4: "Automated Mitigation",
    5: "Entropy & SLSA Attestation",
    6: "Runtime Syscall Monitoring",
    7: "Compliance Tracking & Governance",
    8: "Supply Chain Security & SLSA Provenance",
    9: "Final Policy Gate & Executive Reporting",
}


def compute_metrics(results: Dict[int, Any]) -> Dict[str, Any]:
    remediation_result = results.get(4, {})
    remediation_fixable = remediation_result.get("fixable_count", 0)
    remediation_total = remediation_result.get("total_count", 0)

    entropy_findings = results.get(5, {}).get("entropy", {}).get("findings", [])
    entropy_high = sum(1 for f in entropy_findings if f.get("confidence") == "high")

    risk_result = results.get(3, {})
    risk_band = risk_result.get("risk_band", "n/a")
    risk_score = risk_result.get("risk_score", 0)

    syscall_events = results.get(6, {}).get("recent_events", [])
    lockdown_events = sum(1 for e in syscall_events if e.get("classification") == "lockdown")
    events_per_sec = results.get(6, {}).get("events_per_sec", 0.0)

    semgrep_result = results.get(2, {})
    semgrep_critical = semgrep_result.get("critical_count", 0)
    semgrep_high = semgrep_result.get("high_count", 0)
    semgrep_total = semgrep_result.get("total_issues", 0)

    compliance_result = results.get(7, {})
    compliance_failed = compliance_result.get("rules_failed", 0)
    owasp_readiness_pct = compliance_result.get("owasp", {}).get("readiness_pct", 0.0)
    soc2_readiness_pct = compliance_result.get("soc2", {}).get("readiness_pct", 0.0)

    supply_chain_result = results.get(8, {})
    attestation_failed = supply_chain_result.get("attestation_status") == "FAILED"
    sbom_completeness_pct = supply_chain_result.get("sbom_completeness_pct", 0.0)

    policy_gate_result = results.get(9, {})
    deployment_blocked = policy_gate_result.get("deployment_status") == "BLOCKED"
    failed_gate_count = len(policy_gate_result.get("failure_reasons", []))

    return {
        "remediation_fixable": remediation_fixable,
        "remediation_total": remediation_total,
        "entropy_high": entropy_high,
        "risk_band": risk_band,
        "risk_score": risk_score,
        "lockdown_events": lockdown_events,
        "events_per_sec": events_per_sec,
        "semgrep_critical": semgrep_critical,
        "semgrep_high": semgrep_high,
        "semgrep_total": semgrep_total,
        "compliance_failed": compliance_failed,
        "owasp_readiness_pct": owasp_readiness_pct,
        "soc2_readiness_pct": soc2_readiness_pct,
        "attestation_failed": attestation_failed,
        "sbom_completeness_pct": sbom_completeness_pct,
        "deployment_blocked": deployment_blocked,
        "failed_gate_count": failed_gate_count,
    }


def compute_deepest_band(results: Dict[int, Any], m: Dict[str, Any]) -> str:
    # Stage 9's deployment_blocked is deliberately excluded here - it's a
    # pure derivation of Stage 2/5/7/8's own signals (see policy_gate.py),
    # which are either already counted via the candidates below or via
    # build_overview()'s pipeline_level override. Adding it here too would
    # double-count the same underlying finding.
    candidates = [m["risk_band"]]
    candidates += [e.get("classification") for e in results.get(6, {}).get("recent_events", [])]
    candidates += [f.get("severity") for f in results.get(2, {}).get("findings", [])]
    if m["attestation_failed"]:
        candidates.append("critical")
    return deepest_level(candidates)


def compute_findings_volume(results: Dict[int, Any]) -> Dict[str, int]:
    return {
        "1 Pre-Commit": len(results.get(1, {}).get("commits", [])),
        "2 Semgrep": results.get(2, {}).get("total_issues", 0),
        "3 Risk Correlation": results.get(3, {}).get("recent_files_count", 0),
        "4 Remediation": results.get(4, {}).get("fixable_count", 0),
        "5 Entropy": len(results.get(5, {}).get("entropy", {}).get("findings", [])),
        "6 Syscalls": results.get(6, {}).get("total_events", 0),
        "7 Compliance": results.get(7, {}).get("total_violations", 0),
        "8 Supply Chain": results.get(8, {}).get("dependency_count", 0),
        "9 Policy Gate": len(results.get(9, {}).get("failure_reasons", [])),
    }


def compute_risk_breakdown(results: Dict[int, Any]) -> list[RiskBreakdownRow]:
    stage_labels = ["2 Semgrep", "5 Secrets", "6 Syscalls", "7 Compliance"]
    buckets = {label: Counter() for label in stage_labels}

    def bump(stage_label: str, raw_value: Any) -> None:
        key = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(level_for(raw_value))
        if key:
            buckets[stage_label][key] += 1

    for f in results.get(2, {}).get("findings", []):
        bump("2 Semgrep", f.get("severity"))
    for f in results.get(5, {}).get("entropy", {}).get("findings", []):
        bump("5 Secrets", f.get("confidence"))
    for e in results.get(6, {}).get("recent_events", []):
        bump("6 Syscalls", e.get("classification"))
    for v in results.get(7, {}).get("violations", []):
        bump("7 Compliance", v.get("severity"))

    rows = []
    for label, counts in buckets.items():
        total = sum(counts.values())
        if total > 0:
            rows.append(
                RiskBreakdownRow(
                    stage=label,
                    critical=counts["critical"],
                    high=counts["high"],
                    medium=counts["medium"],
                    low=counts["low"],
                )
            )
    return rows


def compute_top_findings(results: Dict[int, Any]) -> list[FindingRow]:
    combined: list[FindingRow] = []

    for f in results.get(2, {}).get("findings", []):
        if f.get("severity") in ("critical", "high"):
            combined.append(
                FindingRow(
                    stage="2 Semgrep",
                    severity=f["severity"],
                    summary=f"{f['finding_id']} in {f['file_path']}:{f['line_number']}",
                )
            )

    for f in results.get(5, {}).get("entropy", {}).get("findings", []):
        if f.get("confidence") == "high":
            combined.append(
                FindingRow(
                    stage="5 Entropy",
                    severity="high",
                    summary=f"{f['rule_id']} in {f['file_path']}:{f['line_number']}",
                )
            )

    for e in results.get(6, {}).get("recent_events", []):
        if e.get("classification") == "lockdown":
            combined.append(
                FindingRow(
                    stage="6 Syscall",
                    severity="critical",
                    summary=f"{e['event']['syscall']} (score {e['score']:.2f}) on container {e['event']['container_id']}",
                )
            )

    for v in results.get(7, {}).get("violations", []):
        if v.get("severity") in ("critical", "high"):
            combined.append(
                FindingRow(
                    stage="7 Compliance",
                    severity=v["severity"],
                    summary=f"{v['control_id']} ({v['framework']}): {v['summary']}",
                )
            )

    supply_chain = results.get(8, {})
    if supply_chain.get("attestation_status") == "FAILED":
        combined.append(
            FindingRow(
                stage="8 Supply Chain",
                severity="critical",
                summary=f"Pipeline attestation FAILED (SLSA level {supply_chain.get('slsa_level')}/{supply_chain.get('slsa_level_target')}, artifact {str(supply_chain.get('artifact_digest', ''))[:12]})",
            )
        )

    policy_gate = results.get(9, {})
    if policy_gate.get("deployment_status") == "BLOCKED":
        reasons = policy_gate.get("failure_reasons", [])
        combined.append(
            FindingRow(
                stage="9 Policy Gate",
                severity="critical",
                summary=f"Deployment BLOCKED by {len(reasons)} governance gate(s): {'; '.join(reasons)}",
            )
        )

    return combined


def build_overview(results: Dict[int, Any], errors: Dict[int, str]) -> OverviewResponse:
    m = compute_metrics(results)
    deepest = compute_deepest_band(results, m)
    triage_total = (
        m["entropy_high"] + m["lockdown_events"]
        + m["semgrep_critical"] + m["semgrep_high"] + m["compliance_failed"]
        + (1 if m["attestation_failed"] else 0)
    )
    triage_level = "critical" if triage_total > 10 else ("high" if triage_total > 5 else ("medium" if triage_total > 0 else "low"))

    # Stage 9 is the authoritative Go/No-Go verdict over Stage 2/5/7/8's
    # signals - if it says BLOCKED, the headline pipeline level must read
    # critical even on the rare combination (failing SOC 2 readiness or
    # exposed secrets alone) that compute_deepest_band's per-finding-severity
    # walk wouldn't otherwise escalate to critical on its own.
    pipeline_level = "critical" if (errors or m["deployment_blocked"]) else deepest
    pipeline_label = "ALERT" if LEVEL_RANK[pipeline_level] >= LEVEL_RANK["high"] else "OPERATIONAL"

    sub_metrics = {
        1: f"{len(results.get(1, {}).get('commits', []))} commits on {results.get(1, {}).get('active_branch', 'n/a')}",
        2: f"{m['semgrep_total']} issues ({m['semgrep_critical']} critical, {m['semgrep_high']} high)",
        3: f"risk score {m['risk_score']}/100 ({str(m['risk_band']).upper()})",
        4: f"{m['remediation_fixable']} of {m['remediation_total']} findings auto-fixable",
        5: f"{m['entropy_high']} high-confidence secrets",
        6: f"{m['lockdown_events']} lockdown events ({m['events_per_sec']}/sec)",
        7: f"{m['compliance_failed']} controls failing (OWASP {m['owasp_readiness_pct']}% / SOC2 {m['soc2_readiness_pct']}%)",
        8: f"attestation {'PASSED' if not m['attestation_failed'] else 'FAILED'} (SBOM {m['sbom_completeness_pct']}% complete)",
        9: f"deployment {'BLOCKED' if m['deployment_blocked'] else 'APPROVED'} ({m['failed_gate_count']} gate(s) failing)",
    }
    level_overrides = {
        1: "low",
        2: "critical" if m["semgrep_critical"] else ("high" if m["semgrep_high"] else "low"),
        3: level_for(m["risk_band"]),
        4: "low",  # an action center, not its own risk signal - severity already captured by Stage 2/3
        5: "high" if m["entropy_high"] else "low",
        6: "critical" if m["lockdown_events"] else "low",
        7: "high" if m["compliance_failed"] else "low",
        8: "critical" if m["attestation_failed"] else "low",
        9: "critical" if m["deployment_blocked"] else "low",
    }

    stage_health = []
    for n, name in STAGE_META.items():
        if n in errors:
            stage_health.append(
                StageHealth(stage=n, name=name, status="ERROR", level="critical", sub_metric="loader failed - see details below", error=errors[n])
            )
        else:
            lvl = level_overrides.get(n, "low")
            status = "ALERT" if lvl in ("high", "critical") else "OK"
            stage_health.append(StageHealth(stage=n, name=name, status=status, level=lvl, sub_metric=sub_metrics.get(n, "")))

    critical_metrics = [
        MetricItem(label="Auto-fixable findings", value=f"{m['remediation_fixable']}/{m['remediation_total']}", level="low"),
        MetricItem(label="High-confidence secrets", value=str(m["entropy_high"]), level="high" if m["entropy_high"] else "low"),
        MetricItem(label="Repository risk score", value=f"{m['risk_score']}/100", level=level_for(m["risk_band"])),
        MetricItem(label="Lockdown syscalls", value=str(m["lockdown_events"]), level="critical" if m["lockdown_events"] else "low"),
        MetricItem(label="Semgrep critical/high findings", value=str(m["semgrep_critical"] + m["semgrep_high"]), level="critical" if m["semgrep_critical"] else ("high" if m["semgrep_high"] else "low")),
        MetricItem(label="Compliance controls failing", value=str(m["compliance_failed"]), level="high" if m["compliance_failed"] else "low"),
        MetricItem(label="Pipeline attestation", value="FAILED" if m["attestation_failed"] else "PASSED", level="critical" if m["attestation_failed"] else "low"),
        MetricItem(label="Final deployment status", value="BLOCKED" if m["deployment_blocked"] else "APPROVED", level="critical" if m["deployment_blocked"] else "low"),
    ]

    return OverviewResponse(
        pipeline_label=pipeline_label,
        pipeline_level=pipeline_level,
        triage_total=triage_total,
        triage_level=triage_level,
        deepest_level=deepest,
        stage_health=stage_health,
        critical_metrics=critical_metrics,
        findings_volume=compute_findings_volume(results),
        risk_breakdown=compute_risk_breakdown(results),
        top_findings=compute_top_findings(results),
        errors=errors,
    )
