"""CBAD DevSecOps Pipeline Dashboard - executive summary view.

Run with: streamlit run app.py   (from inside the dashboard/ directory)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd
import streamlit as st

from core import ingestion
from core.charts import stacked_risk_bar, trend_spline_area
from core.grid import render_grid
from core.stage_loader import REPO_ROOT
from core.theme import (
    LEVEL_RANK,
    deepest_level,
    divider,
    icon_for_level,
    inject_theme,
    kpi_block,
    level_for,
    pulse_dot,
    section_header,
    stage_health_card,
)

st.set_page_config(page_title="CBAD Pipeline Dashboard", layout="wide", initial_sidebar_state="expanded")
inject_theme()

STAGE_LOADERS = {
    1: ("Pre-Commit Feature Collection", ingestion.load_stage1),
    2: ("Dependency Graph Trust", ingestion.load_stage2),
    3: ("CVE Risk Prediction", ingestion.load_stage3),
    4: ("SAST Taint Tracking", ingestion.load_stage4),
    5: ("Entropy & SLSA Attestation", ingestion.load_stage5),
    6: ("Syscall Monitor & Mitigation", ingestion.load_stage6),
    7: ("Cosign & K8s Admission", ingestion.load_stage7),
    8: ("DAST Interface & Attack Planning", ingestion.load_stage8),
    9: ("OPA Routing & SBOM Monitor", ingestion.load_stage9),
}


# ---------------------------------------------------------------------------
# Backend data loading (unchanged orchestration logic)
# ---------------------------------------------------------------------------

@st.cache_data(ttl=60, show_spinner=False)
def cached_load(stage_num: int):
    _, loader = STAGE_LOADERS[stage_num]
    return loader()


def safe_load(stage_num: int):
    try:
        return cached_load(stage_num), None
    except Exception as exc:  # noqa: BLE001 - surface any stage failure in the UI, don't crash the app
        return None, str(exc)


def _count(data, *path, default=0):
    cur = data
    try:
        for key in path:
            cur = cur[key]
        return len(cur) if isinstance(cur, (list, dict)) else cur
    except (KeyError, TypeError):
        return default


def compute_metrics(results):
    sast_findings = results.get(4, {}).get("findings", [])
    sast_critical = sum(1 for f in sast_findings if f.get("severity") in ("critical", "high"))

    entropy_findings = results.get(5, {}).get("entropy", {}).get("findings", [])
    entropy_high = sum(1 for f in entropy_findings if f.get("confidence") == "high")

    sbom_findings = results.get(9, {}).get("sbom_monitor", {}).get("findings", [])
    sbom_p0p1 = sum(1 for f in sbom_findings if f.get("severity_band") in ("P0", "P1"))

    cve_result = results.get(3, {}).get("result", {})
    cve_band = cve_result.get("risk_band", "n/a")
    cve_score = cve_result.get("risk_score", 0.0)

    syscall_events = results.get(6, {}).get("syscall_events", {}).get("events", [])
    lockdown_events = sum(1 for e in syscall_events if e.get("classification") == "lockdown")

    quarantine_summary = results.get(2, {}).get("summary", {})
    blocked_pkgs = quarantine_summary.get("blocked", 0) + quarantine_summary.get("quarantined", 0)

    admission_scenarios = results.get(7, {}).get("k8s_admission", {}).get("scenarios", {})
    admission_denied = sum(1 for s in admission_scenarios.values() if isinstance(s, dict) and not s.get("allowed", True))

    return {
        "sast_critical": sast_critical,
        "entropy_high": entropy_high,
        "sbom_p0p1": sbom_p0p1,
        "cve_band": cve_band,
        "cve_score": cve_score,
        "lockdown_events": lockdown_events,
        "blocked_pkgs": blocked_pkgs,
        "admission_denied": admission_denied,
    }


def compute_deepest_band(results, m):
    candidates = [m["cve_band"]]
    candidates += [f.get("severity") for f in results.get(4, {}).get("findings", [])]
    candidates += [f.get("severity_band") for f in results.get(9, {}).get("sbom_monitor", {}).get("findings", [])]
    candidates += [e.get("classification") for e in results.get(6, {}).get("syscall_events", {}).get("events", [])]
    candidates += [p.get("trust_category") for p in results.get(2, {}).get("packages", [])]
    return deepest_level(candidates)


def compute_findings_volume(results):
    return pd.Series(
        {
            "1 Pre-Commit": _count(results.get(1, {}), "payloads") if results.get(1) else 0,
            "2 DGT/Quarantine": len(results.get(2, {}).get("packages", [])),
            "3 CVE Predictor": 1 if results.get(3) else 0,
            "4 SAST": len(results.get(4, {}).get("findings", [])),
            "5 Entropy": len(results.get(5, {}).get("entropy", {}).get("findings", [])),
            "6 Syscalls": len(results.get(6, {}).get("syscall_events", {}).get("events", [])),
            "7 Cosign/K8s": len(results.get(7, {}).get("k8s_admission", {}).get("scenarios", {})),
            "8 DAST/Attack Plans": len(results.get(8, {}).get("spec", {}).get("operations", {})),
            "9 SBOM/OPA": len(results.get(9, {}).get("sbom_monitor", {}).get("findings", [])),
        }
    )


def compute_risk_breakdown(results):
    """Per-stage Critical/High/Medium/Low counts, for stages with classifiable findings."""
    stage_labels = ["2 Dependencies", "4 SAST", "5 Secrets", "6 Syscalls", "7 Admission", "9 SBOM"]
    buckets = {label: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0} for label in stage_labels}

    def bump(stage_label, raw_value):
        key = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}.get(level_for(raw_value))
        if key:
            buckets[stage_label][key] += 1

    for p in results.get(2, {}).get("packages", []):
        bump("2 Dependencies", p.get("trust_category"))
    for f in results.get(4, {}).get("findings", []):
        bump("4 SAST", f.get("severity"))
    for f in results.get(5, {}).get("entropy", {}).get("findings", []):
        bump("5 Secrets", f.get("confidence"))
    for e in results.get(6, {}).get("syscall_events", {}).get("events", []):
        bump("6 Syscalls", e.get("classification"))
    for scenario in results.get(7, {}).get("k8s_admission", {}).get("scenarios", {}).values():
        if isinstance(scenario, dict):
            bump("7 Admission", "allowed" if scenario.get("allowed") else "denied")
    for f in results.get(9, {}).get("sbom_monitor", {}).get("findings", []):
        bump("9 SBOM", f.get("severity_band"))

    df = pd.DataFrame(buckets).T[["Critical", "High", "Medium", "Low"]]
    return df[df.sum(axis=1) > 0]


# ---------------------------------------------------------------------------
# Rendering layer
# ---------------------------------------------------------------------------

def render_sidebar():
    st.sidebar.markdown(
        f'<div style="display:flex;align-items:center;margin-bottom:0.1rem;">'
        f'{pulse_dot("low")}<span style="font-size:0.72rem;color:#8B949E;letter-spacing:0.08em;text-transform:uppercase;font-weight:700;">Live</span>'
        f"</div>"
        f'<div style="font-size:1.15rem;font-weight:800;color:#F0F3F6;margin-bottom:0.1rem;">CBAD Command Center</div>'
        f'<div style="font-size:0.74rem;color:#8B949E;margin-bottom:1rem;word-break:break-all;">{REPO_ROOT}</div>',
        unsafe_allow_html=True,
    )
    if st.sidebar.button("Refresh all stage data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.sidebar.markdown('<div style="height:1.1rem;"></div>', unsafe_allow_html=True)
    with st.sidebar.expander("How data sourcing works"):
        st.caption(
            "Each stage page labels whether its data came from a **persisted artifact**, "
            "a **live scan** of this repository, or a **self-test fixture** (used only when "
            "no real target/artifact is available)."
        )
    with st.sidebar.expander("Navigation"):
        st.caption("Use the page list above to drill into any of the 9 pipeline stages for detailed controls and raw payloads.")


def render_hero():
    st.markdown(
        '<div class="cbad-hero">'
        '<div class="cbad-hero-title">Unified Security Posture</div>'
        '<div class="cbad-hero-sub">Single pane of glass across Stage 1 &mdash; Stage 9 of the CBAD DevSecOps pipeline.</div>'
        "</div>",
        unsafe_allow_html=True,
    )


def render_kpi_banner(pipeline_label, pipeline_level, triage_total, triage_level, deepest):
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(
            kpi_block("Global Pipeline Status", pipeline_label, level=pipeline_level, icon_name=icon_for_level(pipeline_level)),
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            kpi_block(
                "Total Vulnerabilities - Triage Queue",
                str(triage_total),
                level=triage_level,
                icon_name=icon_for_level(triage_level),
                sublabel="open items requiring review",
            ),
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            kpi_block("Deepest Mitigation Risk Band", deepest.upper(), level=deepest, icon_name="lock"),
            unsafe_allow_html=True,
        )


def render_status_matrix(results, errors, m):
    section_header("Stage Health Matrix", "Live status and key signal for every loader in the pipeline")

    sub_metrics = {
        1: f"{_count(results.get(1, {}), 'payloads') if results.get(1) else 0} payloads",
        2: f"{m['blocked_pkgs']} quarantined/blocked",
        3: f"risk band: {str(m['cve_band']).upper()}",
        4: f"{m['sast_critical']} critical/high findings",
        5: f"{m['entropy_high']} high-confidence secrets",
        6: f"{m['lockdown_events']} lockdown events",
        7: f"{m['admission_denied']} admissions denied",
        8: f"{len(results.get(8, {}).get('spec', {}).get('operations', {}))} endpoints ingested",
        9: f"{m['sbom_p0p1']} P0/P1 exposures",
    }
    level_overrides = {
        1: "low",
        2: "high" if m["blocked_pkgs"] else "low",
        3: level_for(m["cve_band"]),
        4: "high" if m["sast_critical"] else "low",
        5: "high" if m["entropy_high"] else "low",
        6: "critical" if m["lockdown_events"] else "low",
        7: "high" if m["admission_denied"] else "low",
        8: "low",
        9: "critical" if m["sbom_p0p1"] else "low",
    }

    cards_html = '<div class="cbad-stage-grid">'
    for n in range(1, 10):
        name = STAGE_LOADERS[n][0]
        if n in errors:
            cards_html += stage_health_card(n, name, "ERROR", "loader failed - see details below", "critical")
        else:
            lvl = level_overrides.get(n, "low")
            status = "ALERT" if lvl in ("high", "critical") else "OK"
            cards_html += stage_health_card(n, name, status, sub_metrics.get(n, ""), lvl)
    cards_html += "</div>"
    st.markdown(cards_html, unsafe_allow_html=True)


def render_critical_metrics(m):
    items = [
        ("SAST critical/high", m["sast_critical"], "high" if m["sast_critical"] else "low"),
        ("High-confidence secrets", m["entropy_high"], "high" if m["entropy_high"] else "low"),
        ("SBOM P0/P1 exposures", m["sbom_p0p1"], "critical" if m["sbom_p0p1"] else "low"),
        ("CVE risk band", str(m["cve_band"]).upper(), level_for(m["cve_band"])),
        ("Lockdown syscalls", m["lockdown_events"], "critical" if m["lockdown_events"] else "low"),
        ("Blocked/quarantined deps", m["blocked_pkgs"], "high" if m["blocked_pkgs"] else "low"),
        ("K8s admissions denied", m["admission_denied"], "high" if m["admission_denied"] else "low"),
    ]
    html = '<div class="cbad-metric-grid">'
    for label, value, level in items:
        html += kpi_block(label, str(value), level=level, icon_name=icon_for_level(level))
    html += "</div>"
    st.markdown(html, unsafe_allow_html=True)


def render_trend_chart(results):
    series = compute_findings_volume(results)
    st.plotly_chart(trend_spline_area(series, height=320), use_container_width=True)


def render_risk_breakdown_chart(results):
    df = compute_risk_breakdown(results)
    if df.empty:
        st.success("No severity-classified findings across SAST, secrets, SBOM, syscalls, dependencies, or admission control.")
        return
    st.plotly_chart(stacked_risk_bar(df, height=120 + 60 * len(df)), use_container_width=True)


def render_top_findings_table(results):
    combined = []

    for f in results.get(4, {}).get("findings", []):
        if f.get("severity") in ("critical", "high"):
            combined.append({"stage": "4 SAST", "severity": f["severity"], "summary": f"{f['category']} in {f['file_path']}:{f['source']['line_number']}"})

    for f in results.get(5, {}).get("entropy", {}).get("findings", []):
        if f.get("confidence") == "high":
            combined.append({"stage": "5 Entropy", "severity": "high", "summary": f"{f['rule_id']} in {f['file_path']}:{f['line_number']}"})

    for f in results.get(9, {}).get("sbom_monitor", {}).get("findings", []):
        if f.get("severity_band") in ("P0", "P1"):
            combined.append({"stage": "9 SBOM", "severity": f["severity_band"], "summary": f"{f['vulnerability']['vuln_id']} in {f['material']['name']}@{f['material']['version']}"})

    for e in results.get(6, {}).get("syscall_events", {}).get("events", []):
        if e.get("classification") == "lockdown":
            combined.append({"stage": "6 Syscall", "severity": "critical", "summary": f"{e['event']['syscall']} (score {e['score']:.2f}) on container {e['event']['container_id']}"})

    if not combined:
        st.success("No critical/high-severity findings in the currently loaded telemetry.")
        return

    df = pd.DataFrame(combined)
    render_grid(df, severity_col="severity", height=300, key="top-findings-grid")


def main():
    render_sidebar()
    render_hero()

    results, errors = {}, {}
    with st.spinner("Collecting telemetry from all 9 stages..."):
        for n in STAGE_LOADERS:
            data, err = safe_load(n)
            if err:
                errors[n] = err
            else:
                results[n] = data

    m = compute_metrics(results)
    deepest = compute_deepest_band(results, m)
    triage_total = m["sast_critical"] + m["entropy_high"] + m["sbom_p0p1"] + m["lockdown_events"] + m["blocked_pkgs"] + m["admission_denied"]
    triage_level = "critical" if triage_total > 10 else ("high" if triage_total > 5 else ("medium" if triage_total > 0 else "low"))

    pipeline_level = "critical" if errors else deepest
    pipeline_label = "ALERT" if LEVEL_RANK[pipeline_level] >= LEVEL_RANK["high"] else "OPERATIONAL"

    render_kpi_banner(pipeline_label, pipeline_level, triage_total, triage_level, deepest)
    divider()
    render_status_matrix(results, errors, m)
    divider()
    section_header("Critical Findings Across the Pipeline", "Aggregated from SAST, secrets, SBOM, syscalls, dependencies, and admission control")
    render_critical_metrics(m)
    divider()
    section_header("Vulnerability Ingestion Trend", "Telemetry volume captured at each stage of the pipeline")
    render_trend_chart(results)
    divider()
    section_header("Risk Breakdown by Stage", "Critical / High / Medium / Low composition of classified findings")
    render_risk_breakdown_chart(results)
    divider()
    section_header("Highest-Severity Findings (Combined)")
    render_top_findings_table(results)

    if errors:
        with st.expander(f"{len(errors)} stage(s) failed to load - click for details"):
            for n, err in errors.items():
                st.error(f"Stage {n} ({STAGE_LOADERS[n][0]}): {err}")


# ---------------------------------------------------------------------------
# Navigation - custom titles/icons instead of Streamlit's raw filename nav
# ---------------------------------------------------------------------------

PAGES = [
    st.Page(main, title="Overview", icon=":material/dashboard:", default=True),
    st.Page("pages/1_Stage1_PreCommit.py", title="Pre-Commit Intelligence", icon=":material/commit:"),
    st.Page("pages/2_Stage2_DGT_Quarantine.py", title="Dependency Trust", icon=":material/inventory_2:"),
    st.Page("pages/3_Stage3_CVE_Prediction.py", title="CVE Risk Prediction", icon=":material/psychology:"),
    st.Page("pages/4_Stage4_SAST_TaintTracking.py", title="SAST Taint Tracking", icon=":material/bug_report:"),
    st.Page("pages/5_Stage5_Entropy_SLSA.py", title="Secrets & SLSA Attestation", icon=":material/key:"),
    st.Page("pages/6_Stage6_Syscall_Mitigation.py", title="Syscall Monitor", icon=":material/terminal:"),
    st.Page("pages/7_Stage7_Cosign_K8s.py", title="Cosign & K8s Admission", icon=":material/verified_user:"),
    st.Page("pages/8_Stage8_DAST_AttackPlanning.py", title="DAST Attack Planning", icon=":material/travel_explore:"),
    st.Page("pages/9_Stage9_OPA_SBOM.py", title="OPA & SBOM Monitor", icon=":material/policy:"),
]

st.navigation(PAGES).run()
