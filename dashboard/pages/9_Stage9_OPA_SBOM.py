import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import streamlit as st

from core import ingestion
from core.charts import severity_bar
from core.grid import render_grid
from core.theme import badge, divider, inject_theme, section_header

inject_theme()

st.title("Stage 9: OPA Event Router & SBOM/CVE Exposure Monitor")
st.caption("opa_event_router.py + sbom_monitor.py")

left, right = st.columns([1, 2], gap="large")

with left:
    st.markdown('<div class="cbad-panel-label">Data Controls</div>', unsafe_allow_html=True)
    use_live_feeds = st.checkbox("Query live OSV/GHSA feeds (requires network)", value=False)

    @st.cache_data(ttl=60, show_spinner=False)
    def cached_stage9(live: bool):
        return ingestion.load_stage9(use_live_feeds=live)

    data = cached_stage9(use_live_feeds)
    sbom = data["sbom_monitor"]
    router = data["event_router"]

    st.markdown(badge(f"Feed: {sbom['source']}".upper(), level="low"), unsafe_allow_html=True)
    st.markdown(badge(f"Archive: {router['source']}".upper(), level="low" if router["source"] != "none" else "neutral"), unsafe_allow_html=True)

    with st.expander("Routing policy"):
        st.caption("Events in auto-mitigate severity bands trigger telemetry capture + rollback, unless a "
                    "rollback guard detects the resource is already at its last known-good revision.")

with right:
    section_header("SBOM Exposure Monitor", "CVE exposure findings against the materials in this SBOM")
    findings = sbom["findings"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total findings", len(findings))
    for col, band in zip((c2, c3, c4), ["P0", "P1", "P2"]):
        count = sum(1 for f in findings if f["severity_band"] == band)
        with col:
            st.markdown(badge(band, level="critical" if band == "P0" else ("high" if band == "P1" else "medium")), unsafe_allow_html=True)
            st.metric(" ", count)

    if findings:
        rows = [
            {
                "package": f["material"]["name"],
                "version": f["material"]["version"],
                "vuln_id": f["vulnerability"]["vuln_id"],
                "severity": f["vulnerability"]["severity"],
                "severity_band": f["severity_band"],
                "exposure_score": round(f["exposure_score"], 3),
                "cluster": f["material"].get("cluster"),
                "namespace": f["material"].get("namespace"),
            }
            for f in findings
        ]
        df = pd.DataFrame(rows)
        render_grid(df, severity_col="severity_band", height=340, key="sbom-findings-grid")
        st.plotly_chart(severity_bar(df["severity_band"].value_counts(), height=260), use_container_width=True)
    else:
        st.success("No CVE exposure findings for the materials scanned.")

    divider()
    section_header("Guardian Event Router & Evidence Archive")
    routing = router["routing_demo"]
    results = routing.get("results", {})
    rows = []
    for scenario, outcome in results.items():
        decision = outcome.get("decision", outcome)
        rows.append({"scenario": scenario, **(decision if isinstance(decision, dict) else {"result": decision})})
    if rows:
        df = pd.DataFrame(rows)
        if "should_mitigate" in df.columns:
            df["should_mitigate"] = df["should_mitigate"].map(lambda v: "MITIGATE" if v else "SKIP")
            render_grid(df, severity_col="should_mitigate", height=260, key="event-router-grid")
        else:
            render_grid(df, height=260, key="event-router-grid")

    c1, c2, c3 = st.columns(3)
    c1.metric("Dry-run rollback calls", routing.get("dry_run_rollback_calls"))
    with c2:
        ok = routing.get("archive_chain_intact_before_tamper")
        st.markdown(badge("INTACT" if ok else "BROKEN", level="low" if ok else "critical"), unsafe_allow_html=True)
        st.metric(" ", "Archive chain")
    with c3:
        ok = routing.get("archive_tamper_detected")
        st.markdown(badge("DETECTED" if ok else "MISSED", level="low" if ok else "critical"), unsafe_allow_html=True)
        st.metric(" ", "Tamper test")

    if router["archive_entries"]:
        with st.expander(f"Persisted evidence archive ({len(router['archive_entries'])} entries)"):
            st.json(router["archive_entries"])
