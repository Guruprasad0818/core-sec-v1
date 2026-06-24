import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import streamlit as st

from core import ingestion
from core.charts import accent_bar, severity_bar
from core.grid import render_grid
from core.stage_loader import load_module
from core.theme import badge, divider, inject_theme, section_header

inject_theme()

st.title("Stage 6: Runtime Syscall Monitor & Mitigation Engine")
st.caption("syscall_monitor.py + mitigation_engine.py")


@st.cache_data(ttl=60, show_spinner=False)
def cached_stage6():
    return ingestion.load_stage6()


data = cached_stage6()
syscalls = data["syscall_events"]
mitigation = data["mitigation"]
events = syscalls["events"]

left, right = st.columns([1, 2], gap="large")

with left:
    st.markdown('<div class="cbad-panel-label">Data Controls & Metadata</div>', unsafe_allow_html=True)
    st.markdown(badge(f"Events: {syscalls['source']}".upper(), level="low"), unsafe_allow_html=True)
    st.markdown(badge(f"Audit log: {mitigation['source']}".upper(), level="low" if mitigation["source"] != "none" else "neutral"), unsafe_allow_html=True)

    with st.expander("Falco rule reference"):
        try:
            syscall_mod = load_module("syscall_monitor")
            for rule in syscall_mod.DEFAULT_RULES:
                st.markdown(f"**{rule.rule_id}** - {rule.priority}")
                st.caption(rule.description)
        except Exception as exc:  # noqa: BLE001
            st.caption(f"Rule reference unavailable: {exc}")

with right:
    section_header("Visual Intelligence", "Scored syscall telemetry and automated mitigation decisions")

    c1, c2, c3 = st.columns(3)
    c1.metric("Total events", len(events))
    elevated = sum(1 for e in events if e["classification"] == "elevated")
    with c2:
        st.markdown(badge("Elevated" if elevated else "Clear", level="medium" if elevated else "low"), unsafe_allow_html=True)
        st.metric(" ", elevated)
    lockdown = sum(1 for e in events if e["classification"] == "lockdown")
    with c3:
        st.markdown(badge("Blocked" if lockdown else "Clear", level="critical" if lockdown else "low"), unsafe_allow_html=True)
        st.metric(" ", lockdown)

    divider()
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Blocked syscalls by classification**")
        if events:
            st.plotly_chart(severity_bar(pd.Series([e["classification"] for e in events]).value_counts(), height=280), use_container_width=True)
    with col_b:
        st.markdown("**Syscall type breakdown**")
        if events:
            st.plotly_chart(accent_bar(pd.Series([e["event"]["syscall"] for e in events]).value_counts(), height=280), use_container_width=True)

    st.markdown("**Event detail**")
    rows = [
        {
            "syscall": e["event"]["syscall"],
            "comm": e["event"]["comm"],
            "container_id": e["event"]["container_id"],
            "score": round(e["score"], 3),
            "classification": e["classification"],
            "falco_rules_hit": ", ".join(m["rule_id"] for m in e["falco_matches"]) or "none",
        }
        for e in events
    ]
    render_grid(pd.DataFrame(rows), severity_col="classification", height=380, key="syscall-events-grid")

    divider()
    section_header("Mitigation Decisions")
    preview = mitigation["decision_preview"]
    if preview:
        df = pd.DataFrame(preview)
        render_grid(df, severity_col="decision_action", height=300, key="mitigation-decisions-grid")
        st.plotly_chart(severity_bar(df["decision_action"].value_counts(), height=260, wrap=True), use_container_width=True)

    if mitigation["audit_entries"]:
        with st.expander(f"Persisted mitigation audit log ({len(mitigation['audit_entries'])} entries)"):
            render_grid(pd.DataFrame(mitigation["audit_entries"]), height=320, key="mitigation-audit-log-grid")
    else:
        st.caption("No persisted mitigation_artifacts/audit_log.jsonl found yet - showing live policy-engine decision preview only.")
