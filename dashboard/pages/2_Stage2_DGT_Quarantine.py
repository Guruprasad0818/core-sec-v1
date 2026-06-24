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

st.title("Stage 2: Dependency Graph Trust (DGT) & Quarantine Manager")
st.caption("dgt_engine.py + quarantine_manager.py")

COMPONENT_WEIGHTS = {
    "S_CVE (historical CVE risk)": 0.18,
    "S_maintainers (maintainer strength)": 0.12,
    "S_review (code review evidence)": 0.12,
    "S_bus (bus-factor risk)": 0.10,
    "S_release (release cadence/stability)": 0.10,
    "S_community (downloads/issues/stars)": 0.10,
    "S_corporate (corporate/security backing)": 0.08,
    "S_depth (transitive dependency risk)": 0.08,
    "S_tests (coverage/CI health)": 0.07,
    "S_docs (documentation quality)": 0.05,
}

left, right = st.columns([1, 2], gap="large")

with left:
    st.markdown('<div class="cbad-panel-label">Data Controls</div>', unsafe_allow_html=True)
    env = st.selectbox("Environment bias", ["production", "staging", "development"], index=0)
    threshold = st.slider("Quarantine threshold", 0, 100, 40)

    with st.expander("DGT scoring model (component weights)"):
        st.caption("dgt_score = weighted sum of 10 component scores, penalized for unpatched CVEs / unverified maintainers")
        st.dataframe(pd.DataFrame(COMPONENT_WEIGHTS.items(), columns=["component", "weight"]), use_container_width=True, hide_index=True)

with right:
    section_header("Visual Intelligence", "Dependency trust posture for the resolved package set")

    @st.cache_data(ttl=60, show_spinner=False)
    def cached_stage2(env: str, threshold: int):
        return ingestion.load_stage2(env=env, quarantine_threshold=threshold)

    data = cached_stage2(env, threshold)
    st.caption(f"Dependency source: {data['source']}")

    summary = data["summary"]
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(badge("Blocked", level="critical"), unsafe_allow_html=True)
        st.metric(" ", summary["blocked"])
    with c2:
        st.markdown(badge("Quarantined", level="high"), unsafe_allow_html=True)
        st.metric(" ", summary["quarantined"])
    with c3:
        st.markdown(badge("Review", level="medium"), unsafe_allow_html=True)
        st.metric(" ", summary["review"])
    with c4:
        st.markdown(badge("Allowed", level="low"), unsafe_allow_html=True)
        st.metric(" ", summary["allowed"])

    divider()
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Trust category distribution**")
        if data["packages"]:
            cat_counts = pd.Series([p["trust_category"] for p in data["packages"]]).value_counts()
            st.plotly_chart(severity_bar(cat_counts, height=300), use_container_width=True)
    with col_b:
        st.markdown("**Policy action distribution**")
        if data["packages"]:
            action_counts = pd.Series([p["policy_action"] for p in data["packages"]]).value_counts()
            st.plotly_chart(severity_bar(action_counts, height=300), use_container_width=True)

    st.markdown("**Scored packages**")
    df = pd.DataFrame(data["packages"])
    if not df.empty:
        df = df[["name", "version", "dgt_score", "trust_category", "policy_action", "artifact_id"]]
        render_grid(df, severity_col="trust_category", height=360, key="dgt-packages-grid")

    with st.expander("Per-package detail (narrative reasons & component scores)"):
        for pkg in data["packages"]:
            st.markdown(f"**{pkg['name']}=={pkg['version']}** - {pkg['trust_category']} ({pkg['dgt_score']}/100)")
            for reason in pkg["narrative_reasons"]:
                st.caption(f"- {reason}")
            st.json(pkg["component_scores"])
            st.markdown("---")
