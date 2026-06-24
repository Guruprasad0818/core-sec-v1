import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import streamlit as st

from core import ingestion
from core.charts import accent_bar
from core.theme import badge, divider, inject_theme, section_header

inject_theme()

st.title("Stage 1: Pre-Commit Hook Features & Behavior Collector")
st.caption("cbad_feature_collector.py + local_feature_store.py")


@st.cache_data(ttl=60, show_spinner=False)
def cached_stage1():
    return ingestion.load_stage1()


data = cached_stage1()
payloads = data["payloads"]

left, right = st.columns([1, 2], gap="large")

with left:
    st.markdown('<div class="cbad-panel-label">Data Controls</div>', unsafe_allow_html=True)
    st.markdown(badge(data["source"].replace("_", " ").upper(), level="low" if payloads else "neutral"), unsafe_allow_html=True)
    st.caption(data["store_dir"])

    if st.button("Run live collector against this repo", use_container_width=True):
        with st.spinner("Inspecting staged/unstaged git state..."):
            try:
                st.session_state["stage1_live"] = ingestion.collect_stage1_live()
            except Exception as exc:  # noqa: BLE001
                st.error(f"Live collection failed: {exc}")

    selected_payload = None
    if payloads:
        stage_choice = st.selectbox("Inspect persisted payload", list(payloads.keys()))
        selected_payload = payloads.get(stage_choice)
        with st.expander("Raw feature payload (90+ fields)"):
            st.json(selected_payload or {})
    else:
        st.info("No persisted hook payloads found yet. Run `git commit` with the hook installed, "
                "or use the live-collector button above.")

    if "stage1_live" in st.session_state:
        with st.expander("Raw live collection payload", expanded=True):
            st.json(st.session_state["stage1_live"]["payload"])

with right:
    section_header("Visual Intelligence", "Behavioral signal snapshot for the selected commit/push event")

    active = (st.session_state.get("stage1_live", {}).get("payload") if "stage1_live" in st.session_state else None) or selected_payload

    if not active:
        st.info("Select a payload on the left, or run the live collector, to populate this view.")
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Files changed", active.get("files_changed_count", 0))
        c2.metric("Lines added", active.get("lines_added", 0))
        c3.metric("Lines deleted", active.get("lines_deleted", 0))
        sec_files = active.get("security_file_change_count", 0)
        with c4:
            st.markdown(badge("Security paths touched" if sec_files else "Clean", level="high" if sec_files else "low"), unsafe_allow_html=True)
            st.metric("Security-sensitive files", sec_files)

        divider()
        lang_vec = active.get("language_feature_usage_vector") or {}
        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("**Language mix in this change**")
            if lang_vec:
                st.plotly_chart(accent_bar(pd.Series(lang_vec), height=300), use_container_width=True)
            else:
                st.caption("No language-classified files in this change.")
        with col_b:
            st.markdown("**Change shape**")
            shape = pd.Series(
                {
                    "new files": active.get("new_file_count", 0),
                    "deleted files": active.get("deleted_file_count", 0),
                    "renamed files": active.get("renamed_file_count", 0),
                    "patch hunks": active.get("patch_hunk_count", 0),
                }
            )
            st.plotly_chart(accent_bar(shape, height=300, wrap=False), use_container_width=True)
