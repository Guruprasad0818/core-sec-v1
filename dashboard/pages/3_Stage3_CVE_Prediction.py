import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import streamlit as st

from core import ingestion
from core.charts import feature_importance_bar
from core.theme import badge, inject_theme, level_for, section_header

inject_theme()

st.title("Stage 3: CVE Prediction Ensemble")
st.caption("cve_predictor.py (XGBoost ensemble) + predict_risk.py")

left, right = st.columns([1, 2], gap="large")

with left:
    st.markdown('<div class="cbad-panel-label">Data Controls</div>', unsafe_allow_html=True)
    uploaded = st.file_uploader("Score a real repository: upload metadata JSON", type=["json"])
    custom_metadata = None
    if uploaded is not None:
        try:
            custom_metadata = json.load(uploaded)
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")

    @st.cache_data(ttl=60, show_spinner=False)
    def cached_stage3(metadata_key: str):
        metadata = json.loads(metadata_key) if metadata_key else None
        return ingestion.load_stage3(custom_metadata=metadata)

    data = cached_stage3(json.dumps(custom_metadata) if custom_metadata else "")
    result = data["result"]

    with st.expander("Ensemble architecture & training metrics"):
        st.write(f"**Model path:** `{data['model_path']}`")
        st.write(f"**Models in ensemble:** {data['ensemble_size']} (XGBoost, bagged feature subsets)")
        st.write(f"**Pretrained model loaded:** {data['model_was_pretrained']}")
        if data.get("ensemble_metrics"):
            st.json(data["ensemble_metrics"])

    with st.expander("Full feature vector (raw model input)"):
        st.dataframe(pd.DataFrame(result.get("feature_vector", {}).items(), columns=["feature", "value"]),
                     use_container_width=True, hide_index=True)

with right:
    section_header("Visual Intelligence", f"Source: {data['source'].replace('_', ' ')}")

    band = result.get("risk_band", "n/a")
    score = result.get("risk_score", 0.0)
    c1, c2, c3 = st.columns(3)
    c1.metric("Repository", result.get("repository", "n/a"))
    c2.metric("Risk score", f"{score:.4f}" if isinstance(score, (int, float)) else score)
    with c3:
        st.markdown(badge(str(band).upper(), level=level_for(band)), unsafe_allow_html=True)
        st.metric(" ", str(band).upper())

    st.markdown("**Top contributing features**")
    contrib = result.get("top_contributing_features", {})
    if contrib:
        st.plotly_chart(feature_importance_bar(contrib, height=340), use_container_width=True)
    else:
        st.caption("No feature contribution data available for this run.")
