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

st.title("Stage 5: Entropy Secret Scanner & SLSA Attestor")
st.caption("entropy_scanner.py + slsa_attestor.py")


@st.cache_data(ttl=60, show_spinner=False)
def cached_stage5():
    return ingestion.load_stage5()


data = cached_stage5()
entropy = data["entropy"]
slsa = data["slsa"]
findings = entropy["findings"]

left, right = st.columns([1, 2], gap="large")

with left:
    st.markdown('<div class="cbad-panel-label">Data Controls & Metadata</div>', unsafe_allow_html=True)
    st.markdown(badge(f"Entropy: {entropy['source']}".upper(), level="low"), unsafe_allow_html=True)
    st.markdown(badge(f"SLSA: {slsa['source']}".upper(), level="low"), unsafe_allow_html=True)

    with st.expander("Attestation artifact details"):
        if slsa.get("sbom"):
            st.json(slsa["sbom"].get("metadata", {}))
        else:
            st.caption("No persisted SBOM metadata available - showing self-test summary only.")
            st.json(slsa["summary"])

with right:
    section_header("Secret Detection", "Shannon-entropy based credential scanning")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total findings", len(findings))
    high_conf = sum(1 for f in findings if f["confidence"] == "high")
    with c2:
        st.markdown(badge("Action required" if high_conf else "Clean", level="high" if high_conf else "low"), unsafe_allow_html=True)
        st.metric(" ", high_conf)
    c3.metric("Distinct categories", len({f["category"] for f in findings}))

    if findings:
        df = pd.DataFrame(findings)[["file_path", "line_number", "rule_id", "category", "charset", "entropy", "confidence", "masked_value"]]
        render_grid(df, severity_col="confidence", height=340, key="entropy-findings-grid")

        conf_counts = pd.Series([f["confidence"] for f in findings]).value_counts()
        st.plotly_chart(severity_bar(conf_counts, height=260, title="Findings by confidence"), use_container_width=True)
    else:
        st.success("No high-entropy secrets detected in the scanned paths.")

    divider()
    section_header("SLSA Provenance & SBOM Attestation")
    summary = slsa["summary"]
    if "slsa_level" in summary:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("SLSA level", summary.get("slsa_level"))
        with c2:
            ok = summary.get("sbom_signature_valid")
            st.markdown(badge("VALID" if ok else "INVALID", level="low" if ok else "critical"), unsafe_allow_html=True)
            st.metric(" ", "SBOM signature")
        with c3:
            ok = summary.get("provenance_signature_valid")
            st.markdown(badge("VALID" if ok else "INVALID", level="low" if ok else "critical"), unsafe_allow_html=True)
            st.metric(" ", "Provenance signature")
        with c4:
            caught = summary.get("tampered_provenance_rejected")
            st.markdown(badge("DETECTED" if caught else "MISSED", level="low" if caught else "critical"), unsafe_allow_html=True)
            st.metric(" ", "Tamper test")
    else:
        c1, c2 = st.columns(2)
        c1.metric("SBOM components", summary.get("component_count", 0))
        c2.metric("Transparency log entries", summary.get("transparency_log_entries", 0))

    if slsa["sbom"]:
        with st.expander("SBOM components (CycloneDX)"):
            render_grid(pd.DataFrame(slsa["sbom"].get("components", [])), height=320, key="sbom-components-grid")
    if slsa["provenance"]:
        with st.expander("SLSA provenance statement"):
            st.json(slsa["provenance"])
    if slsa["transparency_log"]:
        with st.expander(f"Transparency log ({len(slsa['transparency_log'])} entries)"):
            render_grid(pd.DataFrame(slsa["transparency_log"]), height=320, key="transparency-log-grid")
