import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import streamlit as st

from core import ingestion
from core.charts import accent_bar, severity_bar
from core.grid import render_grid
from core.theme import badge, divider, inject_theme, section_header

inject_theme()

st.title("Stage 4: Multi-Language Taint Tracking & Claude Verifier")
st.caption("sast_engine.py + claude_verifier.py")


@st.cache_data(ttl=60, show_spinner=False)
def cached_stage4():
    return ingestion.load_stage4()


data = cached_stage4()
findings = data["findings"]
verifications = {v["finding"]["finding_id"]: v for v in data["verifications"]}

left, right = st.columns([1, 2], gap="large")

with left:
    st.markdown('<div class="cbad-panel-label">Data Controls</div>', unsafe_allow_html=True)
    st.markdown(badge(data["source"].replace("_", " ").upper(), level="low"), unsafe_allow_html=True)
    with st.expander("Scanned targets"):
        for d in data["scanned_dirs"]:
            st.caption(d)

    severities = sorted({f["severity"] for f in findings}) or ["critical", "high", "medium", "low"]
    languages = sorted({f["language"] for f in findings}) or ["python", "java", "node"]
    sev_filter = st.multiselect("Severity", severities, default=severities)
    lang_filter = st.multiselect("Language", languages, default=languages)

    with st.expander("Rule engine internals"):
        st.caption("Taint paths are flagged when an unsanitized value flows from a known source rule to a known sink rule.")
        st.markdown("- **Java:** getParameter/getHeader/RequestBody -> executeQuery/Runtime.exec/ProcessBuilder")
        st.markdown("- **Node:** req.query/req.body -> child_process.exec/eval/fs.writeFileSync")
        st.markdown("- **Python:** request.args/request.form -> cursor.execute/subprocess/eval/pickle.loads")

if not findings:
    with right:
        section_header("Visual Intelligence")
        st.success("No taint-tracking findings detected.")
    st.stop()

filtered = [f for f in findings if f["severity"] in sev_filter and f["language"] in lang_filter]

with right:
    section_header("Visual Intelligence", "Active taint paths discovered across the scanned source tree")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total findings", len(findings))
    with c2:
        crit_count = sum(1 for f in findings if f["severity"] in ("critical", "high"))
        st.markdown(badge("Needs triage" if crit_count else "Clean", level="high" if crit_count else "low"), unsafe_allow_html=True)
        st.metric(" ", crit_count)
    c3.metric("Verified (not false-positive)", sum(1 for v in verifications.values() if v["verification"]["verified"]))
    c4.metric("Suppressed (heuristic FP)", sum(1 for v in verifications.values() if not v["verification"]["verified"]))

    divider()
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**By severity**")
        sev_counts = pd.Series([f["severity"] for f in filtered]).value_counts()
        if not sev_counts.empty:
            st.plotly_chart(severity_bar(sev_counts, height=280), use_container_width=True)
    with col_b:
        st.markdown("**By language**")
        lang_counts = pd.Series([f["language"] for f in filtered]).value_counts()
        if not lang_counts.empty:
            st.plotly_chart(accent_bar(lang_counts, height=280, wrap=False), use_container_width=True)

    st.markdown("**Active taint paths (source -> sink)**")
    table_rows = [
        {
            "severity": f["severity"],
            "category": f["category"],
            "language": f["language"],
            "file": f["file_path"],
            "source_line": f["source"]["line_number"],
            "sink_line": f["sink"]["line_number"],
            "sanitized": f["sanitizer"] is not None,
            "confidence": f["confidence"],
        }
        for f in filtered
    ]
    render_grid(pd.DataFrame(table_rows), severity_col="severity", height=380, key="sast-findings-grid")

    with st.expander("Finding detail & Claude verifier output"):
        for f in filtered:
            v = verifications.get(f["finding_id"])
            st.markdown(f"**[{f['severity'].upper()}] {f['category']}** - `{f['file_path']}`")
            st.write(f"Source: `{f['source']['line_text'].strip()}` (line {f['source']['line_number']})")
            st.write(f"Sink: `{f['sink']['line_text'].strip()}` (line {f['sink']['line_number']})")
            if f["sanitizer"]:
                st.write(f"Sanitizer: `{f['sanitizer']['line_text'].strip()}` (line {f['sanitizer']['line_number']})")
            else:
                st.write("Sanitizer: none")
            st.caption(f["description"])
            if v:
                st.json(v["verification"])
                if "fix_recommendation" in v:
                    st.json(v["fix_recommendation"])
            st.markdown("---")
