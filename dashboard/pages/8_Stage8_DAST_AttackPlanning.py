import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import streamlit as st

from core import ingestion
from core.grid import render_grid
from core.theme import badge, divider, inject_theme, section_header

inject_theme()

st.title("Stage 8: Interface Ingestor & LLM Attack Planner")
st.caption("interface_ingestor.py + llm_attack_planner.py")

left, right = st.columns([1, 2], gap="large")

with left:
    st.markdown('<div class="cbad-panel-label">Data Controls</div>', unsafe_allow_html=True)
    uploaded = st.file_uploader("Ingest a real OpenAPI/Swagger spec (JSON)", type=["json"])
    uploaded_spec = None
    if uploaded is not None:
        try:
            uploaded_spec = json.load(uploaded)
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")

    @st.cache_data(ttl=60, show_spinner=False)
    def cached_stage8(spec_key: str):
        spec = json.loads(spec_key) if spec_key else None
        return ingestion.load_stage8(uploaded_spec=spec)

    data = cached_stage8(json.dumps(uploaded_spec) if uploaded_spec else "")
    spec = data["spec"]
    demo = data["attack_planner_demo"]

    st.markdown(badge(f"Spec: {spec['source']}".upper(), level="low"), unsafe_allow_html=True)

    with st.expander("Sandbox safety controls"):
        st.caption("Plans are schema-validated and scanned for forbidden raw-injection tokens before any execution; "
                    "execution requires an explicit SandboxAuthorization against an isolated target.")
        if demo["result"].get("unsafe_plan_findings"):
            st.warning(f"Forbidden-token findings in the rejected unsafe demo plan: {demo['result']['unsafe_plan_findings']}")

with right:
    section_header("Ingested API Surface", f"{spec['title']} @ {spec['base_url']}")
    operations = spec["operations"]
    rows = [
        {
            "operation_id": op_id,
            "method": op["method"],
            "path": op["path_template"],
            "params": len(op["parameters"]),
            "security": ", ".join(op["security_requirements"]) or "none",
        }
        for op_id, op in operations.items()
    ]
    render_grid(pd.DataFrame(rows), height=320, key="api-surface-grid")

    if spec["planned_actions"]:
        with st.expander("Heuristic attack plans for your uploaded spec", expanded=True):
            for i, entry in enumerate(spec["planned_actions"]):
                plan = entry["plan"]
                st.markdown(f"**{entry['operation_id']}** - {plan['goal']} (risk: {plan['risk_level']})")
                render_grid(pd.DataFrame(plan["actions"]), height=220, key=f"plan-actions-grid-{i}")

    divider()
    section_header("LLM Attack-Plan Execution Demo", f"Source: {demo['source']} (sandboxed, end-to-end IDOR plan)")
    result = demo["result"]
    checks = [
        ("Plan generated & valid", result.get("plan_generated_and_valid")),
        ("Unsafe plan rejected", result.get("unsafe_plan_rejected")),
        ("Unauthorized execution blocked", result.get("unauthorized_harness_construction_blocked")),
        ("Unvalidated execution blocked", result.get("unvalidated_plan_execution_blocked")),
    ]
    cols = st.columns(4)
    for col, (label, ok) in zip(cols, checks):
        with col:
            st.markdown(badge("PASS" if ok else "FAIL", level="low" if ok else "critical"), unsafe_allow_html=True)
            st.metric(label, "PASS" if ok else "FAIL")

    if result.get("action_results"):
        st.markdown("**Executed action results**")
        render_grid(pd.DataFrame(result["action_results"]), height=260, key="action-results-grid")
