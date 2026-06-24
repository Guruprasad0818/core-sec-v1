import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import streamlit as st

from core import ingestion
from core.grid import render_grid
from core.theme import badge, divider, inject_theme, section_header

inject_theme()

st.title("Stage 7: Keyless Signing (Cosign/Sigstore) & Kubernetes Admission")
st.caption("cosign_wrapper.py + k8s_admission_validator.py")


@st.cache_data(ttl=60, show_spinner=False)
def cached_stage7():
    return ingestion.load_stage7()


data = cached_stage7()
cosign = data["cosign"]
k8s = data["k8s_admission"]
result = cosign["result"]
scenarios = k8s["scenarios"]

left, right = st.columns([1, 2], gap="large")

with left:
    st.markdown('<div class="cbad-panel-label">Data Controls & Metadata</div>', unsafe_allow_html=True)
    st.markdown(badge(f"Cosign: {cosign['source']}".upper(), level="low"), unsafe_allow_html=True)
    st.markdown(badge(f"K8s: {k8s['source']}".upper(), level="low"), unsafe_allow_html=True)

    with st.expander("Cosign trust-chain detail"):
        st.json(result.get("verify_valid_artifact", {}))

    if cosign["persisted_rekor_entries"]:
        with st.expander(f"Persisted Rekor log ({len(cosign['persisted_rekor_entries'])} entries)"):
            render_grid(pd.DataFrame(cosign["persisted_rekor_entries"]), height=320, key="rekor-log-grid")

with right:
    section_header("Keyless Signing", "Sigstore-pattern sign/verify chain (Fulcio + Rekor simulators)")
    c1, c2, c3, c4 = st.columns(4)
    checks = [
        ("Sign succeeded", result.get("sign_succeeded")),
        ("Tampered artifact rejected", result.get("verify_tampered_artifact_rejected")),
        ("Untrusted issuer rejected", result.get("untrusted_issuer_rejected")),
        ("Rekor chain intact", result.get("rekor_chain_intact")),
    ]
    for col, (label, ok) in zip((c1, c2, c3, c4), checks):
        with col:
            st.markdown(badge("PASS" if ok else "FAIL", level="low" if ok else "critical"), unsafe_allow_html=True)
            st.metric(label, "PASS" if ok else "FAIL")

    divider()
    section_header("Kubernetes Admission Webhook", "Validation log for image signature/attestation policy")
    rows = [{"scenario": name, **payload} for name, payload in scenarios.items()]
    df = pd.DataFrame(rows)
    if not df.empty:
        df["allowed"] = df["allowed"].map(lambda v: "ALLOWED" if v else "DENIED")
        render_grid(df, severity_col="allowed", height=300, key="k8s-admission-grid")

    denied = sum(1 for r in rows if not r.get("allowed", True))
    c1, c2 = st.columns(2)
    c1.metric("Scenarios tested", len(rows))
    with c2:
        st.markdown(badge("Denials present" if denied else "All clear", level="high" if denied else "low"), unsafe_allow_html=True)
        st.metric("Denied by policy", denied)
