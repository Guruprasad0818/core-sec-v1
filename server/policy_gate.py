"""Stage 9 - Final Policy Gate & Executive Reporting.

The terminal stage: a deterministic Go/No-Go decision over the four live
signals this pipeline already computes - Stage 2 (Semgrep critical
findings), Stage 5 (high-confidence entropy/secret findings), Stage 7 (SOC 2
readiness), and Stage 8 (SLSA attestation status). Nothing downstream
depends on Stage 9's output, so unlike Stage 3/4/5/7/8 there's no further
warm-cache fan-out to coordinate here.

This replaces the previous SBOM/CVE-exposure monitor + OPA event router that
occupied the Stage 9 slot - stage9/sbom_monitor.py and
stage9/opa_event_router.py are untouched on disk, just no longer surfaced as
Stage 9's response. Their CVE-exposure signal is dropped from the overview
dashboard along with them (see server/aggregation.py), since nothing in this
stage's brief asks for it to be relocated elsewhere.

The executive summary is generated with a small rule-based text generator
rather than a real LLM call. stage8/llm_attack_planner.py does have a real
ClaudeClient path (used when ANTHROPIC_API_KEY is set, for generating
attack-plan JSON, not prose), but wiring a live network call into what's
explicitly meant to be a deterministic gate would make the one piece of
output most tied to an audit trail - the justification text - non-
reproducible across runs of the same underlying state. The task's own
fallback option is the right choice here, not just the cheap one.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

SOC2_READINESS_THRESHOLD = 80.0


def _condition(condition_id: str, label: str, passed: bool, detail: str) -> Dict[str, Any]:
    return {"condition_id": condition_id, "label": label, "passed": passed, "detail": detail}


def _evaluate_conditions(
    stage2: Dict[str, Any], stage5: Dict[str, Any], stage7: Dict[str, Any], stage8: Dict[str, Any]
) -> List[Dict[str, Any]]:
    critical_count = stage2.get("critical_count", 0)

    entropy_findings = stage5.get("entropy", {}).get("findings", [])
    high_confidence_secrets = sum(1 for f in entropy_findings if f.get("confidence") == "high")

    soc2_pct = stage7.get("soc2", {}).get("readiness_pct", 0.0)

    attestation_status = stage8.get("attestation_status", "FAILED")
    slsa_level = stage8.get("slsa_level", 0)
    slsa_target = stage8.get("slsa_level_target", 3)

    return [
        _condition(
            "stage2_unresolved_criticals",
            "No unresolved Stage 2 critical vulnerabilities",
            critical_count == 0,
            f"{critical_count} critical Semgrep finding(s) unresolved" if critical_count else "No critical findings outstanding",
        ),
        _condition(
            "stage5_unremediated_secrets",
            "No un-remediated Stage 5 high-confidence secrets",
            high_confidence_secrets == 0,
            f"{high_confidence_secrets} high-confidence secret(s) still exposed in source"
            if high_confidence_secrets
            else "No high-confidence secrets detected",
        ),
        _condition(
            "stage7_soc2_readiness",
            f"Stage 7 SOC 2 readiness at or above {SOC2_READINESS_THRESHOLD:.0f}%",
            soc2_pct >= SOC2_READINESS_THRESHOLD,
            f"SOC 2 readiness at {soc2_pct:.1f}% (requires >= {SOC2_READINESS_THRESHOLD:.0f}%)",
        ),
        _condition(
            "stage8_slsa_attestation",
            "Stage 8 SLSA attestation PASSED",
            attestation_status == "PASSED",
            f"Pipeline attestation {attestation_status} (SLSA level {slsa_level}/{slsa_target})",
        ),
    ]


def _generate_executive_summary(deployment_status: str, conditions: List[Dict[str, Any]], soc2_pct: float, slsa_level: int) -> str:
    failed = [c for c in conditions if not c["passed"]]

    if deployment_status == "APPROVED":
        return (
            f"All four governance gates passed: no unresolved critical vulnerabilities, no exposed "
            f"high-confidence secrets, SOC 2 readiness at {soc2_pct:.1f}% (meeting the "
            f"{SOC2_READINESS_THRESHOLD:.0f}% bar), and a PASSED SLSA Level {slsa_level} attestation. "
            f"This build's vulnerability posture, secret hygiene, compliance readiness, and supply-chain "
            f"provenance are each independently verifiable end to end. "
            f"Recommendation: APPROVED for production deployment."
        )

    blocking_labels = "; ".join(c["label"] for c in failed)
    reasons = "; ".join(c["detail"] for c in failed)
    return (
        f"Deployment is BLOCKED by {len(failed)} of {len(conditions)} governance gate(s): {blocking_labels}. "
        f"Specifically: {reasons}. "
        f"Recommendation: remediate the listed conditions and re-run this gate before attempting deployment again."
    )


def run_policy_gate(stage2: Dict[str, Any], stage5: Dict[str, Any], stage7: Dict[str, Any], stage8: Dict[str, Any]) -> Dict[str, Any]:
    conditions = _evaluate_conditions(stage2, stage5, stage7, stage8)
    failed_conditions = [c for c in conditions if not c["passed"]]
    deployment_status = "BLOCKED" if failed_conditions else "APPROVED"

    soc2_pct = stage7.get("soc2", {}).get("readiness_pct", 0.0)
    slsa_level = stage8.get("slsa_level", 0)

    return {
        "source": "live_policy_gate",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "deployment_status": deployment_status,
        "conditions": conditions,
        "failure_reasons": [c["detail"] for c in failed_conditions],
        "executive_summary": _generate_executive_summary(deployment_status, conditions, soc2_pct, slsa_level),
    }
