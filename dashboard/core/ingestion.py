"""Per-stage data ingestion.

Each `load_stageN` function follows the same priority order:
  1. Real persisted artifacts on disk (written by a prior CLI run of that stage).
  2. A live call into the stage's own public API (scanning this repo, or the
     module's built-in `run_self_test()` fixture when no real target applies).

Every function returns a dict with a "source" key describing which of the
above produced the data, so the UI can label it honestly.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.stage_loader import REPO_ROOT, STAGE_DIRS, load_module
from core.utils import read_json_file, read_jsonl_file, to_jsonable

STAGE_SOURCE_DIRS = [d for n, d in STAGE_DIRS.items() if d.exists()]


# ---------------------------------------------------------------------------
# Stage 1 - CBAD pre-commit/pre-push feature collector
# ---------------------------------------------------------------------------

_PAYLOAD_RE = re.compile(r"^(.*)-(\d{8}T\d{6}Z)\.json$")


def load_stage1(repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    store_dir = repo_root / ".git" / "cbad" / "features"
    payloads: Dict[str, Any] = {}
    if store_dir.exists():
        for f in sorted(store_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            match = _PAYLOAD_RE.match(f.name)
            stage_name = match.group(1) if match else f.stem
            if stage_name not in payloads:
                payloads[stage_name] = read_json_file(f)
    if payloads:
        return {"source": "git_hook_artifacts", "store_dir": str(store_dir), "payloads": payloads}
    return {"source": "none", "store_dir": str(store_dir), "payloads": {}}


def collect_stage1_live(repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    """Run the real CBADFeatureCollector against this repo's current git state (read-only)."""
    collector_mod = load_module("cbad_feature_collector")
    collector = collector_mod.CBADFeatureCollector(str(repo_root))
    payload = collector.collect_features("dashboard-live")
    return {"source": "live_repo_inspection", "payload": to_jsonable(payload)}


# ---------------------------------------------------------------------------
# Stage 2 - Dependency Graph Trust + Quarantine
# ---------------------------------------------------------------------------

_FALLBACK_DEPS = {
    "flask": "2.0.1",
    "requests": "2.31.0",
    "left-pad": "1.3.0",
    "lodash": "4.17.15",
    "pyyaml": "5.4",
}


def load_stage2(repo_root: Path = REPO_ROOT, env: str = "production", quarantine_threshold: int = 40) -> Dict[str, Any]:
    dgt_mod = load_module("dgt_engine")
    qm_mod = load_module("quarantine_manager")

    req_file = repo_root / "requirements.txt"
    pkg_file = repo_root / "package.json"
    source = "builtin_sample_packages"
    if req_file.exists():
        dep_map = dgt_mod.parse_requirements(req_file)
        source = "requirements.txt"
    elif pkg_file.exists():
        dep_map = dgt_mod.parse_package_json(pkg_file)
        source = "package.json"
    else:
        dep_map = _FALLBACK_DEPS

    scorer = dgt_mod.DGTScorer(env=env, quarantine_threshold=quarantine_threshold)
    records = dgt_mod.build_package_records(dep_map, {})
    packages = []
    for name, version, metrics in records:
        result = scorer.score_package(name, version, metrics)
        packages.append(
            {
                "name": result.name,
                "version": result.version,
                "artifact_id": result.artifact_id,
                "dgt_score": result.dgt_score,
                "trust_category": result.trust_category,
                "policy_action": result.policy_action,
                "path_factor": round(result.path_factor, 2),
                "env_bias": round(result.env_bias, 2),
                "component_scores": result.component_scores,
                "narrative_reasons": result.narrative_reasons,
            }
        )

    manager = qm_mod.QuarantineManager(quarantine_threshold=quarantine_threshold)
    decisions = manager.filter_quarantine(packages)
    summary = manager.summarize(decisions)

    return {
        "source": source,
        "env": env,
        "quarantine_threshold": quarantine_threshold,
        "packages": packages,
        "summary": summary,
        "decisions": [d.__dict__ for d in decisions],
    }


# ---------------------------------------------------------------------------
# Stage 3 - CVE prediction ensemble
# ---------------------------------------------------------------------------

def load_stage3(repo_root: Path = REPO_ROOT, custom_metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    predict_mod = load_module("predict_risk")
    cve_mod = load_module("cve_predictor")

    model_path = cve_mod.DEFAULT_MODEL_PATH
    model_was_pretrained = model_path.exists()
    ensemble = predict_mod.load_or_train_ensemble(model_path)

    metadata = custom_metadata or predict_mod.build_demo_repository(datetime.now(timezone.utc))
    result = predict_mod.score_repository(metadata, ensemble, model_path)

    return {
        "source": "uploaded_repo_metadata" if custom_metadata else "demo_repository",
        "model_path": str(model_path),
        "model_was_pretrained": model_was_pretrained,
        "ensemble_size": len(ensemble.models),
        "ensemble_metrics": ensemble.metrics,
        "result": to_jsonable(result),
    }


# ---------------------------------------------------------------------------
# Stage 4 - SAST taint tracking + Claude verifier
# ---------------------------------------------------------------------------

def load_stage4(repo_root: Path = REPO_ROOT, scan_dirs: Optional[List[Path]] = None) -> Dict[str, Any]:
    sast_mod = load_module("sast_engine")
    verifier_mod = load_module("claude_verifier")

    targets = scan_dirs or STAGE_SOURCE_DIRS
    findings = []
    for target in targets:
        findings.extend(sast_mod.scan_directory(Path(target)))

    source = "repository_scan"
    if not findings:
        findings = sast_mod.run_self_test()
        source = "self_test_fixture"

    verifications = []
    for finding in findings:
        verification = verifier_mod.heuristic_verify(finding)
        entry = {"finding": finding.to_dict(), "verification": verification.__dict__}
        if verification.verified:
            entry["fix_recommendation"] = verifier_mod.build_fix_recommendation(finding).__dict__
        verifications.append(entry)

    return {
        "source": source,
        "scanned_dirs": [str(t) for t in targets],
        "findings": [f.to_dict() for f in findings],
        "verifications": verifications,
    }


# ---------------------------------------------------------------------------
# Stage 5 - Entropy secret scanner + SLSA attestation
# ---------------------------------------------------------------------------

def load_stage5(repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    entropy_mod = load_module("entropy_scanner")
    slsa_mod = load_module("slsa_attestor")

    findings = []
    for target in STAGE_SOURCE_DIRS:
        findings.extend(entropy_mod.scan_directory(Path(target)))
    entropy_source = "repository_scan"
    if not findings:
        findings = entropy_mod.run_self_test()
        entropy_source = "self_test_fixture"

    artifacts_dir = repo_root / "stage5" / "attestation_artifacts"
    sbom = read_json_file(artifacts_dir / "sbom.json")
    provenance = read_json_file(artifacts_dir / "provenance.json")
    transparency_log = read_jsonl_file(artifacts_dir / "transparency_log.jsonl")

    if sbom is not None:
        slsa_source = "persisted_attestation_artifacts"
        slsa_summary = {
            "component_count": len(sbom.get("components", [])),
            "transparency_log_entries": len(transparency_log),
        }
    else:
        slsa_source = "self_test_fixture"
        slsa_summary = slsa_mod.run_self_test()
        sbom = None
        provenance = None

    return {
        "entropy": {
            "source": entropy_source,
            "findings": [f.to_dict() for f in findings],
        },
        "slsa": {
            "source": slsa_source,
            "summary": to_jsonable(slsa_summary),
            "sbom": sbom,
            "provenance": provenance,
            "transparency_log": transparency_log,
        },
    }


# ---------------------------------------------------------------------------
# Stage 6 - Syscall monitor + mitigation engine
# ---------------------------------------------------------------------------

def load_stage6(repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    syscall_mod = load_module("syscall_monitor")
    mitigation_mod = load_module("mitigation_engine")

    scored_events = syscall_mod.run_self_test()

    audit_log_path = mitigation_mod.DEFAULT_AUDIT_LOG
    audit_entries = read_jsonl_file(audit_log_path)
    audit_source = "persisted_audit_log" if audit_entries else "none"

    policy = mitigation_mod.PolicyEngine()
    decision_preview = []
    for scored_event in scored_events:
        decision = policy.decide(scored_event)
        decision_preview.append(
            {
                "event_id": scored_event.event.event_id,
                "syscall": scored_event.event.syscall,
                "score": scored_event.score,
                "classification": scored_event.classification,
                "decision_action": decision.action,
                "reason": decision.reason,
            }
        )

    return {
        "syscall_events": {
            "source": "simulated_event_source",
            "events": [e.to_dict() for e in scored_events],
        },
        "mitigation": {
            "source": audit_source,
            "audit_entries": audit_entries,
            "decision_preview": decision_preview,
        },
    }


# ---------------------------------------------------------------------------
# Stage 7 - Cosign signing + Kubernetes admission control
# ---------------------------------------------------------------------------

def load_stage7(repo_root: Path = REPO_ROOT) -> Dict[str, Any]:
    cosign_mod = load_module("cosign_wrapper")
    k8s_mod = load_module("k8s_admission_validator")

    rekor_log_path = repo_root / "stage7" / "rekor_sim_artifacts" / "log.jsonl"
    rekor_entries = read_jsonl_file(rekor_log_path)

    cosign_result = cosign_mod.run_self_test()
    admission_result = k8s_mod.run_self_test()

    return {
        "cosign": {
            "source": "self_test_fixture",
            "result": to_jsonable(cosign_result),
            "persisted_rekor_entries": rekor_entries,
        },
        "k8s_admission": {
            "source": "self_test_fixture",
            "scenarios": to_jsonable(admission_result),
        },
    }


# ---------------------------------------------------------------------------
# Stage 8 - DAST interface ingestion + LLM attack planning
# ---------------------------------------------------------------------------

def load_stage8(repo_root: Path = REPO_ROOT, uploaded_spec: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ingestor_mod = load_module("interface_ingestor")
    planner_mod = load_module("llm_attack_planner")

    spec_source = "self_test_spec"
    spec = ingestor_mod.SELF_TEST_SPEC
    if uploaded_spec:
        spec_source = "uploaded_spec"
        spec = uploaded_spec

    graph = ingestor_mod.SpecIngestor().ingest_dict(spec)
    operations = {op_id: op.__dict__ for op_id, op in graph.operations.items()}

    planned_actions = []
    if uploaded_spec:
        for op_id, op in graph.operations.items():
            plan = planner_mod.heuristic_plan(op, "idor")
            planned_actions.append({"operation_id": op_id, "plan": to_jsonable(plan)})

    demo_run = planner_mod.run_self_test()

    return {
        "spec": {
            "source": spec_source,
            "title": graph.title,
            "base_url": graph.base_url,
            "operations": to_jsonable(operations),
            "planned_actions": to_jsonable(planned_actions),
        },
        "attack_planner_demo": {
            "source": "self_test_fixture",
            "result": to_jsonable(demo_run),
        },
    }


# ---------------------------------------------------------------------------
# Stage 9 - OPA event router + SBOM/CVE exposure monitor
# ---------------------------------------------------------------------------

def load_stage9(repo_root: Path = REPO_ROOT, use_live_feeds: bool = False) -> Dict[str, Any]:
    sbom_mod = load_module("sbom_monitor")
    router_mod = load_module("opa_event_router")

    materials = sbom_mod.parse_sbom(sbom_mod.SELF_TEST_SBOM, provenance={"cluster": "staging", "namespace": "orders"})
    if use_live_feeds:
        feeds = sbom_mod.build_default_feed_chain()
        feed_source = "live_osv_ghsa_feeds"
    else:
        feeds = [sbom_mod.LocalFeedSimulator()]
        feed_source = "local_offline_simulator"

    monitor = sbom_mod.SBOMMonitor(feeds)
    try:
        findings = monitor.scan_materials(materials)
    except Exception:
        findings = sbom_mod.SBOMMonitor([sbom_mod.LocalFeedSimulator()]).scan_materials(materials)
        feed_source = "local_offline_simulator_fallback"

    archive_path = repo_root / "stage9" / "evidence_artifacts" / "archive.jsonl"
    archive_entries = read_jsonl_file(archive_path)
    archive_source = "persisted_evidence_archive" if archive_entries else "none"

    routing_demo = router_mod.run_self_test()

    return {
        "sbom_monitor": {
            "source": feed_source,
            "findings": [f.to_dict() for f in findings],
        },
        "event_router": {
            "source": archive_source,
            "archive_entries": archive_entries,
            "routing_demo": to_jsonable(routing_demo),
        },
    }
