#!/usr/bin/env python3
"""CBAD Stage 9 - automated incident mitigation event router.

Implements CBAD_Stage9_SBOM_CVE_Watcher.md SECTION 5 ("Automated Incident
Mitigation Loop"): an Event Router that consumes OPA Gatekeeper denial
events (section 2.9) and SBOM/CVE exposure findings (section 1, bridged
from sbom_monitor.py's ExposureFinding), decides whether automated
mitigation is authorized, triggers a Canary rollback (5.4), requests a
kernel telemetry snapshot via the EventTrigger CRD (5.5) - matching the
exact schema in stage9/guardian-event-trigger-crd.yaml - and seals an
evidence bundle into a WORM-style archive (5.6) before the rollback
completes.

Safety note, same posture as stage6/mitigation_engine.py: rolling back a
production Deployment is destructive and hard to reverse if pointed at a
real cluster. DryRunMitigationBackend is the default everywhere.
KubectlMitigationBackend (real `kubectl rollout undo`/`pause`, exactly per
section 5.4) is only reachable from main() when the caller passes both
--backend kubectl AND --execute. run_self_test() always uses
DryRunMitigationBackend and never shells out to kubectl.

The rollback guard (section 5.4: "only applies to releases older than the
last known good revision") is enforced in EventRouter._should_rollback():
if the event's reported current_revision already equals the recorded
known-good revision, the router logs the decision and skips the redundant
rollback rather than re-triggering one.

Honest stand-in: EvidenceArchive is a local hash-chained JSONL ledger (same
pattern as stage5/stage7), not real WORM/object-lock storage (MinIO/S3
Object Lock per section 5.6) - swap append_to_archive() for a real WORM
client before relying on this for actual non-repudiation.

Usage:
  python stage9/opa_event_router.py self-test
  python stage9/opa_event_router.py listen --events events.jsonl --backend dry-run
  python stage9/opa_event_router.py listen --events events.jsonl --backend kubectl --execute
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sbom_monitor import ExposureFinding

DEFAULT_ARCHIVE_PATH = Path(__file__).resolve().parent / "evidence_artifacts" / "archive.jsonl"
AUTO_MITIGATE_BANDS = ("P0", "P1", "critical")


# ---------------------------------------------------------------------------
# Guardian event model (section 5.2/5.3, section 2.9's denial event context)
# ---------------------------------------------------------------------------

@dataclass
class GuardianEvent:
    event_id: str
    event_type: str  # opa_denial | cve_exposure | runtime_anomaly
    cluster: str
    namespace: str
    resource: str  # deployment/pod name
    reason: str
    severity_band: str  # P0 | P1 | P2 | P3 (or critical/high for raw OPA denials)
    detected_at: str
    policy_id: Optional[str] = None
    sbom_status: Optional[str] = None
    cve_exposure: Optional[Dict[str, Any]] = None
    current_revision: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def event_from_dict(payload: Dict[str, Any]) -> GuardianEvent:
    return GuardianEvent(**payload)


def exposure_finding_to_event(
    finding: ExposureFinding, resource: str, current_revision: Optional[str] = None,
) -> GuardianEvent:
    """Bridges sbom_monitor.py's ExposureFinding into the router's event
    schema (section 1.8's example flow: "Guardrail API publishes the
    finding and triggers a policy action in the production guardian").
    """
    return GuardianEvent(
        event_id=str(uuid.uuid4()),
        event_type="cve_exposure",
        cluster=finding.material.cluster or "unknown",
        namespace=finding.material.namespace or "unknown",
        resource=resource,
        reason=f"{finding.vulnerability.vuln_id} ({finding.vulnerability.severity}) in {finding.material.name}@{finding.material.version}",
        severity_band=finding.severity_band,
        detected_at=finding.detected_at,
        sbom_status="exposed",
        cve_exposure=finding.to_dict(),
        current_revision=current_revision,
    )


# ---------------------------------------------------------------------------
# Router policy and decision (section 5.3 step 2)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RouterPolicy:
    auto_mitigate_bands: tuple = AUTO_MITIGATE_BANDS
    capture_kernel_telemetry: bool = True


@dataclass(frozen=True)
class RouterDecision:
    should_mitigate: bool
    reason: str
    rollback_skipped_by_guard: bool = False


# ---------------------------------------------------------------------------
# EventTrigger CRD model (section 5.5/5.13) - matches
# stage9/guardian-event-trigger-crd.yaml's openAPIV3Schema exactly
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EventTriggerSpec:
    target_pod: str
    target_namespace: str
    event_type: str
    priority: str
    capture_kernel_telemetry: bool = True

    def to_manifest(self, name: str) -> Dict[str, Any]:
        return {
            "apiVersion": "guardian.cbad.io/v1alpha1",
            "kind": "EventTrigger",
            "metadata": {"name": name, "namespace": self.target_namespace},
            "spec": {
                "targetPod": self.target_pod,
                "targetNamespace": self.target_namespace,
                "eventType": self.event_type,
                "priority": self.priority,
                "captureKernelTelemetry": self.capture_kernel_telemetry,
            },
        }


def build_event_trigger(event: GuardianEvent) -> EventTriggerSpec:
    return EventTriggerSpec(
        target_pod=event.resource, target_namespace=event.namespace,
        event_type=event.event_type, priority=event.severity_band,
    )


# ---------------------------------------------------------------------------
# Mitigation backend (section 5.4 - kubectl rollout undo/pause)
# ---------------------------------------------------------------------------

class MitigationBackend(ABC):
    @abstractmethod
    def rollback(self, cluster: str, namespace: str, resource: str) -> str:
        """Returns a reference describing the rollback action taken."""

    @abstractmethod
    def pause_rollout(self, cluster: str, namespace: str, resource: str) -> str: ...

    @abstractmethod
    def request_telemetry_snapshot(self, trigger: EventTriggerSpec) -> str:
        """Returns a reference to the requested snapshot."""


@dataclass
class BackendActionLog:
    actions: List[Dict[str, Any]] = field(default_factory=list)

    def record(self, action: str, **details: Any) -> None:
        self.actions.append({"action": action, **details})


class DryRunMitigationBackend(MitigationBackend):
    """Logs every action it would take without ever touching a real
    cluster. Always safe; used by --self-test and by main() unless
    --backend kubectl --execute are both given.
    """

    def __init__(self) -> None:
        self.log = BackendActionLog()

    def rollback(self, cluster: str, namespace: str, resource: str) -> str:
        ref = f"dry-run-rollback://{cluster}/{namespace}/{resource}"
        self.log.record("rollback", cluster=cluster, namespace=namespace, resource=resource, ref=ref)
        return ref

    def pause_rollout(self, cluster: str, namespace: str, resource: str) -> str:
        ref = f"dry-run-pause://{cluster}/{namespace}/{resource}"
        self.log.record("pause_rollout", cluster=cluster, namespace=namespace, resource=resource, ref=ref)
        return ref

    def request_telemetry_snapshot(self, trigger: EventTriggerSpec) -> str:
        ref = f"dry-run-snapshot://{trigger.target_namespace}/{trigger.target_pod}"
        self.log.record("request_telemetry_snapshot", manifest=trigger.to_manifest("dry-run"), ref=ref)
        return ref


class KubectlMitigationBackend(MitigationBackend):
    """Real, destructive. Shells out to kubectl exactly as section 5.4
    describes. Never invoked by this module's own tests - only reachable
    from main() when the caller passes --backend kubectl --execute.
    """

    def __init__(self, kubectl_binary: str = "kubectl"):
        self.kubectl_binary = kubectl_binary

    def _kubectl(self, *args: str, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
        return subprocess.run([self.kubectl_binary, *args], input=input_text, text=True, capture_output=True, check=False)

    def rollback(self, cluster: str, namespace: str, resource: str) -> str:
        result = self._kubectl("rollout", "undo", f"deployment/{resource}", "-n", namespace, "--context", cluster)
        return f"kubectl rollout undo exit={result.returncode}"

    def pause_rollout(self, cluster: str, namespace: str, resource: str) -> str:
        result = self._kubectl("rollout", "pause", f"deployment/{resource}", "-n", namespace, "--context", cluster)
        return f"kubectl rollout pause exit={result.returncode}"

    def request_telemetry_snapshot(self, trigger: EventTriggerSpec) -> str:
        name = f"trigger-{uuid.uuid4().hex[:8]}"
        manifest_yaml = _manifest_to_yaml(trigger.to_manifest(name))
        result = self._kubectl("apply", "-f", "-", input_text=manifest_yaml)
        return f"eventtrigger/{name} apply exit={result.returncode}"


def _manifest_to_yaml(manifest: Dict[str, Any]) -> str:
    # minimal, dependency-free YAML emission for the small fixed EventTrigger shape
    spec = manifest["spec"]
    return (
        f"apiVersion: {manifest['apiVersion']}\n"
        f"kind: {manifest['kind']}\n"
        f"metadata:\n  name: {manifest['metadata']['name']}\n  namespace: {manifest['metadata']['namespace']}\n"
        f"spec:\n"
        f"  targetPod: {spec['targetPod']}\n"
        f"  targetNamespace: {spec['targetNamespace']}\n"
        f"  eventType: {spec['eventType']}\n"
        f"  priority: {spec['priority']}\n"
        f"  captureKernelTelemetry: {str(spec['captureKernelTelemetry']).lower()}\n"
    )


# ---------------------------------------------------------------------------
# Evidence archive (section 5.6/5.14) - local hash-chained WORM stand-in
# ---------------------------------------------------------------------------

@dataclass
class EvidenceBundle:
    incident_id: str
    event: Dict[str, Any]
    event_trigger_manifest: Dict[str, Any]
    telemetry_ref: str
    rollback_ref: Optional[str]
    sealed_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ArchiveEntry:
    entry_uuid: str
    bundle: Dict[str, Any]
    entry_hash: str
    previous_entry_hash: str
    archived_at: str


class EvidenceArchive:
    GENESIS_HASH = "0" * 64

    def __init__(self, archive_path: Path = DEFAULT_ARCHIVE_PATH):
        self.archive_path = archive_path

    def _read_all(self) -> List[ArchiveEntry]:
        if not self.archive_path.exists():
            return []
        return [ArchiveEntry(**json.loads(line)) for line in self.archive_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def seal_and_store(self, bundle: EvidenceBundle) -> str:
        entries = self._read_all()
        previous_hash = entries[-1].entry_hash if entries else self.GENESIS_HASH
        partial = {
            "entry_uuid": str(uuid.uuid4()), "bundle": bundle.to_dict(),
            "previous_entry_hash": previous_hash, "archived_at": datetime.now(timezone.utc).isoformat(),
        }
        entry_hash = hashlib.sha256(json.dumps(partial, sort_keys=True).encode("utf-8")).hexdigest()
        entry = ArchiveEntry(entry_hash=entry_hash, **partial)
        self.archive_path.parent.mkdir(parents=True, exist_ok=True)
        with self.archive_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry)) + "\n")
        return entry.entry_uuid

    def verify_chain(self) -> bool:
        previous_hash = self.GENESIS_HASH
        for entry in self._read_all():
            if entry.previous_entry_hash != previous_hash:
                return False
            partial = {k: v for k, v in asdict(entry).items() if k != "entry_hash"}
            if hashlib.sha256(json.dumps(partial, sort_keys=True).encode("utf-8")).hexdigest() != entry.entry_hash:
                return False
            previous_hash = entry.entry_hash
        return True


# ---------------------------------------------------------------------------
# Event router orchestration (section 5.3)
# ---------------------------------------------------------------------------

class EventRouter:
    def __init__(
        self,
        policy: RouterPolicy,
        backend: MitigationBackend,
        archive: EvidenceArchive,
        known_good_revisions: Optional[Dict[str, str]] = None,
    ):
        self.policy = policy
        self.backend = backend
        self.archive = archive
        self.known_good_revisions = known_good_revisions or {}

    def _decide(self, event: GuardianEvent) -> RouterDecision:
        if event.severity_band not in self.policy.auto_mitigate_bands:
            return RouterDecision(False, f"severity_band={event.severity_band} not in auto-mitigate set {self.policy.auto_mitigate_bands}")

        known_good = self.known_good_revisions.get(event.resource)
        if known_good is not None and event.current_revision == known_good:
            # section 5.4: "rollback guard that only applies to releases older
            # than the last known good revision" - already at known-good, skip
            return RouterDecision(True, "auto-mitigate eligible, but rollback guard skipped it (already at known-good revision)", rollback_skipped_by_guard=True)

        return RouterDecision(True, f"severity_band={event.severity_band} requires automated mitigation")

    def handle_event(self, event: GuardianEvent) -> Dict[str, Any]:
        decision = self._decide(event)
        if not decision.should_mitigate:
            return {"event_id": event.event_id, "decision": asdict(decision), "archive_entry": None}

        incident_id = str(uuid.uuid4())
        trigger = build_event_trigger(event)
        telemetry_ref = self.backend.request_telemetry_snapshot(trigger)

        rollback_ref: Optional[str] = None
        if not decision.rollback_skipped_by_guard:
            self.backend.pause_rollout(event.cluster, event.namespace, event.resource)
            rollback_ref = self.backend.rollback(event.cluster, event.namespace, event.resource)

        bundle = EvidenceBundle(
            incident_id=incident_id, event=event.to_dict(),
            event_trigger_manifest=trigger.to_manifest(f"trigger-{incident_id[:8]}"),
            telemetry_ref=telemetry_ref, rollback_ref=rollback_ref,
            sealed_at=datetime.now(timezone.utc).isoformat(),
        )
        archive_entry_uuid = self.archive.seal_and_store(bundle)

        return {
            "event_id": event.event_id, "incident_id": incident_id, "decision": asdict(decision),
            "rollback_ref": rollback_ref, "telemetry_ref": telemetry_ref, "archive_entry_uuid": archive_entry_uuid,
        }


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def run_self_test() -> Dict[str, Any]:
    import shutil
    import tempfile

    workdir = Path(tempfile.mkdtemp(prefix="cbad-stage9-"))
    try:
        backend = DryRunMitigationBackend()
        archive = EvidenceArchive(workdir / "archive.jsonl")
        router = EventRouter(RouterPolicy(), backend, archive, known_good_revisions={"orders-api": "rev-42"})

        now = datetime.now(timezone.utc).isoformat()

        opa_denial_event = GuardianEvent(
            event_id=str(uuid.uuid4()), event_type="opa_denial", cluster="prod-cluster",
            namespace="payments", resource="payments-api", reason="missing Cosign verification annotation",
            severity_band="critical", detected_at=now, policy_id="policy.cbad.image_signature",
            current_revision="rev-101",
        )

        cve_exposure_event = GuardianEvent(
            event_id=str(uuid.uuid4()), event_type="cve_exposure", cluster="prod-cluster",
            namespace="orders", resource="orders-api", reason="GHSA-29mw-wpgm-hmr9 (moderate) in lodash@4.17.15",
            severity_band="P0", detected_at=now, sbom_status="exposed", current_revision="rev-77",
        )

        guard_skip_event = GuardianEvent(
            event_id=str(uuid.uuid4()), event_type="cve_exposure", cluster="prod-cluster",
            namespace="orders", resource="orders-api", reason="re-evaluation after prior rollback",
            severity_band="P0", detected_at=now, sbom_status="exposed", current_revision="rev-42",
        )

        low_severity_event = GuardianEvent(
            event_id=str(uuid.uuid4()), event_type="cve_exposure", cluster="prod-cluster",
            namespace="catalog", resource="catalog-api", reason="P3 finding, informational only",
            severity_band="P3", detected_at=now,
        )

        results = {
            "opa_denial_critical": router.handle_event(opa_denial_event),
            "cve_exposure_p0": router.handle_event(cve_exposure_event),
            "rollback_guard_skips_known_good": router.handle_event(guard_skip_event),
            "low_severity_no_mitigation": router.handle_event(low_severity_event),
        }

        rollback_calls = [a for a in backend.log.actions if a["action"] == "rollback"]
        archive_intact = archive.verify_chain()

        # tamper test: corrupt the archive file and confirm the chain check catches it
        archive_path = workdir / "archive.jsonl"
        original = archive_path.read_text(encoding="utf-8")
        lines = original.splitlines()
        if lines:
            tampered = json.loads(lines[0])
            tampered["bundle"]["incident_id"] = "tampered-incident-id"
            lines[0] = json.dumps(tampered)
            archive_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        tamper_detected = not archive.verify_chain()
        archive_path.write_text(original, encoding="utf-8")  # restore

        return {
            "results": results,
            "dry_run_rollback_calls": len(rollback_calls),
            "rollback_guard_prevented_redundant_rollback": results["rollback_guard_skips_known_good"]["decision"]["rollback_skipped_by_guard"],
            "archive_chain_intact_before_tamper": archive_intact,
            "archive_tamper_detected": tamper_detected,
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_events(path: Path) -> List[GuardianEvent]:
    return [event_from_dict(json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 9 OPA/SBOM event router and mitigation engine")
    subparsers = parser.add_subparsers(dest="mode")

    listen_parser = subparsers.add_parser("listen")
    listen_parser.add_argument("--events", required=True, help="Path to a JSONL file of GuardianEvent records")
    listen_parser.add_argument("--backend", choices=["dry-run", "kubectl"], default="dry-run")
    listen_parser.add_argument("--execute", action="store_true", help="Required with --backend kubectl, otherwise dry-run is forced")
    listen_parser.add_argument("--known-good", help="Path to a JSON file mapping resource name -> known-good revision")
    listen_parser.add_argument("--archive", default=str(DEFAULT_ARCHIVE_PATH))

    subparsers.add_parser("self-test")

    args = parser.parse_args()
    if args.mode == "self-test":
        print(json.dumps(run_self_test(), indent=2, default=str))
        return 0
    if args.mode != "listen":
        parser.error("Provide a subcommand: listen | self-test")

    if args.backend == "kubectl" and not args.execute:
        print("[opa_event_router] --backend kubectl requires --execute; forcing dry-run", file=sys.stderr)
        backend: MitigationBackend = DryRunMitigationBackend()
    elif args.backend == "kubectl":
        backend = KubectlMitigationBackend()
    else:
        backend = DryRunMitigationBackend()

    known_good = json.loads(Path(args.known_good).read_text(encoding="utf-8")) if args.known_good else {}
    router = EventRouter(RouterPolicy(), backend, EvidenceArchive(Path(args.archive)), known_good)

    results = [router.handle_event(event) for event in _load_events(Path(args.events))]
    print(json.dumps(results, indent=2, default=str))
    print(f"\n{len(results)} events processed", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
