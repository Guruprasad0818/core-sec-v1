#!/usr/bin/env python3
"""CBAD Stage 6 - automated policy-based mitigation and kill logic.

Implements the mitigation decision flow, Kubernetes kill patterns, and
safe-kill/hard-kill considerations from CBAD_Stage6_gVisor_eBPF.md SECTION 4
("Automated Mitigation & Kill Logic"), consuming ScoredSyscallEvent objects
produced by syscall_monitor.py.

Safety note (this matters more than usual for this module): terminating a
real container is a destructive, hard-to-reverse action. KubernetesBackend
shells out to `kubectl` exactly as section 4.3's pseudo-commands show, but
PolicyEngine/MitigationEngine never touch it directly - main() defaults to
DryRunBackend (which only logs the actions it *would* take) and only wires
in KubernetesBackend if the caller passes both --backend kubernetes AND
--execute. run_self_test() always uses DryRunBackend and never shells out to
kubectl, regardless of what's installed or configured on the host.

Mitigation playbooks (section 4.2/4.5):
  - preserve_forensics=True (default for lockdown-tier events): pause ->
    capture_forensics -> isolate -> terminate -> upload_bundle, so evidence
    is captured before the process can clean up after itself
  - preserve_forensics=False (time-sensitive/exfiltration-in-progress path):
    isolate -> terminate -> capture_forensics (post-mortem) -> upload_bundle

Usage:
  python stage6/mitigation_engine.py --self-test
  python stage6/mitigation_engine.py --listen events.jsonl --backend dry-run
  python stage6/mitigation_engine.py --listen events.jsonl --backend kubernetes --execute
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from syscall_monitor import ScoredSyscallEvent, run_self_test as monitor_self_test, scored_event_from_dict

DEFAULT_AUDIT_LOG = Path(__file__).resolve().parent / "mitigation_artifacts" / "audit_log.jsonl"
DEFAULT_HMAC_KEY_PATH = Path(__file__).resolve().parent / "mitigation_artifacts" / "audit_hmac.key"


# ---------------------------------------------------------------------------
# Policy engine (section 2.5 / 3.4 thresholds + section 4.2 decision flow)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PolicyThresholds:
    lockdown: float = 0.8
    elevated: float = 0.5


@dataclass(frozen=True)
class MitigationDecision:
    action: str  # "log" | "elevated_alert" | "quarantine_and_terminate"
    preserve_forensics: bool
    reason: str


class PolicyEngine:
    def __init__(self, thresholds: PolicyThresholds = PolicyThresholds(), preserve_forensics_default: bool = True):
        self.thresholds = thresholds
        self.preserve_forensics_default = preserve_forensics_default

    def decide(self, scored_event: ScoredSyscallEvent) -> MitigationDecision:
        score = scored_event.score
        critical_falco_hit = any(match.priority == "CRITICAL" for match in scored_event.falco_matches)

        if score >= self.thresholds.lockdown or critical_falco_hit:
            return MitigationDecision(
                action="quarantine_and_terminate",
                preserve_forensics=self.preserve_forensics_default,
                reason=f"score={score:.3f} >= lockdown threshold ({self.thresholds.lockdown}) or a CRITICAL Falco rule matched",
            )
        if score >= self.thresholds.elevated:
            return MitigationDecision(
                action="elevated_alert",
                preserve_forensics=False,
                reason=f"score={score:.3f} in elevated range [{self.thresholds.elevated}, {self.thresholds.lockdown}) - queued for AI verification",
            )
        return MitigationDecision(
            action="log",
            preserve_forensics=False,
            reason=f"score={score:.3f} below elevated threshold ({self.thresholds.elevated})",
        )


# ---------------------------------------------------------------------------
# Container runtime backend (section 4.3 kubectl patterns, section 4.5 kill steps)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ContainerRef:
    pod_namespace: str
    pod_name: str
    container_id: str
    pod_label: str


def derive_container_ref(event_container_id: str, namespace: str = "buildns") -> ContainerRef:
    short_id = event_container_id[:12]
    return ContainerRef(
        pod_namespace=namespace,
        pod_name=f"runner-{short_id}",
        container_id=event_container_id,
        pod_label=f"run={short_id}",
    )


class ContainerRuntimeBackend(ABC):
    @abstractmethod
    def pause(self, container_ref: ContainerRef) -> None: ...

    @abstractmethod
    def capture_forensics(self, container_ref: ContainerRef, incident_id: str) -> str:
        """Returns a reference (path or job name) to the captured forensic bundle."""

    @abstractmethod
    def isolate(self, container_ref: ContainerRef) -> None: ...

    @abstractmethod
    def terminate(self, container_ref: ContainerRef, grace_seconds: float = 5.0) -> None: ...

    @abstractmethod
    def upload_bundle(self, bundle_ref: str, incident_id: str) -> str:
        """Returns a reference to the uploaded bundle in the artifact store."""


@dataclass
class BackendActionLog:
    actions: List[Dict[str, Any]] = field(default_factory=list)

    def record(self, action: str, container_ref: ContainerRef, **extra: Any) -> None:
        self.actions.append({"action": action, "container_ref": asdict(container_ref), **extra})


class DryRunBackend(ContainerRuntimeBackend):
    """Logs every action it would take without ever touching a real
    container runtime or Kubernetes API. Always safe; used by --self-test
    and by main() unless --backend kubernetes --execute are both given.
    """

    def __init__(self) -> None:
        self.log = BackendActionLog()

    def pause(self, container_ref: ContainerRef) -> None:
        self.log.record("pause", container_ref)

    def capture_forensics(self, container_ref: ContainerRef, incident_id: str) -> str:
        bundle_ref = f"dry-run-bundle://{incident_id}/{container_ref.container_id}"
        self.log.record("capture_forensics", container_ref, incident_id=incident_id, bundle_ref=bundle_ref)
        return bundle_ref

    def isolate(self, container_ref: ContainerRef) -> None:
        self.log.record("isolate", container_ref)

    def terminate(self, container_ref: ContainerRef, grace_seconds: float = 5.0) -> None:
        self.log.record("terminate", container_ref, grace_seconds=grace_seconds)

    def upload_bundle(self, bundle_ref: str, incident_id: str) -> str:
        uploaded_ref = f"dry-run-artifact-store://{incident_id}"
        self.log.record(
            "upload_bundle",
            ContainerRef("", "", "", ""),
            incident_id=incident_id, bundle_ref=bundle_ref, uploaded_ref=uploaded_ref,
        )
        return uploaded_ref


class KubernetesBackend(ContainerRuntimeBackend):
    """Shells out to kubectl exactly as section 4.3's pseudo-commands show.
    Real, destructive, never invoked by this module's own tests - only
    reachable from main() when the caller passes --backend kubernetes
    --execute.
    """

    def __init__(self, kubectl_binary: str = "kubectl"):
        self.kubectl_binary = kubectl_binary

    def _kubectl(self, *args: str, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.kubectl_binary, *args],
            input=input_text, text=True, capture_output=True, check=False,
        )

    def pause(self, container_ref: ContainerRef) -> None:
        self._kubectl("exec", "-n", container_ref.pod_namespace, container_ref.pod_name, "--", "kill", "-STOP", "1")

    def capture_forensics(self, container_ref: ContainerRef, incident_id: str) -> str:
        job_name = f"forensic-{incident_id}"
        self._kubectl("create", "job", "--from=cronjob/forensic-capture", job_name, "-n", container_ref.pod_namespace)
        return job_name

    def isolate(self, container_ref: ContainerRef) -> None:
        network_policy_yaml = f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress-{container_ref.pod_name}
  namespace: {container_ref.pod_namespace}
spec:
  podSelector:
    matchLabels:
      {container_ref.pod_label}
  policyTypes:
    - Egress
  egress: []
"""
        self._kubectl("apply", "-f", "-", input_text=network_policy_yaml)
        self._kubectl("annotate", "pod", "-n", container_ref.pod_namespace, container_ref.pod_name, "cbad/quarantine=true")

    def terminate(self, container_ref: ContainerRef, grace_seconds: float = 5.0) -> None:
        import time

        self._kubectl("exec", "-n", container_ref.pod_namespace, container_ref.pod_name, "--", "kill", "-TERM", "1")
        time.sleep(grace_seconds)
        self._kubectl("exec", "-n", container_ref.pod_namespace, container_ref.pod_name, "--", "kill", "-KILL", "1")

    def upload_bundle(self, bundle_ref: str, incident_id: str) -> str:
        # extension point: wire to the real artifact store / Stage 5 attestor.
        # kubectl has no direct equivalent in section 4.3's examples, so this
        # is a no-op reference rather than a fabricated kubectl call.
        return f"artifact-store://incidents/{incident_id}/{bundle_ref}"


# ---------------------------------------------------------------------------
# Playbook execution (section 4.2 step 3 / section 4.5)
# ---------------------------------------------------------------------------

def execute_playbook(
    decision: MitigationDecision,
    container_ref: ContainerRef,
    backend: ContainerRuntimeBackend,
    incident_id: str,
) -> List[str]:
    if decision.action != "quarantine_and_terminate":
        return []

    steps: List[str] = []
    if decision.preserve_forensics:
        backend.pause(container_ref)
        steps.append("pause")
        bundle_ref = backend.capture_forensics(container_ref, incident_id)
        steps.append("capture_forensics")
        backend.isolate(container_ref)
        steps.append("isolate")
        backend.terminate(container_ref)
        steps.append("terminate")
        backend.upload_bundle(bundle_ref, incident_id)
        steps.append("upload_bundle")
    else:
        backend.isolate(container_ref)
        steps.append("isolate")
        backend.terminate(container_ref)
        steps.append("terminate")
        bundle_ref = backend.capture_forensics(container_ref, incident_id)  # post-mortem per section 4.5
        steps.append("capture_forensics_postmortem")
        backend.upload_bundle(bundle_ref, incident_id)
        steps.append("upload_bundle")
    return steps


# ---------------------------------------------------------------------------
# Audit log / non-repudiation (section 4.6)
# ---------------------------------------------------------------------------

@dataclass
class MitigationAuditEntry:
    incident_id: str
    triggered_by_event_id: str
    container_ref: Dict[str, str]
    decision_action: str
    reason: str
    steps_taken: List[str]
    operator: str
    timestamp: str
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def load_or_create_hmac_key(key_path: Path) -> bytes:
    if key_path.exists():
        return key_path.read_bytes()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    key_path.write_bytes(key)
    try:
        key_path.chmod(0o600)
    except (NotImplementedError, OSError):
        pass
    return key


def _sign_entry(entry: MitigationAuditEntry, hmac_key: bytes) -> str:
    unsigned = entry.to_dict()
    unsigned.pop("signature", None)
    payload = json.dumps(unsigned, sort_keys=True).encode("utf-8")
    return hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()


def verify_entry_signature(entry: MitigationAuditEntry, hmac_key: bytes) -> bool:
    return hmac.compare_digest(entry.signature, _sign_entry(entry, hmac_key))


def append_audit_entry(log_path: Path, entry: MitigationAuditEntry, hmac_key: bytes) -> None:
    entry.signature = _sign_entry(entry, hmac_key)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry.to_dict()) + "\n")


def read_audit_log(log_path: Path) -> List[MitigationAuditEntry]:
    if not log_path.exists():
        return []
    entries = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(MitigationAuditEntry(**json.loads(line)))
    return entries


# ---------------------------------------------------------------------------
# Mitigation engine orchestration
# ---------------------------------------------------------------------------

class MitigationEngine:
    def __init__(
        self,
        policy: PolicyEngine,
        backend: ContainerRuntimeBackend,
        audit_log_path: Path = DEFAULT_AUDIT_LOG,
        hmac_key: Optional[bytes] = None,
        operator: str = "cbad-mitigation-engine",
    ):
        self.policy = policy
        self.backend = backend
        self.audit_log_path = audit_log_path
        self.hmac_key = hmac_key or load_or_create_hmac_key(DEFAULT_HMAC_KEY_PATH)
        self.operator = operator

    def handle(self, scored_event: ScoredSyscallEvent, container_ref: ContainerRef) -> MitigationDecision:
        decision = self.policy.decide(scored_event)
        incident_id = str(uuid.uuid4())
        steps = execute_playbook(decision, container_ref, self.backend, incident_id)

        entry = MitigationAuditEntry(
            incident_id=incident_id,
            triggered_by_event_id=scored_event.event.event_id,
            container_ref=asdict(container_ref),
            decision_action=decision.action,
            reason=decision.reason,
            steps_taken=steps,
            operator=self.operator,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        append_audit_entry(self.audit_log_path, entry, self.hmac_key)
        return decision


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run_self_test() -> Dict[str, Any]:
    import shutil
    import tempfile

    workdir = Path(tempfile.mkdtemp(prefix="cbad-stage6-"))
    try:
        backend = DryRunBackend()
        policy = PolicyEngine()
        hmac_key = load_or_create_hmac_key(workdir / "hmac.key")
        engine = MitigationEngine(policy, backend, audit_log_path=workdir / "audit.jsonl", hmac_key=hmac_key)

        decisions_by_action: Dict[str, int] = {}
        for scored_event in monitor_self_test():
            container_ref = derive_container_ref(scored_event.event.container_id)
            decision = engine.handle(scored_event, container_ref)
            decisions_by_action[decision.action] = decisions_by_action.get(decision.action, 0) + 1

        audit_entries = read_audit_log(engine.audit_log_path)
        all_signatures_valid = all(verify_entry_signature(e, hmac_key) for e in audit_entries)
        terminate_actions = sum(1 for a in backend.log.actions if a["action"] == "terminate")

        return {
            "decisions_by_action": decisions_by_action,
            "audit_entries_written": len(audit_entries),
            "all_signatures_valid": all_signatures_valid,
            "dry_run_terminate_calls": terminate_actions,
            "backend_actions_sample": backend.log.actions[:3],
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _load_scored_events(path: Path) -> List[ScoredSyscallEvent]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(scored_event_from_dict(json.loads(line)))
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 6 automated mitigation and kill-logic engine")
    parser.add_argument("--listen", help="Path to a JSONL file of ScoredSyscallEvent records (from syscall_monitor.py --output)")
    parser.add_argument("--backend", choices=["dry-run", "kubernetes"], default="dry-run")
    parser.add_argument(
        "--execute", action="store_true",
        help="Required in addition to --backend kubernetes to actually issue kubectl commands; otherwise dry-run is forced",
    )
    parser.add_argument("--namespace", default="buildns")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        print(json.dumps(run_self_test(), indent=2))
        return 0

    if not args.listen:
        parser.error("Provide --listen <jsonl file> or --self-test")

    if args.backend == "kubernetes" and not args.execute:
        print("[mitigation_engine] --backend kubernetes requires --execute; forcing dry-run", file=sys.stderr)
        backend: ContainerRuntimeBackend = DryRunBackend()
    elif args.backend == "kubernetes":
        backend = KubernetesBackend()
    else:
        backend = DryRunBackend()

    engine = MitigationEngine(PolicyEngine(), backend)
    results = []
    for scored_event in _load_scored_events(Path(args.listen)):
        container_ref = derive_container_ref(scored_event.event.container_id, namespace=args.namespace)
        decision = engine.handle(scored_event, container_ref)
        results.append({
            "event_id": scored_event.event.event_id,
            "score": scored_event.score,
            "decision": asdict(decision),
        })

    print(json.dumps(results, indent=2))
    print(f"\n{len(results)} events processed; audit log: {engine.audit_log_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
