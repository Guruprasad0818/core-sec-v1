"""Stage 7 - Compliance Tracking & Governance.

Maps live findings from Stage 2 (Semgrep), Stage 5 (entropy/secrets), and
Stage 6 (runtime syscall monitor) onto two standard frameworks:
  - OWASP Top 10 (2021)
  - SOC 2 Trust Services Criteria, Common Criteria 6: CC6.1 (logical access
    control) and CC6.3 (perimeter defense / points of access)

This replaces the previous Cosign/K8s-admission demo that occupied the
Stage 7 API slot - stage7/cosign_wrapper.py and stage7/k8s_admission_validator.py
are untouched on disk, just no longer surfaced as Stage 7's response.

Semgrep findings already carry real OWASP metadata (see SemgrepFinding.owasp
in server/schemas.py), but different rules cite different OWASP *editions*
(2017, 2021, even a non-standard "2025" label some Semgrep rulepacks use) -
normalize_owasp_tag() below maps by category *name*, not by number, since
category numbers shifted meaning between editions (2017's A3 "Sensitive Data
Exposure" became 2021's A02 "Cryptographic Failures", not A03). Stage 5/6
findings have no native OWASP tag, so they're mapped deterministically onto
the two categories explicitly named in this stage's brief.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from bootstrap import REPO_ROOT
from risk import LEVEL_RANK

AUDIT_LOG_PATH = REPO_ROOT / "server" / "logs" / "compliance_audit.json"
AUDIT_LOG_MAX_ENTRIES = 500


@dataclass(frozen=True)
class ComplianceControl:
    control_id: str
    framework: str
    title: str
    description: str


OWASP_CONTROLS: Dict[str, ComplianceControl] = {
    "A01:2021": ComplianceControl("A01:2021", "OWASP Top 10 2021", "Broken Access Control", "Restrictions on what authenticated users are allowed to do are not properly enforced."),
    "A02:2021": ComplianceControl("A02:2021", "OWASP Top 10 2021", "Cryptographic Failures", "Sensitive data exposed due to weak or missing cryptographic protection, including hardcoded credentials."),
    "A03:2021": ComplianceControl("A03:2021", "OWASP Top 10 2021", "Injection", "Untrusted input is interpreted as part of a command or query."),
    "A04:2021": ComplianceControl("A04:2021", "OWASP Top 10 2021", "Insecure Design", "A missing or ineffective control design, not just an implementation bug."),
    "A05:2021": ComplianceControl("A05:2021", "OWASP Top 10 2021", "Security Misconfiguration", "Insecure default configurations, incomplete configurations, or verbose error messages."),
    "A06:2021": ComplianceControl("A06:2021", "OWASP Top 10 2021", "Vulnerable and Outdated Components", "Use of components with known vulnerabilities or that are unsupported."),
    "A07:2021": ComplianceControl("A07:2021", "OWASP Top 10 2021", "Identification and Authentication Failures", "Weaknesses in confirming a user's identity, authentication, or session management."),
    "A08:2021": ComplianceControl("A08:2021", "OWASP Top 10 2021", "Software and Data Integrity Failures", "Code and infrastructure that does not protect against integrity violations, including insecure deserialization."),
    "A09:2021": ComplianceControl("A09:2021", "OWASP Top 10 2021", "Security Logging and Monitoring Failures", "Insufficient logging/monitoring to detect and respond to active breaches."),
    "A10:2021": ComplianceControl("A10:2021", "OWASP Top 10 2021", "Server-Side Request Forgery (SSRF)", "An application fetches a remote resource without validating the user-supplied destination."),
}

SOC2_CONTROLS: Dict[str, ComplianceControl] = {
    "CC6.1": ComplianceControl("CC6.1", "SOC 2", "Logical Access Controls", "The entity implements logical access security to protect information assets from unauthorized access."),
    "CC6.3": ComplianceControl("CC6.3", "SOC 2", "Perimeter Defense", "The entity manages points of access and evaluates network egress/ingress against authorization."),
}

# (keyword fragment, canonical OWASP Top 10:2021 control_id) - matched as a
# case-insensitive substring against the free-text portion of any incoming
# owasp tag, regardless of which edition's number prefix it was filed under.
_OWASP_NAME_TO_2021: Tuple[Tuple[str, str], ...] = (
    ("access control", "A01:2021"),
    ("crypto", "A02:2021"),
    ("sensitive data exposure", "A02:2021"),
    ("injection", "A03:2021"),
    ("insecure design", "A04:2021"),
    ("misconfiguration", "A05:2021"),
    ("outdated component", "A06:2021"),
    ("vulnerable component", "A06:2021"),
    ("authentication", "A07:2021"),
    ("identification", "A07:2021"),
    ("deserialization", "A08:2021"),
    ("data integrity", "A08:2021"),
    ("logging", "A09:2021"),
    ("monitoring", "A09:2021"),
    ("ssrf", "A10:2021"),
    ("server-side request forgery", "A10:2021"),
)


def normalize_owasp_tag(raw: str) -> Optional[str]:
    lowered = raw.lower()
    for keyword, canonical in _OWASP_NAME_TO_2021:
        if keyword in lowered:
            return canonical
    return None


def _violation(
    control_id: str, source_stage: int, severity: str, summary: str,
    file_path: Optional[str] = None, line_number: Optional[int] = None,
    finding_ref: Optional[str] = None, timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    control = OWASP_CONTROLS.get(control_id) or SOC2_CONTROLS[control_id]
    return {
        "control_id": control_id,
        "framework": control.framework,
        "control_title": control.title,
        "source_stage": source_stage,
        "severity": severity,
        "summary": summary,
        "file_path": file_path,
        "line_number": line_number,
        "finding_ref": finding_ref,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
    }


def _evaluate(stage2: Dict[str, Any], stage5: Dict[str, Any], stage6: Dict[str, Any]) -> List[Dict[str, Any]]:
    violations: List[Dict[str, Any]] = []

    # Stage 2 - Semgrep findings already carry real OWASP rule metadata.
    for f in stage2.get("findings", []):
        canon_tags = {normalize_owasp_tag(t) for t in f.get("owasp", [])} - {None}
        for control_id in canon_tags:
            violations.append(_violation(
                control_id, source_stage=2, severity=f["severity"],
                summary=f"{f['finding_id']} - {f['message'][:140]}",
                file_path=f["file_path"], line_number=f["line_number"], finding_ref=f["instance_id"],
            ))
        if canon_tags & {"A01:2021", "A07:2021"}:
            violations.append(_violation(
                "CC6.1", source_stage=2, severity=f["severity"],
                summary=f"Access-control weakness: {f['finding_id']}",
                file_path=f["file_path"], line_number=f["line_number"], finding_ref=f["instance_id"],
            ))
        if "A10:2021" in canon_tags:
            violations.append(_violation(
                "CC6.3", source_stage=2, severity=f["severity"],
                summary=f"Perimeter/egress weakness: {f['finding_id']}",
                file_path=f["file_path"], line_number=f["line_number"], finding_ref=f["instance_id"],
            ))

    # Stage 5 - entropy/secrets findings have no native OWASP tag; a
    # hardcoded credential is a textbook A02 (Cryptographic Failures) and a
    # CC6.1 access-control exposure (whoever reads the file gets the secret).
    for f in stage5.get("entropy", {}).get("findings", []):
        severity = "high" if f["confidence"] == "high" else "medium"
        violations.append(_violation(
            "A02:2021", source_stage=5, severity=severity,
            summary=f"{f['rule_id']}: exposed secret {f['masked_value']}",
            file_path=f["file_path"], line_number=f["line_number"], finding_ref=f["finding_id"],
        ))
        violations.append(_violation(
            "CC6.1", source_stage=5, severity=severity,
            summary=f"Exposed credential in source: {f['masked_value']}",
            file_path=f["file_path"], line_number=f["line_number"], finding_ref=f["finding_id"],
        ))

    # Stage 6 - runtime syscall anomalies. An external egress is a perimeter
    # issue (CC6.3); everything else anomalous (unauthorized file/process
    # access, ptrace) is a logical access-control issue (CC6.1). Both are
    # broken-access-control in OWASP terms (A01), matching this stage's brief.
    for e in stage6.get("recent_events", []):
        if not e.get("is_anomalous"):
            continue
        event = e["event"]
        severity = "critical" if e["classification"] == "lockdown" else "high"
        rule_ids = [m["rule_id"] for m in e.get("falco_matches", [])]
        violations.append(_violation(
            "A01:2021", source_stage=6, severity=severity,
            summary=f"{event['syscall']} anomaly by {event['comm']} (pid {event['pid']})",
            finding_ref=event["event_id"], timestamp=event["timestamp"],
        ))
        if "connect_external_ip" in rule_ids:
            violations.append(_violation(
                "CC6.3", source_stage=6, severity=severity,
                summary=f"Unexpected egress to {event['args'].get('ip', '?')}:{event['args'].get('port', '?')}",
                finding_ref=event["event_id"], timestamp=event["timestamp"],
            ))
        else:
            violations.append(_violation(
                "CC6.1", source_stage=6, severity=severity,
                summary=f"Unauthorized {event['syscall']} by {event['comm']}",
                finding_ref=event["event_id"], timestamp=event["timestamp"],
            ))

    return violations


def _scorecard(controls: Dict[str, ComplianceControl], violations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_control: Dict[str, List[Dict[str, Any]]] = {cid: [] for cid in controls}
    for v in violations:
        if v["control_id"] in by_control:
            by_control[v["control_id"]].append(v)

    rows = []
    for control_id, control in controls.items():
        matched = by_control[control_id]
        highest = max((v["severity"] for v in matched), key=lambda s: LEVEL_RANK.get(s, 0), default=None)
        rows.append({
            "control_id": control_id,
            "title": control.title,
            "description": control.description,
            "status": "FAIL" if matched else "PASS",
            "violation_count": len(matched),
            "highest_severity": highest,
        })
    return rows


def _violation_key(v: Dict[str, Any]) -> str:
    # Stable identity for a violation across scans: prefer the originating
    # finding's own id (instance_id/finding_id/event_id), since file/line
    # alone isn't unique when several controls map to the same finding.
    return f"{v['control_id']}|{v.get('finding_ref') or (v.get('file_path'), v.get('line_number'))}"


# In-memory only (resets on process restart, which is fine for a demo app) -
# lets run_compliance_check() log only *new* failures and *resolved* ones
# instead of re-dumping the entire current violation list on every scan.
# Without this, a single scan's ~1400 violations embedded in every 5-minute
# cache-refresh entry would balloon this "static" log file by hundreds of KB
# per write - observed directly during testing (674KB from one scan alone).
# None (not an empty set) means "no baseline established yet" - the first
# scan in a fresh process sets the baseline without individually logging
# every pre-existing finding as "new", since that's the existing backlog, not
# something that just happened; only genuine changes after that get logged.
_last_violation_keys: Optional[Set[str]] = None


def _write_audit_log(entries: List[Dict[str, Any]]) -> None:
    if not entries:
        return
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = json.loads(AUDIT_LOG_PATH.read_text(encoding="utf-8")) if AUDIT_LOG_PATH.exists() else []
        if not isinstance(existing, list):
            existing = []
    except (OSError, json.JSONDecodeError):
        existing = []
    existing.extend(entries)
    if len(existing) > AUDIT_LOG_MAX_ENTRIES:
        existing = existing[-AUDIT_LOG_MAX_ENTRIES:]
    AUDIT_LOG_PATH.write_text(json.dumps(existing, indent=2), encoding="utf-8")


def record_remediation(result: Dict[str, Any]) -> None:
    """Called from server/main.py's /api/v1/stage/4/remediate endpoint after
    a successful commit - the other half of "every compliance failure and
    remediation action" gets logged to the same audit trail."""
    _write_audit_log([{
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "remediation",
        "status": result.get("status"),
        "file_path": result.get("file_path"),
        "line_number": result.get("line_number"),
        "branch": result.get("branch"),
        "commit_hash": result.get("commit_hash"),
        "summary": result.get("summary"),
    }])


def run_compliance_check(stage2: Dict[str, Any], stage5: Dict[str, Any], stage6: Dict[str, Any]) -> Dict[str, Any]:
    violations = _evaluate(stage2, stage5, stage6)
    violations.sort(key=lambda v: (LEVEL_RANK.get(v["severity"], 0), v["timestamp"]), reverse=True)

    owasp_rows = _scorecard(OWASP_CONTROLS, violations)
    soc2_rows = _scorecard(SOC2_CONTROLS, violations)
    owasp_passed = sum(1 for r in owasp_rows if r["status"] == "PASS")
    soc2_passed = sum(1 for r in soc2_rows if r["status"] == "PASS")

    report = {
        "source": "live_compliance_engine",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "owasp": {
            "framework": "OWASP Top 10 2021",
            "controls": owasp_rows,
            "passed": owasp_passed,
            "total": len(owasp_rows),
            "readiness_pct": round(100 * owasp_passed / len(owasp_rows), 1),
        },
        "soc2": {
            "framework": "SOC 2 - Common Criteria 6",
            "controls": soc2_rows,
            "passed": soc2_passed,
            "total": len(soc2_rows),
            "readiness_pct": round(100 * soc2_passed / len(soc2_rows), 1),
        },
        "rules_passed": owasp_passed + soc2_passed,
        "rules_failed": (len(owasp_rows) - owasp_passed) + (len(soc2_rows) - soc2_passed),
        "total_violations": len(violations),
        "violations": violations,
    }

    # Diff-based audit logging only covers Stage 2/5 (Semgrep/entropy) -
    # those are static code-state findings with a stable finding_ref, so
    # "new" vs "resolved" is a meaningful, low-churn signal. Stage 6's
    # runtime events get a fresh event_id every cycle by design (each one
    # really is a distinct moment in time) and already have their own live
    # view (Stage 6's SSE terminal) - diffing them here would mean every
    # scan looks "all new" forever and floods this log out of usefulness.
    global _last_violation_keys
    trackable = [v for v in violations if v["source_stage"] in (2, 5)]
    current_by_key = {_violation_key(v): v for v in trackable}
    current_keys = set(current_by_key)
    is_baseline = _last_violation_keys is None
    new_keys = set() if is_baseline else current_keys - _last_violation_keys
    resolved_keys = set() if is_baseline else _last_violation_keys - current_keys

    audit_entries: List[Dict[str, Any]] = [{
        "timestamp": report["generated_at"],
        "event": "compliance_baseline" if is_baseline else "compliance_scan",
        "total_violations": len(violations),
        "rules_passed": report["rules_passed"],
        "rules_failed": report["rules_failed"],
        "owasp_readiness_pct": report["owasp"]["readiness_pct"],
        "soc2_readiness_pct": report["soc2"]["readiness_pct"],
        "new_failures": len(new_keys),
        "resolved": len(resolved_keys),
    }]
    for key in new_keys:
        audit_entries.append({**current_by_key[key], "event": "compliance_failure"})
    for key in resolved_keys:
        audit_entries.append({
            "timestamp": report["generated_at"],
            "event": "compliance_resolved",
            "control_id": key.split("|", 1)[0],
        })
    _write_audit_log(audit_entries)
    _last_violation_keys = current_keys

    return report
