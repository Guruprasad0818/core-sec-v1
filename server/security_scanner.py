"""Live Semgrep vulnerability scanning for Stage 2.

Runs the real `semgrep` CLI against this repository and parses its JSON
output. This supersedes the previous Dependency Graph Trust (package-trust)
scoring that used to live here - Stage 2 is now a source-code vulnerability
scan, mirroring the request to repurpose it as "Threat Modeling &
Vulnerability Assessment".
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from bootstrap import REPO_ROOT
from risk import LEVEL_RANK

SEMGREP_CONFIGS = ["p/security-audit", "p/secrets"]
EXCLUDE_DIRS = ["node_modules", ".venv", ".next", ".git", "__pycache__", "dist", "build"]
# Generous margin: scanning through a Docker Desktop bind mount on Windows
# (the docker-compose deployment) is far slower than the native filesystem
# (~95s vs ~8s observed for this repo) since every excluded directory still
# has to be walked through the virtualized filesystem layer first.
SCAN_TIMEOUT_SECONDS = 180


def _severity_band(result: Dict[str, Any]) -> str:
    """Blend Semgrep's 3-tier rule severity with its rule-metadata impact
    rating into our critical/high/medium/low vocabulary (shared with every
    other stage via risk.py's level_for())."""
    extra = result.get("extra", {})
    severity = str(extra.get("severity", "INFO")).upper()
    impact = str(extra.get("metadata", {}).get("impact", "LOW")).upper()

    if severity == "ERROR":
        return "critical" if impact == "HIGH" else "high"
    if severity == "WARNING":
        if impact == "HIGH":
            return "high"
        return "medium" if impact == "MEDIUM" else "low"
    return "low"


def _as_list(value: Any) -> List[str]:
    # Semgrep rule metadata is author-supplied and inconsistent: owasp/cwe
    # show up as either a single string or a list of strings depending on
    # the rule.
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def run_semgrep_scan(repo_path: Path = REPO_ROOT) -> Dict[str, Any]:
    semgrep_bin = shutil.which("semgrep")
    if semgrep_bin is None:
        raise RuntimeError("semgrep executable not found on PATH - is it installed in this environment?")

    cmd = [semgrep_bin, "scan", "--json", "--quiet", "--metrics=off"]
    for config in SEMGREP_CONFIGS:
        cmd += ["--config", config]
    for exclude in EXCLUDE_DIRS:
        cmd += ["--exclude", exclude]
    cmd.append(str(repo_path))

    proc = subprocess.run(
        cmd,
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_SECONDS,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"semgrep scan failed (exit {proc.returncode}): {proc.stderr[-2000:]}")

    payload = json.loads(proc.stdout)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings: List[Dict[str, Any]] = []
    for r in payload.get("results", []):
        band = _severity_band(r)
        counts[band] += 1
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        raw_path = r.get("path", "")
        try:
            file_path = str(Path(raw_path).relative_to(repo_path))
        except ValueError:
            file_path = raw_path
        finding_id = r.get("check_id", "unknown")
        line_number = r.get("start", {}).get("line", 0)
        # finding_id is the Semgrep rule id, which repeats across every
        # location it matches - instance_id is the unique per-occurrence key
        # the Stage 4 remediation endpoint targets.
        instance_id = hashlib.sha256(f"{finding_id}|{file_path}|{line_number}".encode()).hexdigest()[:12]
        findings.append(
            {
                "instance_id": instance_id,
                "finding_id": finding_id,
                "severity": band,
                "message": extra.get("message", ""),
                "file_path": file_path,
                "line_number": line_number,
                "end_line": r.get("end", {}).get("line", 0),
                "owasp": _as_list(metadata.get("owasp")),
                "cwe": _as_list(metadata.get("cwe")),
            }
        )
    findings.sort(key=lambda f: LEVEL_RANK.get(f["severity"], 0), reverse=True)

    return {
        "source": "live_semgrep_scan",
        "repo_path": str(repo_path),
        "configs": SEMGREP_CONFIGS,
        "total_issues": len(findings),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "findings": findings,
        "scan_errors": [e.get("message", str(e)) for e in payload.get("errors", [])],
    }
