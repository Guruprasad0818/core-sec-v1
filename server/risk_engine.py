"""Stage 3 - Predictive Risk Analytics.

Correlates Stage 1's live git history (server/git_info.py) with Stage 2's
live Semgrep findings (server/security_scanner.py): a file that has both
been touched by recent commits AND has open Semgrep findings is weighted
into a single 0-100 Risk Score. The score is also persisted as a real time
series under .git/cbad/risk_history.json (one point per distinct commit) so
the frontend can render an actual trend instead of synthetic data.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from bootstrap import REPO_ROOT
from git_info import get_live_git_info
from security_scanner import run_semgrep_scan

HISTORY_PATH = REPO_ROOT / ".git" / "cbad" / "risk_history.json"
HISTORY_MAX_ENTRIES = 30
SEVERITY_WEIGHTS = {"critical": 40, "high": 20, "medium": 5, "low": 1}


def _normalize(path: str) -> str:
    return path.replace("\\", "/")


def _touched_files(git_info: Dict[str, Any]) -> set[str]:
    """Union of every file path touched by the commits git_info covers."""
    touched: set[str] = set()
    for commit in git_info.get("commits", []):
        touched.update(_normalize(p) for p in commit.get("changed_files", []))
    return touched


def _band_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _score_findings_in_files(findings: List[Dict[str, Any]], target_files: set[str]) -> tuple[int, Dict[str, int], List[Dict[str, Any]]]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    matched: List[Dict[str, Any]] = []
    for f in findings:
        if _normalize(f.get("file_path", "")) not in target_files:
            continue
        band = f.get("severity", "low")
        counts[band] = counts.get(band, 0) + 1
        matched.append(f)
    weighted = sum(SEVERITY_WEIGHTS[band] * n for band, n in counts.items())
    return max(0, min(100, weighted)), counts, matched


def _load_history() -> List[Dict[str, Any]]:
    if not HISTORY_PATH.exists():
        return []
    try:
        return json.loads(HISTORY_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save_history(history: List[Dict[str, Any]]) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(history[-HISTORY_MAX_ENTRIES:], indent=2))


def _backfill_history(git_info: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """First-run bootstrap: replay the real commit history cumulatively
    against today's Semgrep findings to seed a non-empty, non-fabricated
    sparkline before any history has been persisted yet."""
    commits_oldest_first = list(reversed(git_info.get("commits", [])))
    touched: set[str] = set()
    history: List[Dict[str, Any]] = []
    for commit in commits_oldest_first:
        touched.update(_normalize(p) for p in commit.get("changed_files", []))
        score, _, _ = _score_findings_in_files(findings, touched)
        history.append(
            {
                "timestamp": commit.get("timestamp"),
                "commit_hash": commit.get("hash"),
                "risk_score": score,
            }
        )
    return history


def compute_risk_trend(git_info: Dict[str, Any] | None = None, semgrep_result: Dict[str, Any] | None = None) -> Dict[str, Any]:
    git_info = git_info if git_info is not None else get_live_git_info()
    semgrep_result = semgrep_result if semgrep_result is not None else run_semgrep_scan()

    findings = semgrep_result.get("findings", [])
    recent_files = _touched_files(git_info)
    risk_score, counts, matched = _score_findings_in_files(findings, recent_files)
    risk_band = _band_for_score(risk_score)
    commits = git_info.get("commits", [])
    latest_commit = commits[0]["hash"] if commits else "n/a"

    history = _load_history()
    if not history:
        history = _backfill_history(git_info, findings)

    if history and history[-1].get("commit_hash") == latest_commit:
        history[-1]["risk_score"] = risk_score
        history[-1]["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    else:
        history.append(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "commit_hash": latest_commit,
                "risk_score": risk_score,
            }
        )
    history = history[-HISTORY_MAX_ENTRIES:]
    _save_history(history)

    return {
        "source": "live_risk_correlation",
        "risk_score": risk_score,
        "risk_band": risk_band,
        "active_branch": git_info.get("active_branch", "n/a"),
        "commit_hash": latest_commit,
        "recent_files_count": len(recent_files),
        "findings_in_recent_files": counts,
        "matched_findings": matched,
        "history": history,
    }
