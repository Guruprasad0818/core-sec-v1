"""Live Shannon-entropy / secrets scanning for Stage 5.

Runs stage5/entropy_scanner.py's existing detection engine (Shannon entropy
plus known-credential-format rules) against the live repository working
tree, the same way server/security_scanner.py runs live Semgrep for Stage 2.
This supersedes dashboard/core/ingestion.load_stage5's entropy half, which
only scanned STAGE_SOURCE_DIRS (stage1/..stage9/, not server/ or frontend/)
and silently fell back to a fixture whenever that narrower scan found
nothing.

stage5/entropy_scanner.py itself is untouched - it owns the entropy math and
detection rules. This module only adds the directory-walk pruning its
scan_directory() doesn't have: without skipping node_modules/.venv/etc., a
plain walk would also crawl every installed package, which is both pointless
and (per security_scanner.py's SCAN_TIMEOUT_SECONDS comment) slow under a
Docker Desktop bind mount.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Iterator, List

from bootstrap import REPO_ROOT
from core.stage_loader import load_module

_es = load_module("entropy_scanner")
SCAN_EXTENSIONS = _es.SCAN_EXTENSIONS
scan_file = _es.scan_file

EXCLUDE_DIRS = {"node_modules", ".venv", ".next", ".git", "__pycache__", "dist", "build"}

# Lockfiles are full of legitimate high-entropy content by design - npm's
# package-lock.json alone contributed 1152 of 1156 findings in this repo
# during testing, all sha512 subresource-integrity hashes, not secrets.
# Excluding them is standard practice for secret scanners generally (gitleaks
# and trufflehog both default-exclude the same set).
EXCLUDE_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock",
    "poetry.lock", "Cargo.lock", "go.sum", "composer.lock",
}

# Bucket edges for the findings' entropy-score distribution chart. Covers the
# engine's charset-relative thresholds (hex 3.0, generic 3.5, base64 4.5
# bits/char - see ENTROPY_THRESHOLDS_BITS_PER_CHAR in entropy_scanner.py) up
# through the practical ceiling for short tokens.
HISTOGRAM_EDGES: List[float] = [3.0, 3.5, 4.0, 4.5, 5.0, 5.5, 6.0]


def _scan_targets(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for filename in filenames:
            if filename in EXCLUDE_FILENAMES:
                continue
            path = Path(dirpath) / filename
            if path.suffix.lower() in SCAN_EXTENSIONS:
                yield path


def _entropy_distribution(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    edges = HISTOGRAM_EDGES
    counts = [0] * len(edges)
    for f in findings:
        entropy = f["entropy"]
        idx = len(edges) - 1
        for i in range(len(edges) - 1):
            if entropy < edges[i + 1]:
                idx = i
                break
        counts[idx] += 1
    buckets = []
    for i, count in enumerate(counts):
        lo = edges[i]
        label = f"{lo:.1f}+" if i == len(edges) - 1 else f"{lo:.1f}-{edges[i + 1]:.1f}"
        buckets.append({"bucket": label, "count": count})
    return buckets


def run_entropy_scan(repo_path: Path = REPO_ROOT) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for path in _scan_targets(repo_path):
        for finding in scan_file(path):
            d = finding.to_dict()
            try:
                d["file_path"] = str(Path(d["file_path"]).relative_to(repo_path))
            except ValueError:
                pass
            findings.append(d)

    findings.sort(key=lambda f: f["entropy"], reverse=True)

    return {
        "source": "live_entropy_scan",
        "repo_path": str(repo_path),
        "total_findings": len(findings),
        "high_confidence_count": sum(1 for f in findings if f["confidence"] == "high"),
        "medium_confidence_count": sum(1 for f in findings if f["confidence"] == "medium"),
        "entropy_distribution": _entropy_distribution(findings),
        "findings": findings,
    }
