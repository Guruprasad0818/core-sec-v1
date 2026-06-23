#!/usr/bin/env python3
"""CBAD Stage 3 - risk scoring entrypoint.

Ingests repository metadata (commits, issues, maintainer records), runs it
through the feature extraction + XGBoost ensemble in cve_predictor.py, and
outputs a calibrated CVE risk score with an action band.

Risk bands follow CBAD_Stage3_ML_Pipeline_Actions.md section 3.2:
  low      p < 0.30   -> no automatic action
  medium   0.30-0.55   -> diagnostic review item
  high     0.55-0.80   -> Jira ticket + on-call alert
  critical p >= 0.80   -> Jira P1 + upgrade PR bot trigger

Usage:
  python stage3/predict_risk.py --demo
  python stage3/predict_risk.py --metadata path/to/repo.json
  python stage3/predict_risk.py --metadata path/to/repo.json --output result.json
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

from cve_predictor import (
    DEFAULT_MODEL_PATH,
    extract_features,
    load_ensemble,
    train_default_ensemble,
    vectorize,
)

RISK_BANDS = (
    (0.80, "critical"),
    (0.55, "high"),
    (0.30, "medium"),
    (0.0, "low"),
)


def classify_band(score: float) -> str:
    for threshold, label in RISK_BANDS:
        if score >= threshold:
            return label
    return "low"


def load_or_train_ensemble(model_path: Path = DEFAULT_MODEL_PATH):
    try:
        return load_ensemble(model_path)
    except FileNotFoundError:
        return train_default_ensemble(path=model_path)


def load_repo_metadata(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def build_demo_repository(now: datetime) -> Dict[str, Any]:
    """Synthetic example repository with a stale, under-resourced maintainer
    team and a growing security-labeled issue backlog - used for --demo runs.
    """
    return {
        "repository": "acme/legacy-parser",
        "commits": [
            {
                "timestamp": (now - timedelta(days=d, hours=2)).isoformat(),
                "author": "solo-maintainer",
                "lines_changed": 15,
            }
            for d in range(0, 90, 11)
        ],
        "issues": [
            {
                "created_at": (now - timedelta(days=d)).isoformat(),
                "closed_at": None if d < 60 else (now - timedelta(days=d - 5)).isoformat(),
                "labels": ["security"] if d % 12 == 0 else ["bug"],
                "reopened": d % 30 == 0,
                "triaged_at": (now - timedelta(days=d - 20)).isoformat() if d > 20 else None,
            }
            for d in range(0, 120, 6)
        ],
        "maintainers": [
            {
                "name": "solo-maintainer",
                "last_active": (now - timedelta(days=10)).isoformat(),
                "commit_count_90d": 8,
                "avg_response_hours": 96.0,
                "2fa_enabled": False,
            }
        ],
    }


def score_repository(metadata: Dict[str, Any], ensemble=None, model_path: Path = DEFAULT_MODEL_PATH) -> Dict[str, Any]:
    ensemble = ensemble or load_or_train_ensemble(model_path)
    now = datetime.now(timezone.utc)

    features = extract_features(metadata, now=now)
    vector = vectorize(features)
    score = ensemble.predict_proba(vector)
    band = classify_band(score)

    return {
        "repository": metadata.get("repository", metadata.get("name", "unknown")),
        "scored_at": now.isoformat(),
        "risk_score": round(score, 4),
        "risk_band": band,
        "top_contributing_features": ensemble.feature_contributions(),
        "feature_vector": {name: round(value, 4) for name, value in features.items()},
        "schema_hash": ensemble.schema_hash,
        "model_trained_at": ensemble.trained_at,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 3 CVE risk scoring")
    parser.add_argument("--metadata", help="Path to repository metadata JSON")
    parser.add_argument("--demo", action="store_true", help="Score a built-in synthetic example repository")
    parser.add_argument("--output", help="Optional path to write the JSON result")
    parser.add_argument("--model-path", default=str(DEFAULT_MODEL_PATH))
    args = parser.parse_args()

    if not args.metadata and not args.demo:
        parser.error("Provide --metadata <file> or --demo")

    model_path = Path(args.model_path)
    metadata = build_demo_repository(datetime.now(timezone.utc)) if args.demo else load_repo_metadata(Path(args.metadata))
    ensemble = load_or_train_ensemble(model_path)
    result = score_repository(metadata, ensemble, model_path)

    output_text = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Wrote risk score to {args.output}")
    else:
        print(output_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
