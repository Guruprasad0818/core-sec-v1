#!/usr/bin/env python3
"""CBAD Stage 3 - CVE Prediction Platform: feature extraction + XGBoost ensemble.

Implements the modeling layer described in CBAD_Stage3_ML_Pipeline_Actions.md
(section 2.3, "XGBoost ensemble design") and CBAD_Stage3_MLOps_Serving_Drift.md
(section 4.2, "Model serving architecture"). Feature extraction here covers the
three domains requested for this build-out: commit velocity, issue velocity,
and maintainer activity (subsets of the full 205-feature catalog described in
CBAD_Stage3_Dataset_Architecture_FeatureEngineering.md, section 1.4).

This module does not perform feed ingestion (NVD/OSV/GitHub Advisories/etc. -
see section 1.2 of the architecture doc). It consumes already-collected
repository metadata (commits, issues, maintainer records) and trains/serves
an XGBoost ensemble that estimates the probability of a HIGH/CRITICAL CVE
within the next 90 days.

No historical CVE-labeled training set is wired up yet, so the ensemble
bootstraps itself from a deterministic synthetic dataset that encodes the
risk heuristics from the architecture docs (low maintainer bus factor, stale
maintainer activity, growing issue backlog, frequent reopens, etc.). Replace
`generate_synthetic_training_set` with a real feature-store extract once the
Stage 3 ingestion pipeline is online.

Usage:
  python stage3/cve_predictor.py --train
  python stage3/cve_predictor.py --train --samples 8000 --force
  python stage3/cve_predictor.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import math
import pickle
import statistics
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import xgboost as xgb

MODEL_DIR = Path(__file__).resolve().parent / "model_artifacts"
DEFAULT_MODEL_PATH = MODEL_DIR / "cve_ensemble.pkl"

ENSEMBLE_SIZE = 5
RANDOM_SEED = 1337

FEATURE_NAMES: List[str] = [
    # --- commit velocity (CBAD_Stage3_Dataset_Architecture_FeatureEngineering.md, 1.4.1) ---
    "commit_count_7d",
    "commit_count_30d",
    "commit_count_90d",
    "commit_weekly_rate",
    "commit_daily_rate",
    "commit_velocity_trend_90d",
    "night_commit_ratio_90d",
    "weekend_commit_ratio_90d",
    "avg_commit_size_30d",
    "commit_author_entropy_90d",
    # --- issue velocity (1.4.2) ---
    "issue_count_created_90d",
    "issue_count_closed_90d",
    "issue_close_rate_90d",
    "issue_backlog_age_median",
    "issue_security_label_ratio_90d",
    "issue_reopen_ratio_90d",
    "issue_triage_latency_median",
    # --- maintainer activity (1.4.3) ---
    "maintainer_count_active_90d",
    "maintainer_count_total",
    "maintainer_bus_factor",
    "maintainer_last_active_days",
    "maintainer_response_time_median",
    "maintainer_2fa_enforced_ratio",
]

SECURITY_LABELS = {"security", "vulnerability", "cve"}


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def _shannon_entropy(counts: Sequence[float]) -> float:
    total = sum(counts)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _linear_trend(series: Sequence[float]) -> float:
    n = len(series)
    if n < 2:
        return 0.0
    mean_x = (n - 1) / 2.0
    mean_y = sum(series) / n
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in enumerate(series))
    denominator = sum((x - mean_x) ** 2 for x in range(n))
    return numerator / denominator if denominator else 0.0


def extract_commit_velocity_features(commits: List[Dict[str, Any]], now: datetime) -> Dict[str, float]:
    parsed = [(ts, c) for c in commits if (ts := _parse_ts(c.get("timestamp"))) is not None]

    def count_since(days: int) -> int:
        cutoff = now - timedelta(days=days)
        return sum(1 for ts, _ in parsed if ts >= cutoff)

    count_7d = count_since(7)
    count_30d = count_since(30)
    count_90d = count_since(90)

    window_90d = [(ts, c) for ts, c in parsed if ts >= now - timedelta(days=90)]
    daily_buckets = [0.0] * 90
    night_count = 0
    weekend_count = 0
    for ts, _ in window_90d:
        day_offset = min(89, (now - ts).days)
        daily_buckets[89 - day_offset] += 1.0
        if ts.hour < 6 or ts.hour >= 22:
            night_count += 1
        if ts.weekday() >= 5:
            weekend_count += 1

    window_30d_sizes = [
        float(c.get("lines_changed", 0)) for ts, c in parsed if ts >= now - timedelta(days=30)
    ]
    author_counts = Counter(c.get("author", "unknown") for ts, c in window_90d)

    return {
        "commit_count_7d": float(count_7d),
        "commit_count_30d": float(count_30d),
        "commit_count_90d": float(count_90d),
        "commit_weekly_rate": count_30d / 4.0,
        "commit_daily_rate": count_30d / 30.0,
        "commit_velocity_trend_90d": _linear_trend(daily_buckets),
        "night_commit_ratio_90d": night_count / len(window_90d) if window_90d else 0.0,
        "weekend_commit_ratio_90d": weekend_count / len(window_90d) if window_90d else 0.0,
        "avg_commit_size_30d": statistics.fmean(window_30d_sizes) if window_30d_sizes else 0.0,
        "commit_author_entropy_90d": _shannon_entropy(list(author_counts.values())),
    }


def extract_issue_velocity_features(issues: List[Dict[str, Any]], now: datetime) -> Dict[str, float]:
    cutoff_90d = now - timedelta(days=90)
    window_90d = [i for i in issues if (ts := _parse_ts(i.get("created_at"))) is not None and ts >= cutoff_90d]

    created_90d = len(window_90d)
    closed_90d = sum(
        1 for i in issues
        if (ts := _parse_ts(i.get("closed_at"))) is not None and ts >= cutoff_90d
    )
    close_rate = closed_90d / created_90d if created_90d else 1.0

    backlog_ages: List[float] = []
    for issue in issues:
        created = _parse_ts(issue.get("created_at"))
        if created is None:
            continue
        closed = _parse_ts(issue.get("closed_at"))
        end = closed or now
        backlog_ages.append((end - created).total_seconds() / 86400.0)
    backlog_age_median = statistics.median(backlog_ages) if backlog_ages else 0.0

    security_count = sum(
        1 for i in window_90d
        if SECURITY_LABELS.intersection(label.lower() for label in i.get("labels", []))
    )
    security_ratio = security_count / created_90d if created_90d else 0.0

    reopened_count = sum(1 for i in window_90d if i.get("reopened"))
    reopen_ratio = reopened_count / created_90d if created_90d else 0.0

    triage_latencies: List[float] = []
    for issue in window_90d:
        created = _parse_ts(issue.get("created_at"))
        triaged = _parse_ts(issue.get("triaged_at"))
        if created is not None and triaged is not None:
            triage_latencies.append((triaged - created).total_seconds() / 86400.0)
    triage_latency_median = statistics.median(triage_latencies) if triage_latencies else 0.0

    return {
        "issue_count_created_90d": float(created_90d),
        "issue_count_closed_90d": float(closed_90d),
        "issue_close_rate_90d": close_rate,
        "issue_backlog_age_median": backlog_age_median,
        "issue_security_label_ratio_90d": security_ratio,
        "issue_reopen_ratio_90d": reopen_ratio,
        "issue_triage_latency_median": triage_latency_median,
    }


def extract_maintainer_activity_features(maintainers: List[Dict[str, Any]], now: datetime) -> Dict[str, float]:
    cutoff_90d = now - timedelta(days=90)
    active_90d = sum(
        1 for m in maintainers
        if (ts := _parse_ts(m.get("last_active"))) is not None and ts >= cutoff_90d
    )
    total = len(maintainers)

    commit_shares = [float(m.get("commit_count_90d", 0)) for m in maintainers]
    total_commits = sum(commit_shares)
    if total_commits > 0:
        herfindahl = sum((c / total_commits) ** 2 for c in commit_shares)
        bus_factor = (1.0 / herfindahl) if herfindahl > 0 else float(total)
    else:
        bus_factor = float(total)

    last_active_days = [
        (now - ts).total_seconds() / 86400.0
        for m in maintainers
        if (ts := _parse_ts(m.get("last_active"))) is not None
    ]
    min_last_active_days = min(last_active_days) if last_active_days else 9999.0

    response_times = [
        float(m["avg_response_hours"]) for m in maintainers if m.get("avg_response_hours") is not None
    ]
    response_time_median = statistics.median(response_times) if response_times else 0.0

    twofa_flags = [1.0 if m.get("2fa_enabled") else 0.0 for m in maintainers]
    twofa_ratio = statistics.fmean(twofa_flags) if twofa_flags else 0.0

    return {
        "maintainer_count_active_90d": float(active_90d),
        "maintainer_count_total": float(total),
        "maintainer_bus_factor": bus_factor,
        "maintainer_last_active_days": min_last_active_days,
        "maintainer_response_time_median": response_time_median,
        "maintainer_2fa_enforced_ratio": twofa_ratio,
    }


def extract_features(repo_metadata: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, float]:
    """Build the full named feature dict from raw repository metadata.

    `repo_metadata` is expected to have `commits`, `issues`, and `maintainers`
    list fields (see predict_risk.build_demo_repository for the expected shape).
    """
    now = now or datetime.now(timezone.utc)
    features: Dict[str, float] = {}
    features.update(extract_commit_velocity_features(repo_metadata.get("commits", []), now))
    features.update(extract_issue_velocity_features(repo_metadata.get("issues", []), now))
    features.update(extract_maintainer_activity_features(repo_metadata.get("maintainers", []), now))
    return features


def vectorize(features: Dict[str, float]) -> np.ndarray:
    return np.array([[features.get(name, 0.0) for name in FEATURE_NAMES]], dtype=np.float64)


# ---------------------------------------------------------------------------
# Synthetic bootstrap training data
# ---------------------------------------------------------------------------

FEATURE_RANGES: Dict[str, Tuple[float, float]] = {
    "commit_count_7d": (0, 60),
    "commit_count_30d": (0, 240),
    "commit_count_90d": (0, 720),
    "commit_weekly_rate": (0, 60),
    "commit_daily_rate": (0, 8),
    "commit_velocity_trend_90d": (-3, 3),
    "night_commit_ratio_90d": (0, 1),
    "weekend_commit_ratio_90d": (0, 1),
    "avg_commit_size_30d": (5, 800),
    "commit_author_entropy_90d": (0, 4),
    "issue_count_created_90d": (0, 150),
    "issue_count_closed_90d": (0, 150),
    "issue_close_rate_90d": (0, 1),
    "issue_backlog_age_median": (0, 250),
    "issue_security_label_ratio_90d": (0, 1),
    "issue_reopen_ratio_90d": (0, 0.6),
    "issue_triage_latency_median": (0, 45),
    "maintainer_count_active_90d": (0, 25),
    "maintainer_count_total": (0, 40),
    "maintainer_bus_factor": (1, 20),
    "maintainer_last_active_days": (0, 400),
    "maintainer_response_time_median": (0, 240),
    "maintainer_2fa_enforced_ratio": (0, 1),
}

# weights encode the risk heuristics from CBAD_Stage3_ML_Pipeline_Actions.md 2.5.3;
# "inv_" prefix means the *low* end of that feature's range is the risky end.
RISK_WEIGHTS: Dict[str, float] = {
    "issue_backlog_age_median": 0.65,
    "issue_security_label_ratio_90d": 0.75,
    "issue_reopen_ratio_90d": 0.55,
    "issue_triage_latency_median": 0.45,
    "maintainer_last_active_days": 0.65,
    "avg_commit_size_30d": 0.30,
    "night_commit_ratio_90d": 0.25,
    "weekend_commit_ratio_90d": 0.15,
    "commit_velocity_trend_90d": 0.15,
    "inv_maintainer_bus_factor": 0.65,
    "inv_maintainer_2fa_enforced_ratio": 0.55,
    "inv_maintainer_count_active_90d": 0.45,
    "inv_issue_close_rate_90d": 0.45,
    "inv_commit_author_entropy_90d": 0.20,
}


def _minmax(value: float, lo: float, hi: float) -> float:
    if hi <= lo:
        return 0.0
    return max(0.0, min(1.0, (value - lo) / (hi - lo)))


def generate_synthetic_training_set(
    n_samples: int = 4000, seed: int = RANDOM_SEED
) -> Tuple[np.ndarray, np.ndarray]:
    """Deterministic synthetic dataset used to bootstrap the ensemble until a
    real CVE-labeled feature store (section 1 of the architecture doc) is wired up.
    """
    rng = np.random.default_rng(seed)
    n_features = len(FEATURE_NAMES)
    X = np.zeros((n_samples, n_features), dtype=np.float64)

    for col, name in enumerate(FEATURE_NAMES):
        lo, hi = FEATURE_RANGES[name]
        if name == "commit_velocity_trend_90d":
            values = np.clip(rng.normal(0.0, 1.0, n_samples), lo, hi)
        else:
            values = rng.uniform(lo, hi, n_samples)
        X[:, col] = values

    # light, realistic correlations instead of pure independent noise
    idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
    X[:, idx["commit_weekly_rate"]] = X[:, idx["commit_count_30d"]] / 4.0
    X[:, idx["commit_daily_rate"]] = X[:, idx["commit_count_30d"]] / 30.0
    X[:, idx["commit_count_90d"]] = X[:, idx["commit_count_30d"]] * rng.uniform(2.0, 3.2, n_samples)
    X[:, idx["issue_count_closed_90d"]] = X[:, idx["issue_count_created_90d"]] * rng.uniform(0.2, 1.0, n_samples)
    created = X[:, idx["issue_count_created_90d"]]
    closed = X[:, idx["issue_count_closed_90d"]]
    X[:, idx["issue_close_rate_90d"]] = np.divide(closed, created, out=np.ones_like(created), where=created > 0)
    X[:, idx["maintainer_count_total"]] = X[:, idx["maintainer_count_active_90d"]] + rng.uniform(0, 15, n_samples)

    logits = np.zeros(n_samples, dtype=np.float64)
    for name, weight in RISK_WEIGHTS.items():
        inverse = name.startswith("inv_")
        feature_name = name[4:] if inverse else name
        lo, hi = FEATURE_RANGES[feature_name]
        col = idx[feature_name]
        norm = np.clip((X[:, col] - lo) / (hi - lo if hi > lo else 1.0), 0.0, 1.0)
        logits += weight * ((1.0 - norm) if inverse else norm)

    logits -= np.mean(logits)
    logits *= 4.0  # sharpen separation so the bootstrap labels aren't dominated by Bernoulli sampling noise
    noise = rng.normal(0.0, 0.3, n_samples)
    probabilities = 1.0 / (1.0 + np.exp(-(logits + noise)))
    y = (rng.uniform(0.0, 1.0, n_samples) < probabilities).astype(int)
    return X, y


# ---------------------------------------------------------------------------
# XGBoost ensemble
# ---------------------------------------------------------------------------

@dataclass
class CVEPredictionEnsemble:
    """Bag of XGBoost classifiers, each trained on a bootstrap row sample and a
    random feature subset (CBAD_Stage3_ML_Pipeline_Actions.md, 2.3.1: "stack
    multiple XGBoost models trained on different feature subsets").
    """

    models: List[xgb.XGBClassifier]
    feature_names: List[str]
    feature_subsets: List[List[int]]
    schema_hash: str
    trained_at: str
    metrics: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # pin to the real module name so pickle round-trips correctly even when
        # this file is executed directly (which would otherwise pickle the
        # class under "__main__" and break loading from other entrypoints)
        type(self).__module__ = "cve_predictor"

    def predict_proba(self, feature_vector: np.ndarray) -> float:
        vector = feature_vector.reshape(1, -1) if feature_vector.ndim == 1 else feature_vector
        probs = [
            float(model.predict_proba(vector[:, subset])[0, 1])
            for model, subset in zip(self.models, self.feature_subsets)
        ]
        return float(np.mean(probs))

    def feature_contributions(self, top_n: int = 5) -> Dict[str, float]:
        totals = np.zeros(len(self.feature_names))
        counts = np.zeros(len(self.feature_names))
        for model, subset in zip(self.models, self.feature_subsets):
            for local_idx, global_idx in enumerate(subset):
                totals[global_idx] += model.feature_importances_[local_idx]
                counts[global_idx] += 1
        averaged = np.divide(totals, counts, out=np.zeros_like(totals), where=counts > 0)
        ranked = sorted(zip(self.feature_names, averaged), key=lambda kv: kv[1], reverse=True)
        return {name: round(float(score), 4) for name, score in ranked[:top_n]}


def train_ensemble(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: List[str] = FEATURE_NAMES,
    ensemble_size: int = ENSEMBLE_SIZE,
    seed: int = RANDOM_SEED,
) -> CVEPredictionEnsemble:
    rng = np.random.default_rng(seed)
    n_samples, n_features = X.shape
    min_subset = max(4, int(n_features * 0.6))

    split = int(n_samples * 0.85)
    X_train, X_holdout = X[:split], X[split:]
    y_train, y_holdout = y[:split], y[split:]

    models: List[xgb.XGBClassifier] = []
    feature_subsets: List[List[int]] = []
    for i in range(ensemble_size):
        row_idx = rng.integers(0, len(X_train), len(X_train))
        subset_size = int(rng.integers(min_subset, n_features + 1))
        col_idx = sorted(rng.choice(n_features, size=subset_size, replace=False).tolist())

        model = xgb.XGBClassifier(
            objective="binary:logistic",
            tree_method="hist",
            n_estimators=150,
            max_depth=4,
            learning_rate=0.08,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=8,
            reg_lambda=4.0,
            eval_metric="logloss",
            random_state=seed + i,
        )
        model.fit(X_train[row_idx][:, col_idx], y_train[row_idx])
        models.append(model)
        feature_subsets.append(col_idx)

    schema_hash = hashlib.sha256(",".join(feature_names).encode("utf-8")).hexdigest()[:16]
    ensemble = CVEPredictionEnsemble(
        models=models,
        feature_names=list(feature_names),
        feature_subsets=feature_subsets,
        schema_hash=schema_hash,
        trained_at=datetime.now(timezone.utc).isoformat(),
    )

    if len(X_holdout):
        holdout_probs = np.array([ensemble.predict_proba(row) for row in X_holdout])
        predicted_labels = (holdout_probs >= 0.5).astype(int)
        accuracy = float(np.mean(predicted_labels == y_holdout))
        positive_rate = float(np.mean(y_holdout))
        ensemble.metrics = {
            "holdout_size": len(X_holdout),
            "holdout_accuracy": round(accuracy, 4),
            "holdout_positive_rate": round(positive_rate, 4),
        }

    return ensemble


def save_ensemble(ensemble: CVEPredictionEnsemble, path: Path = DEFAULT_MODEL_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(ensemble, fh)


def load_ensemble(path: Path = DEFAULT_MODEL_PATH) -> CVEPredictionEnsemble:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"No trained ensemble found at {path}")
    with path.open("rb") as fh:
        return pickle.load(fh)


def train_default_ensemble(
    samples: int = 4000, force: bool = False, path: Path = DEFAULT_MODEL_PATH
) -> CVEPredictionEnsemble:
    if not force:
        try:
            return load_ensemble(path)
        except FileNotFoundError:
            pass
    X, y = generate_synthetic_training_set(n_samples=samples)
    ensemble = train_ensemble(X, y)
    save_ensemble(ensemble, path)
    return ensemble


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 3 CVE prediction model trainer")
    parser.add_argument("--train", action="store_true", help="Train (or retrain) the XGBoost ensemble")
    parser.add_argument("--samples", type=int, default=4000, help="Synthetic training set size")
    parser.add_argument("--force", action="store_true", help="Retrain even if a cached model exists")
    parser.add_argument("--model-path", default=str(DEFAULT_MODEL_PATH))
    parser.add_argument("--self-test", action="store_true", help="Run feature extraction against a tiny inline sample")
    args = parser.parse_args()

    if args.train:
        ensemble = train_default_ensemble(samples=args.samples, force=args.force, path=Path(args.model_path))
        print(f"Trained ensemble of {len(ensemble.models)} XGBoost models")
        print(f"schema_hash={ensemble.schema_hash} trained_at={ensemble.trained_at}")
        print(f"holdout metrics: {ensemble.metrics}")
        print(f"global top features: {ensemble.feature_contributions()}")
        print(f"saved to {args.model_path}")

    if args.self_test:
        now = datetime.now(timezone.utc)
        sample_repo = {
            "commits": [
                {"timestamp": (now - timedelta(days=d)).isoformat(), "author": f"dev{d % 3}", "lines_changed": 40 + d}
                for d in range(0, 60, 3)
            ],
            "issues": [
                {
                    "created_at": (now - timedelta(days=d)).isoformat(),
                    "closed_at": (now - timedelta(days=max(d - 5, 0))).isoformat() if d > 10 else None,
                    "labels": ["security"] if d % 9 == 0 else ["bug"],
                    "reopened": d % 15 == 0,
                }
                for d in range(0, 90, 7)
            ],
            "maintainers": [
                {"name": "alice", "last_active": (now - timedelta(days=2)).isoformat(), "commit_count_90d": 40, "avg_response_hours": 4.0, "2fa_enabled": True},
                {"name": "bob", "last_active": (now - timedelta(days=120)).isoformat(), "commit_count_90d": 3, "avg_response_hours": 48.0, "2fa_enabled": False},
            ],
        }
        features = extract_features(sample_repo, now=now)
        for name, value in features.items():
            print(f"{name} = {round(value, 4)}")

    if not args.train and not args.self_test:
        parser.error("Provide --train and/or --self-test")
    return 0


if __name__ == "__main__":
    import sys as _sys

    # when run directly this module is "__main__", but pickle needs a stable,
    # importable module name to reload CVEPredictionEnsemble from other
    # entrypoints (e.g. predict_risk.py) - alias it so both names resolve to
    # the same module/class objects.
    _sys.modules.setdefault("cve_predictor", _sys.modules["__main__"])
    raise SystemExit(main())
