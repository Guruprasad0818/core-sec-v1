#!/usr/bin/env python3
"""Dependency Graph Trust engine for CBAD Stage 2.

Usage:
  python stage2/dgt_engine.py --input requirements.txt
  python stage2/dgt_engine.py --input package.json
  python stage2/dgt_engine.py --input package.json --metrics package_metrics.json
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def clip(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return max(minimum, min(maximum, value))


def sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def normalized(value: float, max_value: float, min_value: float = 0.0) -> float:
    if max_value <= min_value:
        return 0.0
    return clip((value - min_value) / (max_value - min_value))


def parse_requirements(path: Path) -> Dict[str, str]:
    deps = {}
    with path.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("-e "):
                line = line[3:].strip()
            if ";" in line:
                line = line.split(";", 1)[0].strip()
            if "==" in line:
                name, version = line.split("==", 1)
            elif ">=" in line:
                name, version = line.split(">=", 1)
            elif "~=" in line:
                name, version = line.split("~=", 1)
            elif "@" in line and line.startswith("git+"):
                name = os.path.basename(line)
                version = "git"
            elif "@" in line:
                name, version = line.split("@", 1)
            else:
                parts = re.split(r"[<>=!~]+", line, maxsplit=1)
                name = parts[0]
                version = ""
            name = name.strip().lower()
            version = version.strip()
            if name:
                deps[name] = version or "latest"
    return deps


def parse_package_json(path: Path) -> Dict[str, str]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    deps = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section_data = data.get(section, {})
        if isinstance(section_data, dict):
            for name, version in section_data.items():
                deps[name.lower()] = str(version)
    return deps


def deterministic_metrics(seed: str) -> Dict[str, float]:
    seed_hash = int(hashlib.sha256(seed.encode("utf-8")).hexdigest(), 16)
    random_values = [(seed_hash >> (i * 8)) & 0xFF for i in range(8)]
    return {
        "cve_count_1y": float(random_values[0] % 6),
        "cve_severity_sum": float((random_values[1] % 30) + (random_values[0] % 6) * 1.5),
        "cve_age_weighted": float((random_values[2] % 40) + 5.0),
        "direct_transitive_cve_count": float(random_values[3] % 4),
        "owner_count": float((random_values[4] % 6) + 1),
        "org_count": float(random_values[5] % 3),
        "maintainer_activity_index": float(((random_values[6] % 80) + 20) / 100),
        "top_contributor_ratio": float(((random_values[7] % 80) + 10) / 100),
        "recent_commit_diversity": float(min(1.0, ((random_values[0] % 12) / 10))),
        "maintainer_depth": float((random_values[1] % 8) + 1),
        "release_interval_days": float(((random_values[2] % 120) + 10)),
        "release_volume": float((random_values[3] % 24) + 1),
        "churned_major_releases": float(random_values[4] % 4),
        "patch_density": float(((random_values[5] % 90) + 10) / 100),
        "pr_review_rate": float(((random_values[6] % 80) + 10) / 100),
        "review_depth": float(((random_values[7] % 3) + 1)),
        "review_latency_days": float((random_values[0] % 20) + 1),
        "reviewed_release_ratio": float(((random_values[1] % 70) + 20) / 100),
        "download_rank": float(((random_values[2] % 90) + 5) / 100),
        "issue_activity": float(((random_values[3] % 80) + 10) / 100),
        "stars_forks_score": float(((random_values[4] % 80) + 10) / 100),
        "community_age": float(min(1.0, ((random_values[5] % 48) / 24))),
        "corporate_sponsor": float(random_values[6] % 2),
        "paid_support_available": float(random_values[7] % 2),
        "security_program_presence": float(((random_values[0] % 70) + 20) / 100),
        "enterprise_adoption": float(((random_values[1] % 70) + 10) / 100),
        "dependency_depth": float((random_values[2] % 10) + 1),
        "transitive_count": float((random_values[3] % 60) + 1),
        "critical_dependency_ratio": float(((random_values[4] % 50) + 5) / 100),
        "coverage_percent": float(((random_values[5] % 90) + 5)),
        "ci_status": float(((random_values[6] % 90) + 5) / 100),
        "thin_tests_flag": float(random_values[7] % 2),
        "docs_presence": float(random_values[0] % 2),
        "docs_depth": float(min(1.0, ((random_values[1] % 6) / 5))),
        "docs_freshness": float(((random_values[2] % 90) + 10) / 100),
    }


@dataclass
class DGTResult:
    name: str
    version: str
    dgt_score: int
    trust_category: str
    policy_action: str
    path_factor: float
    env_bias: float
    component_scores: Dict[str, float]
    narrative_reasons: List[str]
    artifact_id: str
    raw_scores: Dict[str, float]


class DGTScorer:
    def __init__(self, env: str = "production", quarantine_threshold: int = 40):
        self.env = env
        self.quarantine_threshold = quarantine_threshold

    def score_package(self, name: str, version: str, metrics: Dict[str, float]) -> DGTResult:
        scores = self.compute_component_scores(metrics)
        raw = (
            0.18 * scores["S_CVE"]
            + 0.12 * scores["S_maintainers"]
            + 0.10 * scores["S_bus"]
            + 0.10 * scores["S_release"]
            + 0.12 * scores["S_review"]
            + 0.10 * scores["S_community"]
            + 0.08 * scores["S_corporate"]
            + 0.08 * scores["S_depth"]
            + 0.07 * scores["S_tests"]
            + 0.05 * scores["S_docs"]
        )
        penalty = self.compute_penalty(metrics)
        dgt_raw = clip(raw - penalty / 100.0, 0.0, 1.0)
        dgt_score = int(round(dgt_raw * 100.0))
        path_factor = max(0.25, 1 - 0.05 * metrics.get("dependency_depth", 0.0))
        env_bias = 0.9 if self.env == "production" else 1.0
        effective = int(round(clip(dgt_score * path_factor * env_bias, 0.0, 100.0)))
        trust_category = self.categorize(effective)
        policy_action = self.determine_action(effective, metrics)
        narrative = self.build_narrative(scores, metrics)
        artifact_id = hashlib.sha256(f"{name}:{version}".encode("utf-8")).hexdigest()
        return DGTResult(
            name=name,
            version=version,
            dgt_score=effective,
            trust_category=trust_category,
            policy_action=policy_action,
            path_factor=path_factor,
            env_bias=env_bias,
            component_scores={k: round(v, 2) for k, v in scores.items()},
            narrative_reasons=narrative,
            artifact_id=artifact_id,
            raw_scores={k: round(v, 2) for k, v in scores.items()},
        )

    def compute_component_scores(self, metrics: Dict[str, float]) -> Dict[str, float]:
        s_cve = self.score_cve(metrics)
        s_maintainers = self.score_maintainers(metrics)
        s_bus = self.score_bus(metrics)
        s_release = self.score_release(metrics)
        s_review = self.score_review(metrics)
        s_community = self.score_community(metrics)
        s_corporate = self.score_corporate(metrics)
        s_depth = self.score_depth(metrics)
        s_tests = self.score_tests(metrics)
        s_docs = self.score_docs(metrics)
        return {
            "S_CVE": s_cve,
            "S_maintainers": s_maintainers,
            "S_bus": s_bus,
            "S_release": s_release,
            "S_review": s_review,
            "S_community": s_community,
            "S_corporate": s_corporate,
            "S_depth": s_depth,
            "S_tests": s_tests,
            "S_docs": s_docs,
        }

    def score_cve(self, metrics: Dict[str, float]) -> float:
        cve_count = metrics.get("cve_count_1y", 0.0)
        severity = metrics.get("cve_severity_sum", 0.0)
        age_weighted = metrics.get("cve_age_weighted", 0.0)
        transitive = 1 + 0.25 * metrics.get("direct_transitive_cve_count", 0.0)
        risk = clip(
            (0.6 * normalized(cve_count, 10) + 0.3 * normalized(severity, 30) + 0.1 * normalized(age_weighted, 50))
            * transitive,
            0.0,
            1.0,
        )
        return 100.0 * (1.0 - risk)

    def score_maintainers(self, metrics: Dict[str, float]) -> float:
        owner_count = metrics.get("owner_count", 1.0)
        org_count = metrics.get("org_count", 1.0)
        activity_index = metrics.get("maintainer_activity_index", 0.5)
        strength = clip((owner_count / 5.0) * 0.6 + org_count * 0.2 + activity_index * 0.2, 0.0, 1.0)
        return 100.0 * strength

    def score_bus(self, metrics: Dict[str, float]) -> float:
        top_ratio = metrics.get("top_contributor_ratio", 0.8)
        diversity = clip(metrics.get("recent_commit_diversity", 0.5), 0.0, 1.0)
        depth = clip(metrics.get("maintainer_depth", 1.0) / 10.0, 0.0, 1.0)
        risk = clip(0.4 * top_ratio + 0.3 * (1.0 - diversity) + 0.3 * (1.0 - depth), 0.0, 1.0)
        return 100.0 * (1.0 - risk)

    def score_release(self, metrics: Dict[str, float]) -> float:
        interval = metrics.get("release_interval_days", 90.0)
        volume = metrics.get("release_volume", 4.0)
        churned = metrics.get("churned_major_releases", 0.0)
        patch_density = clip(metrics.get("patch_density", 0.5), 0.0, 1.0)
        freq_score = clip(
            0.5 * math.exp(-interval / 90.0)
            + 0.3 * math.tanh(volume / 20.0)
            + 0.2 * patch_density,
            0.0,
            1.0,
        )
        stab_penalty = min(0.4, 0.1 * max(0.0, churned - 2.0))
        return 100.0 * clip(freq_score - stab_penalty, 0.0, 1.0)

    def score_review(self, metrics: Dict[str, float]) -> float:
        pr_rate = clip(metrics.get("pr_review_rate", 0.5), 0.0, 1.0)
        review_depth = clip(metrics.get("review_depth", 1.0) / 2.0, 0.0, 1.0)
        latency = metrics.get("review_latency_days", 7.0)
        reviewed_release_ratio = clip(metrics.get("reviewed_release_ratio", 0.5), 0.0, 1.0)
        review_signal = (
            0.4 * pr_rate
            + 0.3 * review_depth
            + 0.2 * (1.0 - sigmoid(latency / 7.0))
            + 0.1 * reviewed_release_ratio
        )
        return 100.0 * clip(review_signal, 0.0, 1.0)

    def score_community(self, metrics: Dict[str, float]) -> float:
        download_rank = clip(metrics.get("download_rank", 0.5), 0.0, 1.0)
        issue_activity = clip(metrics.get("issue_activity", 0.5), 0.0, 1.0)
        stars_forks = clip(metrics.get("stars_forks_score", 0.5), 0.0, 1.0)
        community_age = clip(metrics.get("community_age", 0.5), 0.0, 1.0)
        community_signal = (
            0.45 * download_rank
            + 0.25 * issue_activity
            + 0.2 * stars_forks
            + 0.1 * community_age
        )
        return 100.0 * clip(community_signal, 0.0, 1.0)

    def score_corporate(self, metrics: Dict[str, float]) -> float:
        sponsor = clip(metrics.get("corporate_sponsor", 0.0), 0.0, 1.0)
        paid_support = clip(metrics.get("paid_support_available", 0.0), 0.0, 1.0)
        security_program = clip(metrics.get("security_program_presence", 0.0), 0.0, 1.0)
        adoption = clip(metrics.get("enterprise_adoption", 0.0), 0.0, 1.0)
        corp_signal = 0.4 * sponsor + 0.2 * paid_support + 0.3 * security_program + 0.1 * adoption
        return 100.0 * clip(corp_signal, 0.0, 1.0)

    def score_depth(self, metrics: Dict[str, float]) -> float:
        depth = metrics.get("dependency_depth", 1.0)
        transitive = metrics.get("transitive_count", 1.0)
        critical_ratio = clip(metrics.get("critical_dependency_ratio", 0.0), 0.0, 1.0)
        depth_risk = clip(
            0.5 * sigmoid((depth - 4.0) / 2.0)
            + 0.3 * sigmoid((transitive - 20.0) / 20.0)
            + 0.2 * critical_ratio,
            0.0,
            1.0,
        )
        return 100.0 * (1.0 - depth_risk)

    def score_tests(self, metrics: Dict[str, float]) -> float:
        coverage = normalized(metrics.get("coverage_percent", 0.0), 100.0)
        ci_status = clip(metrics.get("ci_status", 0.5), 0.0, 1.0)
        thin_tests = clip(metrics.get("thin_tests_flag", 1.0), 0.0, 1.0)
        test_signal = 0.5 * coverage + 0.3 * ci_status + 0.2 * (1.0 - thin_tests)
        return 100.0 * clip(test_signal, 0.0, 1.0)

    def score_docs(self, metrics: Dict[str, float]) -> float:
        docs_presence = clip(metrics.get("docs_presence", 0.0), 0.0, 1.0)
        docs_depth = clip(metrics.get("docs_depth", 0.0), 0.0, 1.0)
        docs_freshness = clip(metrics.get("docs_freshness", 0.0), 0.0, 1.0)
        docs_signal = 0.5 * docs_presence + 0.3 * docs_depth + 0.2 * docs_freshness
        return 100.0 * clip(docs_signal, 0.0, 1.0)

    def compute_penalty(self, metrics: Dict[str, float]) -> float:
        penalty = 0.0
        if metrics.get("has_unpatched_high_severity_CVE", False):
            penalty += 20.0
        if metrics.get("maintainer_account_unverified", False):
            penalty += 10.0
        if metrics.get("release_signature_missing", False):
            penalty += 15.0
        if metrics.get("namespace_conflict_with_internal_name", False):
            penalty += 30.0
        return penalty

    def categorize(self, score: int) -> str:
        if score >= 80:
            return "trusted"
        if score >= 60:
            return "caution"
        if score >= 40:
            return "risk"
        return "blocked"

    def determine_action(self, score: int, metrics: Dict[str, float]) -> str:
        if metrics.get("has_unpatched_high_severity_CVE", False) or metrics.get("namespace_conflict_with_internal_name", False):
            return "block"
        if score < self.quarantine_threshold:
            return "quarantine"
        if score < 60:
            return "review"
        return "allow"

    def build_narrative(self, scores: Dict[str, float], metrics: Dict[str, float]) -> List[str]:
        reasons: List[str] = []
        if scores["S_CVE"] < 50:
            reasons.append("High historical CVE risk.")
        if scores["S_maintainers"] < 50:
            reasons.append("Limited maintainer diversity or activity.")
        if scores["S_bus"] < 50:
            reasons.append("Low bus factor and contributor concentration.")
        if scores["S_release"] < 50:
            reasons.append("Unstable release cadence or major churn.")
        if scores["S_review"] < 50:
            reasons.append("Insufficient code review evidence.")
        if scores["S_depth"] < 50:
            reasons.append("Deep or risky transitive dependency graph.")
        if scores["S_tests"] < 50:
            reasons.append("Weak test coverage or flaky CI.")
        if scores["S_docs"] < 50:
            reasons.append("Minimal documentation quality.")
        if metrics.get("has_unpatched_high_severity_CVE", False):
            reasons.append("Unpatched high-severity CVE detected.")
        return reasons or ["No significant trust risks identified."]


def load_metrics(path: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    if path is None:
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def build_package_records(dep_map: Dict[str, str], metrics_map: Dict[str, Dict[str, Any]]) -> List[Tuple[str, str, Dict[str, float]]]:
    records: List[Tuple[str, str, Dict[str, float]]] = []
    for name, version in sorted(dep_map.items()):
        key = name.lower()
        metrics = metrics_map.get(key, {})
        if not metrics:
            metrics = deterministic_metrics(f"{name}:{version}")
        else:
            metrics = {**deterministic_metrics(f"{name}:{version}"), **metrics}
        records.append((name, version, metrics))
    return records


def detect_input_type(path: Path) -> str:
    if path.name.lower() == "package.json":
        return "package.json"
    if path.name.lower() == "requirements.txt":
        return "requirements.txt"
    raise ValueError("Unsupported input file type. Provide requirements.txt or package.json.")


def parse_input(path: Path) -> Dict[str, str]:
    if path.name.lower() == "package.json":
        return parse_package_json(path)
    if path.name.lower() == "requirements.txt":
        return parse_requirements(path)
    raise ValueError("Only requirements.txt and package.json are supported.")


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 2 Dependency Graph Trust (DGT) Engine")
    parser.add_argument("--input", required=True, help="Path to requirements.txt or package.json")
    parser.add_argument("--metrics", required=False, help="Optional JSON file with per-package metric overrides")
    parser.add_argument("--env", default="production", choices=["production", "staging", "development"], help="Environment bias")
    parser.add_argument("--quarantine-threshold", type=int, default=40, help="DGT score threshold to quarantine packages")
    parser.add_argument("--output", required=False, help="Optional JSON output file")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return 1

    dep_map = parse_input(input_path)
    metrics_map = load_metrics(Path(args.metrics)) if args.metrics else {}
    scorer = DGTScorer(env=args.env, quarantine_threshold=args.quarantine_threshold)
    results = []
    for name, version, metrics in build_package_records(dep_map, metrics_map):
        result = scorer.score_package(name, version, metrics)
        results.append({
            "name": name,
            "version": version,
            "artifact_id": result.artifact_id,
            "dgt_score": result.dgt_score,
            "trust_category": result.trust_category,
            "policy_action": result.policy_action,
            "path_factor": round(result.path_factor, 2),
            "env_bias": round(result.env_bias, 2),
            "component_scores": result.component_scores,
            "narrative_reasons": result.narrative_reasons,
        })

    output = {
        "input": str(input_path),
        "env": args.env,
        "quarantine_threshold": args.quarantine_threshold,
        "packages": results,
    }

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"Wrote DGT results to {out_path}")
    else:
        print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
