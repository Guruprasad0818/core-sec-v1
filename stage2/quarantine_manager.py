#!/usr/bin/env python3
"""Quarantine manager for CBAD Stage 2 artifact cache.

This module evaluates DGT results and decides whether an artifact should be quarantined,
blocked, reviewed, or allowed through the cache pipeline.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class QuarantineDecision:
    name: str
    version: str
    dgt_score: int
    trust_category: str
    policy_action: str
    quarantine: bool
    block: bool
    review: bool
    allow: bool
    reasons: List[str]


class QuarantineManager:
    def __init__(self, quarantine_threshold: int = 40, review_threshold: int = 60):
        self.quarantine_threshold = quarantine_threshold
        self.review_threshold = review_threshold

    def evaluate(self, package_record: Dict[str, Any]) -> QuarantineDecision:
        score = int(package_record.get("dgt_score", 0))
        category = package_record.get("trust_category", "risk")
        action = package_record.get("policy_action", "quarantine")
        reasons = list(package_record.get("narrative_reasons", []))

        block = action == "block" or score < 20
        quarantine = action == "quarantine" or (score < self.quarantine_threshold and not block)
        review = action == "review" or (score < self.review_threshold and score >= self.quarantine_threshold and not block)
        allow = action == "allow" and score >= self.review_threshold and not (block or quarantine)

        if block:
            reasons.append("Action: block")
        elif quarantine:
            reasons.append("Action: quarantine")
        elif review:
            reasons.append("Action: review")
        else:
            reasons.append("Action: allow")

        return QuarantineDecision(
            name=package_record.get("name", "unknown"),
            version=package_record.get("version", ""),
            dgt_score=score,
            trust_category=category,
            policy_action=action,
            quarantine=quarantine,
            block=block,
            review=review,
            allow=allow,
            reasons=reasons,
        )

    def filter_quarantine(self, records: List[Dict[str, Any]]) -> List[QuarantineDecision]:
        return [self.evaluate(record) for record in records]

    def summarize(self, decisions: List[QuarantineDecision]) -> Dict[str, Any]:
        summary = {
            "total_packages": len(decisions),
            "blocked": sum(1 for d in decisions if d.block),
            "quarantined": sum(1 for d in decisions if d.quarantine),
            "review": sum(1 for d in decisions if d.review),
            "allowed": sum(1 for d in decisions if d.allow),
        }
        return summary


def load_dgt_results(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("packages", []) if isinstance(data, dict) else data


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage 2 Quarantine Manager")
    parser.add_argument("--dgt-results", required=True, help="Path to DGT JSON output")
    parser.add_argument("--output", required=False, help="Optional JSON output path for quarantine decisions")
    parser.add_argument("--quarantine-threshold", type=int, default=40, help="Threshold to quarantine packages")
    parser.add_argument("--review-threshold", type=int, default=60, help="Threshold to mark packages for review")
    args = parser.parse_args()

    input_path = Path(args.dgt_results)
    if not input_path.exists():
        print(f"DGT results file not found: {input_path}")
        return 1

    records = load_dgt_results(input_path)
    manager = QuarantineManager(quarantine_threshold=args.quarantine_threshold, review_threshold=args.review_threshold)
    decisions = manager.filter_quarantine(records)
    output = {
        "dgt_results": str(input_path),
        "quarantine_threshold": args.quarantine_threshold,
        "review_threshold": args.review_threshold,
        "summary": manager.summarize(decisions),
        "decisions": [d.__dict__ for d in decisions],
    }

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(f"Wrote quarantine decisions to {out_path}")
    else:
        print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
