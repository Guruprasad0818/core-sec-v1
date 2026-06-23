#!/usr/bin/env python3
"""Manual smoke test for CBAD Stage 2: DGT scoring + quarantine logic.

Simulates a package scan against a dummy dependency list (no network calls),
prints the trust score for each package, and runs the quarantine manager to
show which packages get blocked, quarantined, reviewed, or allowed.
"""

from __future__ import annotations

from dgt_engine import DGTScorer, deterministic_metrics
from quarantine_manager import QuarantineManager

DUMMY_DEPENDENCIES = [
    # (name, version, metric overrides)
    ("requests", "2.31.0", {}),
    ("left-pad", "1.0.0", {}),
    ("log4j-core", "2.14.1", {"has_unpatched_high_severity_CVE": True}),
    ("evil-typosquat-pkg", "0.0.1", {"namespace_conflict_with_internal_name": True}),
]


def main() -> int:
    scorer = DGTScorer(env="production", quarantine_threshold=40)
    manager = QuarantineManager(quarantine_threshold=40, review_threshold=60)

    records = []
    print("=== DGT Trust Scores ===")
    for name, version, overrides in DUMMY_DEPENDENCIES:
        metrics = {**deterministic_metrics(f"{name}:{version}"), **overrides}
        result = scorer.score_package(name, version, metrics)
        print(
            f"{name}@{version}: dgt_score={result.dgt_score} "
            f"category={result.trust_category} action={result.policy_action}"
        )
        records.append(
            {
                "name": result.name,
                "version": result.version,
                "dgt_score": result.dgt_score,
                "trust_category": result.trust_category,
                "policy_action": result.policy_action,
                "narrative_reasons": result.narrative_reasons,
            }
        )

    print("\n=== Quarantine Decisions ===")
    decisions = manager.filter_quarantine(records)
    for decision in decisions:
        flags = []
        if decision.block:
            flags.append("BLOCK")
        if decision.quarantine:
            flags.append("QUARANTINE")
        if decision.review:
            flags.append("REVIEW")
        if decision.allow:
            flags.append("ALLOW")
        print(f"{decision.name}@{decision.version}: score={decision.dgt_score} -> {', '.join(flags)}")
        for reason in decision.reasons:
            print(f"    - {reason}")

    summary = manager.summarize(decisions)
    print("\n=== Summary ===")
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
