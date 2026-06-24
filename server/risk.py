"""Pure risk-classification logic shared by the overview aggregation.

Ported from dashboard/core/theme.py's level_for()/_VALUE_TO_LEVEL/LEVEL_RANK
so the API has no Streamlit dependency. Keep these two in sync if the
classification vocabulary changes.
"""

from __future__ import annotations

from typing import Any, Iterable

LEVEL_RANK = {"neutral": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_VALUE_TO_LEVEL = {
    "critical": "critical", "p0": "critical", "blocked": "critical", "block": "critical",
    "quarantine_and_terminate": "critical", "lockdown": "critical", "fail": "critical", "false": "critical",
    "high": "high", "p1": "high", "quarantine": "high", "quarantined": "high",
    "elevated_alert": "high", "elevated": "high", "risk": "high", "denied": "high",
    "medium": "medium", "moderate": "medium", "p2": "medium", "review": "medium", "caution": "medium",
    "low": "low", "p3": "low", "allow": "low", "allowed": "low", "trusted": "low",
    "log": "low", "pass": "low", "true": "low", "valid": "low", "ok": "low", "operational": "low",
    "skip": "low", "mitigate": "high",
}


def level_for(value: Any) -> str:
    """Classify any raw stage value onto critical/high/medium/low/neutral."""
    if value is None:
        return "neutral"
    if isinstance(value, bool):
        return "low" if value else "critical"
    return _VALUE_TO_LEVEL.get(str(value).strip().lower(), "neutral")


def deepest_level(values: Iterable[Any]) -> str:
    """Given a list of raw values, return the single highest-risk level."""
    levels = [level_for(v) for v in values if v is not None]
    if not levels:
        return "neutral"
    return max(levels, key=lambda lvl: LEVEL_RANK[lvl])
