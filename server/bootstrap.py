"""Puts dashboard/ on sys.path so the API can import core.ingestion directly
instead of duplicating the stage1..stage9 loading logic. dashboard/core has
no Streamlit import at module scope (it's only used by theme.py, which this
server never imports), so this stays a clean, UI-framework-free dependency.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = REPO_ROOT / "dashboard"

_bootstrapped = False


def bootstrap() -> None:
    global _bootstrapped
    if _bootstrapped:
        return
    path_str = str(DASHBOARD_DIR)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
    _bootstrapped = True
