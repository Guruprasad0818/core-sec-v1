"""Bootstraps sys.path so the dashboard can import the stage1..stage9 modules
directly (they use flat sibling imports like `from sast_engine import ...`,
so each stageN/ directory must be on sys.path, not just the repo root)."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGE_DIRS = {n: REPO_ROOT / f"stage{n}" for n in range(1, 10)}

_bootstrapped = False


def bootstrap() -> None:
    global _bootstrapped
    if _bootstrapped:
        return
    for stage_dir in STAGE_DIRS.values():
        path_str = str(stage_dir)
        if stage_dir.exists() and path_str not in sys.path:
            sys.path.insert(0, path_str)
    _bootstrapped = True


def load_module(module_name: str) -> Any:
    """Import a stage module by its bare filename (e.g. 'sast_engine')."""
    bootstrap()
    if module_name in sys.modules:
        return sys.modules[module_name]
    return importlib.import_module(module_name)
