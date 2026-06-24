"""Shared helpers for reading on-disk telemetry and normalizing it for the UI."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, List, Optional


def to_jsonable(obj: Any) -> Any:
    """Recursively convert dataclasses/sets into plain JSON-safe structures."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return to_jsonable(dataclasses.asdict(obj))
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    return obj


def read_json_file(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def read_jsonl_file(path: Path) -> List[Any]:
    if not path.exists():
        return []
    records = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return records
