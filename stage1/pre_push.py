#!/usr/bin/env python3
import os
import sys
import json
from typing import List, Tuple
from cbad_feature_collector import CBADFeatureCollector
from local_feature_store import LocalFeatureStore


def parse_push_refs(lines: List[str]) -> List[Tuple[str, str, str]]:
    refs = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) == 3:
            refs.append((parts[0], parts[1], parts[2]))
    return refs


def main() -> int:
    repo_root = os.getcwd()
    stdin_lines = [line for line in sys.stdin.readlines()]
    push_refs = parse_push_refs(stdin_lines)

    collector = CBADFeatureCollector(repo_root)
    payload = collector.collect_features("pre-push", push_refs=push_refs)
    store = LocalFeatureStore(repo_root)
    path = store.save_feature_payload("pre-push", payload)
    print(f"CBAD pre-push feature payload saved to {path}")
    print(json.dumps({"stage": payload["stage"], "files_changed_count": payload["files_changed_count"], "push_ref_count": len(push_refs)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())