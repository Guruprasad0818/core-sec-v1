#!/usr/bin/env python3
import os
import sys
from cbad_feature_collector import CBADFeatureCollector
from local_feature_store import LocalFeatureStore


def main() -> int:
    repo_root = os.getcwd()
    collector = CBADFeatureCollector(repo_root)
    payload = collector.collect_features("pre-commit")
    store = LocalFeatureStore(repo_root)
    path = store.save_feature_payload("pre-commit", payload)
    print(f"CBAD pre-commit feature payload saved to {path}")
    print(f"files_changed_count={payload['files_changed_count']} lines_added={payload['lines_added']} lines_deleted={payload['lines_deleted']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())