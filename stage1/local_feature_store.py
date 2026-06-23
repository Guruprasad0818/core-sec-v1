import json
import os
import datetime
from typing import Dict, Optional


class LocalFeatureStore:
    def __init__(self, repo_root: str):
        self.repo_root = repo_root
        self.store_dir = os.path.join(repo_root, ".git", "cbad", "features")
        os.makedirs(self.store_dir, exist_ok=True)

    def save_feature_payload(self, stage: str, payload: Dict) -> str:
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        filename = f"{stage}-{timestamp}.json"
        path = os.path.join(self.store_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        return path

    def load_latest_payload(self, stage: str) -> Optional[Dict]:
        files = sorted([f for f in os.listdir(self.store_dir) if f.startswith(stage) and f.endswith(".json")])
        if not files:
            return None
        latest = files[-1]
        with open(os.path.join(self.store_dir, latest), "r", encoding="utf-8") as fh:
            return json.load(fh)
