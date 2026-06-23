"""
Simple data seeder for ephemeral sandbox environments.
- Writes a small SQLite demo DB with a canary user
- Accepts a YAML/JSON manifest in future extensions
"""
import os
import sqlite3
import uuid
import json
from typing import Tuple

BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "sandbox_demo.db")


def seed_demo() -> Tuple[str, str]:
    """Create a demo sqlite DB and insert a canary user.
    Returns (db_path, canary_email)
    """
    canary = f"canary-{uuid.uuid4().hex[:8]}@example.com"
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, name TEXT);")
    cur.execute("INSERT INTO users (email, name) VALUES (?, ?)", (canary, "Canary User"))
    conn.commit()
    conn.close()
    return DB_PATH, canary


if __name__ == "__main__":
    db, email = seed_demo()
    print(json.dumps({"db": db, "canary": email}))
