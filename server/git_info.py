"""Live git-log telemetry for Stage 1, read directly from this repository's
.git history via GitPython - independent of the persisted pre-commit/pre-push
hook artifacts that dashboard/core/ingestion.py's load_stage1() reads (that
function stays untouched so the Streamlit dashboard's Stage 1 is unaffected).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import git

from bootstrap import REPO_ROOT


def get_live_git_info(repo_path: Path = REPO_ROOT, max_commits: int = 5) -> Dict[str, Any]:
    # search_parent_directories guards against being invoked from a cwd one or
    # more levels below the repo root (e.g. `cd server && uvicorn main:app`).
    repo = git.Repo(repo_path, search_parent_directories=True)

    try:
        active_branch = repo.active_branch.name
    except TypeError:
        # Detached HEAD (no named branch) - fall back to the short commit hash.
        active_branch = f"detached@{repo.head.commit.hexsha[:8]}"

    commits = []
    total_insertions = 0
    total_deletions = 0
    for commit in repo.iter_commits(max_count=max_commits):
        stats = commit.stats.total
        insertions = stats.get("insertions", 0)
        deletions = stats.get("deletions", 0)
        total_insertions += insertions
        total_deletions += deletions
        commits.append(
            {
                "hash": commit.hexsha[:8],
                "author": commit.author.name,
                "message": commit.message.strip().splitlines()[0] if commit.message else "",
                "timestamp": commit.committed_datetime.isoformat(),
                "insertions": insertions,
                "deletions": deletions,
                "files_changed": stats.get("files", 0),
                # Per-file paths (not just the count) - Stage 3's risk engine
                # correlates these against Semgrep finding locations.
                "changed_files": list(commit.stats.files.keys()),
            }
        )

    return {
        "source": "live_git_log",
        "repo_path": str(repo_path),
        "active_branch": active_branch,
        "is_dirty": repo.is_dirty(untracked_files=True),
        "commits": commits,
        "total_insertions": total_insertions,
        "total_deletions": total_deletions,
    }
