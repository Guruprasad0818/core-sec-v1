"""Stage 4 - Automated Mitigation ("One-Click Fix").

Generates and commits safe, mechanical remediation patches for a narrow,
well-understood class of Semgrep findings: hardcoded secrets rewritten as
environment-variable placeholders. This is deliberately the ONLY category
auto-fixed - most finding types (insecure hashing, deserialization, dynamic
urllib use, etc.) require real code restructuring that can't be done safely
by mechanical find/replace, so those are reported as not-auto-fixable rather
than risking a broken or semantically-wrong edit.

Safety boundaries:
- writes are confined to the repo, excluding server/ and frontend/ (the
  dashboard's own code) - see is_path_allowed().
- a patch is only applied if the target line is a real top-level Python
  assignment (via ast), not e.g. text that merely looks like one while
  sitting inside a triple-quoted string literal.
- refuses to run against a dirty working tree, so it never mixes an
  automated commit with unrelated in-progress local changes.
- commits land on a brand-new branch, never on the branch the caller was
  already on at the time of the request.
"""

from __future__ import annotations

import ast
import difflib
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

import git

from bootstrap import REPO_ROOT

BLOCKED_TOP_LEVEL_DIRS = {"server", "frontend", ".git", ".venv", "node_modules"}

ASSIGNMENT_RE = re.compile(
    r'^(?P<indent>[ \t]*)(?P<name>[A-Za-z_][A-Za-z0-9_]*)'
    r'(?P<annotation>\s*:\s*[A-Za-z_][A-Za-z0-9_.\[\], ]*)?'
    r'\s*=\s*(?P<quote>["\'])(?P<value>(?:[^"\'\\]|\\.)*)(?P=quote)\s*$'
)


def is_path_allowed(file_path: Path) -> bool:
    try:
        rel = file_path.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return False  # outside the repo entirely
    top = rel.parts[0] if rel.parts else ""
    return top not in BLOCKED_TOP_LEVEL_DIRS


def _line_is_real_assignment(source: str, line_number: int) -> bool:
    """True only if `line_number` is the start of a genuine ast.Assign
    statement - guards against mechanically editing a line that merely
    looks like `name = "value"` but is actually inside a triple-quoted
    string literal (editing it there would corrupt the string)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    return any(isinstance(node, ast.Assign) and node.lineno == line_number for node in ast.walk(tree))


def _ensure_import_os(source: str) -> str:
    if re.search(r"(?m)^\s*import os\s*$", source):
        return source
    insert_at = 0
    try:
        tree = ast.parse(source)
        first = tree.body[0] if tree.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            insert_at = first.end_lineno or 0  # insert after the module docstring
    except SyntaxError:
        pass
    lines = source.splitlines(keepends=True)
    lines.insert(insert_at, "import os\n")
    return "".join(lines)


def _fix_hardcoded_secret(source: str, line_number: int) -> Tuple[Optional[str], str]:
    if not _line_is_real_assignment(source, line_number):
        return None, (
            "Target line is not a standalone Python assignment statement - it "
            "may be inside a string literal, f-string, or multi-line construct. "
            "Refusing to auto-edit to avoid corrupting surrounding code."
        )

    lines = source.splitlines(keepends=True)
    if not (1 <= line_number <= len(lines)):
        return None, "Line number is out of range for the current file contents."

    raw = lines[line_number - 1]
    stripped = raw.rstrip("\r\n")
    newline = raw[len(stripped):]
    match = ASSIGNMENT_RE.match(stripped)
    if not match:
        return None, 'Could not recognize a simple `name = "value"` assignment on this line.'

    env_name = re.sub(r"[^A-Za-z0-9_]", "_", match.group("name")).upper()
    annotation = match.group("annotation") or ""
    replacement = f'{match.group("indent")}{match.group("name")}{annotation} = os.environ.get("{env_name}", ""){newline}'
    lines[line_number - 1] = replacement

    patched = _ensure_import_os("".join(lines))
    summary = f'Replaced the hardcoded value assigned to `{match.group("name")}` with os.environ.get("{env_name}", "").'
    return patched, summary


# Rule-id substring -> fix strategy. Only hardcoded-secret detections are
# mechanically safe to rewrite generically; everything else needs a human.
FIX_STRATEGIES: Dict[str, Callable[[str, int], Tuple[Optional[str], str]]] = {
    "secrets.security.detected-": _fix_hardcoded_secret,
}


def _strategy_for_rule(finding_id: str) -> Optional[Callable[[str, int], Tuple[Optional[str], str]]]:
    for marker, strategy in FIX_STRATEGIES.items():
        if marker in finding_id:
            return strategy
    return None


def is_auto_fixable(finding_id: str) -> bool:
    return _strategy_for_rule(finding_id) is not None


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[-40:] or "fix"


def remediate_finding(instance_id: str, findings_by_instance: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    finding = findings_by_instance.get(instance_id)
    if finding is None:
        raise ValueError(f"Unknown finding instance_id: {instance_id}")

    rel_path = finding["file_path"]
    file_path = (REPO_ROOT / rel_path).resolve()
    line_number = finding["line_number"]

    if not is_path_allowed(file_path):
        raise PermissionError(f"Refusing to modify a path outside the allowed sandbox: {rel_path}")
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {rel_path}")

    strategy = _strategy_for_rule(finding["finding_id"])
    if strategy is None:
        return {
            "status": "not_auto_fixable",
            "file_path": rel_path,
            "line_number": line_number,
            "reason": f"No safe automated fix is defined for rule `{finding['finding_id']}` - this category needs manual remediation.",
        }

    original = file_path.read_text(encoding="utf-8")
    patched, summary = strategy(original, line_number)
    if patched is None:
        return {
            "status": "not_auto_fixable",
            "file_path": rel_path,
            "line_number": line_number,
            "reason": summary,
        }

    repo = git.Repo(REPO_ROOT)
    if repo.is_dirty(untracked_files=False):
        return {
            "status": "error",
            "file_path": rel_path,
            "line_number": line_number,
            "reason": "Working tree has uncommitted changes - commit or stash them before requesting an automated remediation.",
        }

    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=rel_path,
            tofile=rel_path,
        )
    )

    branch_name = f"remediate/{_slugify(finding['finding_id'])}-{int(time.time())}"
    commit_message = f"fix: remediate {finding['finding_id']} in {rel_path}:{line_number}\n\n{summary}"

    try:
        new_branch = repo.create_head(branch_name)
        new_branch.checkout()
        file_path.write_text(patched, encoding="utf-8")
        repo.index.add([str(file_path)])
        commit = repo.index.commit(commit_message)
    except Exception as exc:  # noqa: BLE001 - surface any git failure to the caller
        raise RuntimeError(f"Git remediation commit failed: {exc}") from exc

    return {
        "status": "committed",
        "branch": branch_name,
        "commit_hash": commit.hexsha[:8],
        "file_path": rel_path,
        "line_number": line_number,
        "summary": summary,
        "diff": diff,
    }
