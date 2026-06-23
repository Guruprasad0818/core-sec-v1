import os
import re
import subprocess
import hashlib
import json
import math
import statistics
import socket
import getpass
import datetime
from typing import Dict, List, Optional, Tuple

LANGUAGE_EXTENSIONS = {
    "py": "python",
    "js": "javascript",
    "ts": "typescript",
    "go": "go",
    "java": "java",
    "kt": "kotlin",
    "rs": "rust",
    "cpp": "cpp",
    "c": "c",
    "cs": "csharp",
    "sh": "shell",
    "yaml": "yaml",
    "yml": "yaml",
    "json": "json",
    "rb": "ruby",
    "php": "php",
    "swift": "swift",
    "scala": "scala",
    "md": "markdown",
}

DEPENDENCY_MANIFESTS = {
    "package.json",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "Cargo.toml",
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}

SECURITY_PATH_PATTERNS = ["security", "secrets", "auth", "oauth", "jwt", "ssh", "tls", "cert"]
TEST_PATH_PATTERNS = ["test", "tests", "spec", "__tests__", "integration"]
DOCUMENTATION_EXT = {"md", "rst", "txt", "adoc"}
LICENSE_FILES = {"LICENSE", "LICENSE.txt", "COPYING"}
CODEGEN_PATTERNS = ["generated", "gen", "build/generated", "dist", "target"]


class CBADFeatureCollector:
    def __init__(self, repo_root: Optional[str] = None):
        self.repo_root = repo_root or self.get_repo_root()
        self.now = datetime.datetime.utcnow()

    def get_repo_root(self) -> str:
        return self.run_git(["rev-parse", "--show-toplevel"]).strip()

    def run_git(self, args: List[str]) -> str:
        result = subprocess.check_output(["git"] + args, cwd=self.repo_root, text=True, stderr=subprocess.DEVNULL)
        return result

    def get_staged_files(self) -> List[str]:
        output = self.run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"])
        return [line.strip() for line in output.splitlines() if line.strip()]

    def get_staged_diff_numstat(self) -> List[Tuple[Optional[int], Optional[int], str]]:
        output = self.run_git(["diff", "--cached", "--numstat", "--diff-filter=ACMRTUXB"])
        rows = []
        for line in output.splitlines():
            parts = line.split('\t')
            if len(parts) < 3:
                continue
            added = None if parts[0] == "-" else int(parts[0])
            deleted = None if parts[1] == "-" else int(parts[1])
            rows.append((added, deleted, parts[2]))
        return rows

    def get_staged_name_status(self) -> List[Tuple[str, str]]:
        output = self.run_git(["diff", "--cached", "--name-status", "--diff-filter=ACMDRUXB"])
        entries = []
        for line in output.splitlines():
            parts = line.split('\t')
            if len(parts) >= 2:
                status = parts[0]
                path = parts[-1]
                entries.append((status, path))
        return entries

    def get_diff_summary(self) -> str:
        return self.run_git(["diff", "--cached", "--summary", "--diff-filter=ACMRTUXB"])

    def get_commit_dates(self, interval_days: int, since_days: Optional[int] = None) -> List[int]:
        if since_days is None:
            since = f"{interval_days} days ago"
            output = self.run_git(["log", f"--since={since}", "--pretty=%ct"])
        else:
            since = f"{since_days} days ago"
            until = f"{interval_days} days ago"
            output = self.run_git(["log", f"--since={since}", f"--until={until}", "--pretty=%ct"])
        return [int(line.strip()) for line in output.splitlines() if line.strip().isdigit()]

    def get_last_commit_timestamp(self) -> Optional[int]:
        try:
            output = self.run_git(["log", "-1", "--pretty=%ct"]).strip()
            return int(output) if output else None
        except subprocess.CalledProcessError:
            return None

    def get_commit_message(self) -> str:
        try:
            return self.run_git(["log", "-1", "--pretty=%B"]).strip()
        except subprocess.CalledProcessError:
            return ""

    def get_branch_name(self) -> str:
        return self.run_git(["rev-parse", "--abbrev-ref", "HEAD"]).strip()

    def get_default_branch(self) -> str:
        try:
            output = self.run_git(["symbolic-ref", "refs/remotes/origin/HEAD"]).strip()
            return os.path.basename(output)
        except subprocess.CalledProcessError:
            return "main"

    def get_branch_distance(self, branch: str, default_branch: str) -> int:
        try:
            output = self.run_git(["rev-list", "--left-right", "--count", f"{default_branch}...{branch}"])
            left, right = output.strip().split()
            return int(right)
        except subprocess.CalledProcessError:
            return 0

    def get_repo_size_mb(self) -> float:
        try:
            output = self.run_git(["count-objects", "-vH"]).splitlines()
            for line in output:
                if line.startswith("size-pack:"):
                    value = line.split(":", 1)[1].strip()
                    if value.endswith("MiB"):
                        return float(value[:-3].strip())
                    if value.endswith("KiB"):
                        return float(value[:-3].strip()) / 1024.0
            return 0.0
        except subprocess.CalledProcessError:
            return 0.0

    def get_remote_url(self) -> str:
        try:
            return self.run_git(["remote", "get-url", "origin"]).strip()
        except subprocess.CalledProcessError:
            return ""

    def compute_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counts = {}
        for ch in text:
            counts[ch] = counts.get(ch, 0) + 1
        length = len(text)
        entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
        return entropy

    def parse_language(self, path: str) -> Optional[str]:
        ext = os.path.splitext(path)[1].lstrip(".").lower()
        return LANGUAGE_EXTENSIONS.get(ext)

    def extract_comment_ratio(self, added_lines: List[str], ext: Optional[str]) -> float:
        if not added_lines:
            return 0.0
        comment_count = 0
        code_count = 0
        for line in added_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if ext in {"python", "ruby", "shell", "javascript", "typescript", "java", "go", "c", "cpp", "csharp"}:
                if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*") or stripped.endswith("*/"):
                    comment_count += 1
                else:
                    code_count += 1
            else:
                if stripped.startswith("#") or stripped.startswith("//"):
                    comment_count += 1
                else:
                    code_count += 1
        total = comment_count + code_count
        return float(comment_count) / float(total) if total > 0 else 0.0

    def read_staged_file(self, path: str) -> str:
        try:
            return self.run_git(["show", f":{path}"])
        except subprocess.CalledProcessError:
            return ""

    def count_syntax_errors(self, path: str, language: Optional[str]) -> int:
        if language != "python" or not path.endswith(".py"):
            return 0
        content = self.read_staged_file(path)
        if not content:
            return 0
        try:
            compile(content, path, "exec")
            return 0
        except SyntaxError:
            return 1
        except Exception:
            return 0

    def collect_features(self, stage_name: str, push_refs: Optional[List[Tuple[str, str, str]]] = None) -> Dict:
        staged_files = self.get_staged_files()
        numstat_rows = self.get_staged_diff_numstat()
        name_status = self.get_staged_name_status()
        diff_summary = self.get_diff_summary()

        now_ts = int(self.now.timestamp())
        last_commit_ts = self.get_last_commit_timestamp() or now_ts
        commit_count_7d = len(self.get_commit_dates(7))
        commit_count_30d = len(self.get_commit_dates(30))
        commit_count_prev_30d = len(self.get_commit_dates(37, since_days=30))
        file_exts = [os.path.splitext(path)[1].lstrip(".").lower() for path in staged_files]
        langs = [self.parse_language(path) for path in staged_files if self.parse_language(path)]
        language_counts = {lang: langs.count(lang) for lang in set(langs)}
        path_depths = [len(path.split("/")) for path in staged_files if path]
        added_lines = [added for added, deleted, path in numstat_rows if added is not None]
        deleted_lines = [deleted for added, deleted, path in numstat_rows if deleted is not None]
        file_change_size = [((added or 0) + (deleted or 0)) for added, deleted, _ in numstat_rows]

        branch_name = self.get_branch_name()
        default_branch = self.get_default_branch()
        branch_distance = self.get_branch_distance(branch_name, default_branch)
        merge_base_distance = branch_distance
        repo_size_mb = self.get_repo_size_mb()
        remote = self.get_remote_url()
        issue_pattern = re.compile(r"(#\d+|[A-Za-z]+-\d+)")
        issue_links = len(issue_pattern.findall(self.get_commit_message()))

        test_file_count = sum(1 for path in staged_files if any(pattern in path.lower() for pattern in TEST_PATH_PATTERNS))
        security_file_count = sum(1 for path in staged_files if any(part in path.lower() for part in SECURITY_PATH_PATTERNS))
        docs_file_count = sum(1 for path in staged_files if path.split(".")[-1].lower() in DOCUMENTATION_EXT)
        dep_manifest_count = sum(1 for path in staged_files if os.path.basename(path) in DEPENDENCY_MANIFESTS)
        license_file_count = sum(1 for path in staged_files if os.path.basename(path) in LICENSE_FILES)
        hidden_file_count = sum(1 for path in staged_files if os.path.basename(path).startswith("."))
        codegen_file_count = sum(1 for path in staged_files if any(pat in path.lower() for pat in CODEGEN_PATTERNS))

        def safe_div(n, d):
            return float(n) / float(d) if d else 0.0

        commit_timestamps = self.get_commit_dates(30)
        weekend_commits = sum(1 for ts in commit_timestamps if datetime.datetime.utcfromtimestamp(ts).weekday() >= 5)
        work_hours = sum(1 for ts in commit_timestamps if 9 <= datetime.datetime.utcfromtimestamp(ts).hour < 18)
        commit_hours = len(commit_timestamps)

        commit_message = self.get_commit_message()

        feature_payload = {
            "stage": stage_name,
            "timestamp_utc": now_ts,
            "commit_timestamp_utc": now_ts,
            "commit_day_of_week": self.now.weekday(),
            "commit_hour_local": int(self.now.astimezone().hour),
            "commit_minute_bucket": (self.now.minute // 5) * 5,
            "time_since_last_commit_seconds": now_ts - last_commit_ts,
            "time_since_last_push_seconds": None,
            "commit_cadence_per_week": safe_div(commit_count_7d, 7),
            "commit_cadence_percentile": 0.5,
            "work_hour_ratio": safe_div(work_hours, commit_hours),
            "weekend_commit_flag": self.now.weekday() >= 5,
            "holiday_commit_flag": False,
            "late_night_commit_flag": self.now.hour < 7 or self.now.hour > 20,
            "branch_age_days": 0,
            "commit_age_since_repo_creation_days": 0,
            "burst_commit_count_last_24h": len(self.get_commit_dates(1)),
            "files_changed_count": len(staged_files),
            "lines_added": sum(added for added in added_lines),
            "lines_deleted": sum(deleted for deleted in deleted_lines),
            "net_line_delta": sum(added for added in added_lines) - sum(deleted for deleted in deleted_lines),
            "churn_ratio": safe_div(sum(added for added in added_lines) - sum(deleted for deleted in deleted_lines), sum((added or 0) + (deleted or 0) for added, deleted, _ in numstat_rows)),
            "binary_file_change_count": sum(1 for added, deleted, path in numstat_rows if added is None or deleted is None),
            "executable_file_change_count": sum(1 for line in diff_summary.splitlines() if "mode change" in line and "100755" in line),
            "renamed_file_count": sum(1 for status, _ in name_status if status.startswith("R")),
            "new_file_count": sum(1 for status, _ in name_status if status == "A"),
            "deleted_file_count": sum(1 for status, _ in name_status if status == "D"),
            "changed_file_ext_count": len(set(file_exts)),
            "top_filetype_change_ratio": max([safe_div(list(file_exts).count(ext), len(file_exts)) for ext in set(file_exts)] or [0.0]),
            "average_file_change_size": safe_div(sum(file_change_size), len(file_change_size)),
            "max_file_change_size": max(file_change_size or [0]),
            "cyclomatic_complexity_delta": sum(self._estimate_cyclomatic_complexity_delta(path) for _, _, path in numstat_rows),
            "code_entropy_delta": sum(self.compute_entropy(self.read_staged_file(path)) for _, _, path in numstat_rows),
            "TODO_FIXME_comment_delta": sum(1 for _, _, path in numstat_rows if self._path_contains_comment_keyword(path)),
            "comment_to_code_ratio_delta": safe_div(sum(self.extract_comment_ratio(self._collect_added_diff_lines(path), self.parse_language(path)) for _, _, path in numstat_rows), max(len(numstat_rows), 1)),
            "test_file_change_ratio": safe_div(test_file_count, len(staged_files)),
            "src_to_test_change_ratio": safe_div(len(staged_files) - test_file_count, test_file_count),
            "patch_hunk_count": self._count_hunks(),
            "patch_hunk_size_variance": self._hunk_size_variance(),
            "documentation_file_change_count": docs_file_count,
            "security_file_change_count": security_file_count,
            "dependency_manifest_delta": dep_manifest_count,
            "license_file_change_flag": license_file_count > 0,
            "path_depth_change_mean": safe_div(sum(path_depths), len(path_depths)),
            "code_style_violation_count": 0,
            "formatting_diff_ratio": 0.0,
            "branch_protection_state": None,
            "push_protection_state": None,
            "branch_distance_from_default": branch_distance,
            "merge_base_distance_commits": merge_base_distance,
            "repo_commit_rate_change": safe_div(commit_count_7d, commit_count_prev_30d or 1),
            "repo_issue_link_density": issue_links,
            "open_pr_count": None,
            "active_reviewer_count": None,
            "repo_size_mb": repo_size_mb,
            "source_to_test_ratio": safe_div(len(staged_files) - test_file_count, test_file_count),
            "repo_language_mix_entropy": self.compute_entropy(json.dumps(language_counts)),
            "recent_security_scan_findings_count": None,
            "recent_build_failure_rate": None,
            "package_dependency_delta_count": dep_manifest_count,
            "submodule_change_flag": any(path.endswith(".gitmodules") or ".gitmodules" in path for path in staged_files),
            "monorepo_topology_flag": len(set(p.split("/")[0] for p in staged_files)) > 1,
            "sensitive_path_change_flag": any(any(part in path.lower() for part in SECURITY_PATH_PATTERNS) for path in staged_files),
            "hidden_file_change_flag": hidden_file_count > 0,
            "developer_id_hash": hashlib.sha256(self.get_git_user_email().encode("utf-8")).hexdigest(),
            "author_email_domain": self.get_git_user_email().split("@")[-1] if "@" in self.get_git_user_email() else "",
            "author_username_stability_score": 1.0,
            "device_fingerprint_hash": hashlib.sha256(f"{getpass.getuser()}@{socket.gethostname()}".encode("utf-8")).hexdigest(),
            "git_client_version": self.get_git_version(),
            "commit_authoring_latency_seconds": now_ts - last_commit_ts,
            "author_experience_days": safe_div(now_ts - self._get_first_commit_timestamp(), 86400.0),
            "developer_role_vector": None,
            "prior_anomaly_count": 0,
            "prior_anomaly_rate": 0.0,
            "commit_size_vs_baseline_zscore": 0.0,
            "developer_commit_distribution_entropy": self._compute_time_entropy(commit_timestamps),
            "author_pairing_signal": 1 if "Co-authored-by:" in commit_message else 0,
            "author_change_of_significant_files": any(p in path.lower() for path in staged_files for p in ["README", "docs", "security", "infra"]),
            "identity_drift_score": 0.0,
            "timezone_drift_flag": False,
            "author_reviewer_delta": None,
            "prior_failed_build_ratio": 0.0,
            "approved_merge_count_last_30d": None,
            "primary_language": max(language_counts, key=language_counts.get) if language_counts else None,
            "file_language_mix_ratio": safe_div(max(language_counts.values()) if language_counts else 0, len(staged_files)),
            "new_language_introduction_flag": self._detect_new_language(file_exts),
            "syntax_error_count": sum(self.count_syntax_errors(path, self.parse_language(path)) for path in staged_files),
            "linter_violation_delta": 0,
            "language_specific_security_flag": any(lang in {"python", "javascript", "java", "go", "ruby"} for lang in language_counts),
            "language_feature_usage_vector": language_counts,
            "language_dependency_risk_score": 0.0,
            "language_typing_intensity_change": 0.0,
            "language_linted_files_ratio": 1.0 if os.path.exists(os.path.join(self.repo_root, ".pre-commit-config.yaml")) else 0.0,
            "devtool_signature_hash": hashlib.sha256(self.get_git_version().encode("utf-8")).hexdigest(),
            "pre_commit_toolchain_used_flag": os.path.exists(os.path.join(self.repo_root, ".pre-commit-config.yaml")),
            "formatter_used_flag": os.path.exists(os.path.join(self.repo_root, ".prettierrc")) or os.path.exists(os.path.join(self.repo_root, "pyproject.toml")),
            "ci_skipped_flag": bool(re.search(r"\[ci skip\]|\[skip ci\]", commit_message, re.IGNORECASE)),
            "hook_bypass_flag": bool(os.environ.get("SKIP", "")) or bool(os.environ.get("HUSKY_SKIP_HOOKS", "")),
            "git_commit_template_used_flag": bool(self.get_git_config("commit.template")),
            "git_user_config_changes_flag": any(path.endswith(".git/config") for path in staged_files),
            "local_config_changes_flag": any(path.startswith(".cbad") or path.startswith(".git") for path in staged_files),
            "build_tool_changes_flag": any(path.endswith(ext) for path in staged_files for ext in ["build.gradle", "build.gradle.kts", "pom.xml", "Makefile"]),
            "security_tooling_changes_flag": any(path.lower().endswith(name) for path in staged_files for name in ["owasp", "semgrep", "bandit", "trivy", "snyk", ".eslintrc", ".flake8"]),
            "git_remote_endpoint_type": self._parse_remote_endpoint_type(remote),
            "ssh_key_type": None,
            "git_push_transport": self._parse_push_transport(remote),
            "codegen_file_change_flag": codegen_file_count > 0,
            "package_manager_lockfile_change_flag": any(path.endswith(name) for path in staged_files for name in ["package-lock.json", "yarn.lock", "go.sum", "Pipfile.lock", "Gemfile.lock", "Cargo.lock"]),
            "push_refs": push_refs,
        }

        return feature_payload

    def get_git_user_email(self) -> str:
        try:
            return self.run_git(["config", "user.email"]).strip().lower()
        except subprocess.CalledProcessError:
            return "unknown@example.com"

    def get_git_version(self) -> str:
        try:
            output = subprocess.check_output(["git", "--version"], text=True).strip()
            return output
        except subprocess.CalledProcessError:
            return "git unknown"

    def get_git_config(self, key: str) -> Optional[str]:
        try:
            return self.run_git(["config", "--get", key]).strip()
        except subprocess.CalledProcessError:
            return None

    def _estimate_cyclomatic_complexity_delta(self, path: str) -> int:
        content = self.read_staged_file(path).lower()
        return sum(content.count(keyword) for keyword in [" if ", " for ", " while ", " case ", " catch ", " && ", " || "])

    def _path_contains_comment_keyword(self, path: str) -> bool:
        content = self.read_staged_file(path).lower()
        return "todo" in content or "fixme" in content

    def _collect_added_diff_lines(self, path: str) -> List[str]:
        output = self.run_git(["diff", "--cached", "--unified=0", "--", path])
        lines = []
        for line in output.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                lines.append(line[1:])
        return lines

    def _count_hunks(self) -> int:
        output = self.run_git(["diff", "--cached", "--unified=0"])
        return output.count("@@")

    def _hunk_size_variance(self) -> float:
        output = self.run_git(["diff", "--cached", "--unified=0"])
        sizes = []
        for line in output.splitlines():
            if line.startswith("@@"):
                parts = line.split("@@")
                if len(parts) > 1:
                    match = re.search(r"\+(\d+)(?:,(\d+))?", parts[1])
                    if match:
                        count = int(match.group(2) or "1")
                        sizes.append(count)
        return statistics.pvariance(sizes) if len(sizes) > 1 else 0.0

    def _get_first_commit_timestamp(self) -> int:
        try:
            output = self.run_git(["log", "--reverse", "--pretty=%ct"]).splitlines()
            return int(output[0]) if output else int(self.now.timestamp())
        except (subprocess.CalledProcessError, ValueError):
            return int(self.now.timestamp())

    def _compute_time_entropy(self, timestamps: List[int]) -> float:
        if not timestamps:
            return 0.0
        hours = [datetime.datetime.utcfromtimestamp(ts).hour for ts in timestamps]
        counts = {h: hours.count(h) for h in set(hours)}
        return self.compute_entropy(json.dumps(counts))

    def _detect_new_language(self, file_exts: List[str]) -> bool:
        try:
            output = self.run_git(["ls-files"]).splitlines()
            known_exts = {os.path.splitext(path)[1].lstrip(".").lower() for path in output if path}
            return any(ext not in known_exts for ext in file_exts if ext)
        except subprocess.CalledProcessError:
            return False

    def _parse_remote_endpoint_type(self, url: str) -> Optional[str]:
        if url.startswith("ssh://") or "@" in url:
            return "ssh"
        if url.startswith("http://") or url.startswith("https://"):
            return "https"
        return None

    def _parse_push_transport(self, url: str) -> Optional[str]:
        if url.startswith("ssh://") or "@" in url:
            return "ssh"
        if url.startswith("http://") or url.startswith("https://"):
            return "https"
        return None
