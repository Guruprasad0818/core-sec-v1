#!/usr/bin/env python3
"""CBAD Stage 5 - Shannon entropy analysis for credential detection.

Implements the Shannon entropy formula from CBAD_Stage5_Entropy_SLSA.md
section 3.2 (H(X) = -sum p_b * log2(p_b)) and applies it to source/config
text rather than compiled .class-file byte sections: section 3.3-3.9 of that
document specialize the same entropy math into a bytecode obfuscation/BMES
classifier for compiled artifacts, which is a distinct, heavier-weight
concern (it needs a JVM class-file parser and a trained ML model). This
module targets the credential-detection use case named in the Stage 5 build
brief - the same "high-entropy string detection" role Gitleaks/Trufflehog
play in Stage 1 - implemented as a standalone entropy + known-format engine
that can run as a pre-attestation gate before SBOM/provenance generation.

Detection strategy (mirrors section 3.5's tiered thresholds, adapted to
charset-relative bits/char rather than whole-class-file bits/byte):
  - known-format rules (AWS keys, private key headers, JWTs) are flagged
    regardless of entropy - the format itself is the signal
  - assignment-style rules (`api_key = "..."`, `password: "..."`) gate the
    captured value on entropy relative to its apparent charset, so
    `password = "changeme"` does not fire but `api_key = "kJ8$qzL..."` does
  - a generic unlabeled-token sweep catches high-entropy strings with no
    recognizable variable name

Honest limitation: character-level entropy does not detect "is this English
text" - a long lowercase dictionary phrase can still score below threshold
even though it is a poor password, and a structured-but-random-looking
identifier (e.g. a UUID) can score above threshold without being a secret.
Thresholds should be tuned against a labeled corpus per section 3.5's
guidance before this is trusted as a hard CI gate.

Matched values are never printed in full - findings carry a masked preview
only, since a credential scanner that echoes the credential into its own
report/log defeats the point.

Usage:
  python stage5/entropy_scanner.py --scan-dir path/to/code
  python stage5/entropy_scanner.py --self-test
  python stage5/entropy_scanner.py --scan-dir path/to/code --output findings.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import string
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Sequence, Tuple

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php",
    ".yml", ".yaml", ".json", ".env", ".ini", ".cfg", ".properties", ".sh",
    ".tf", ".txt", ".conf", ".xml",
}

# alphabets used to pick a charset-relative entropy threshold; hex is a
# strict subset of base64's alphabet, so it must be checked first
HEX_CHARSET = set("0123456789abcdefABCDEF")
BASE64_CHARSET = set(string.ascii_letters + string.digits + "+/=")
ENTROPY_THRESHOLDS_BITS_PER_CHAR: Dict[str, float] = {
    "hex": 3.0,       # theoretical max log2(16) = 4.0
    "base64": 4.5,    # theoretical max log2(64) = 6.0
    "generic": 3.5,
}

PLACEHOLDER_VALUES = {
    "changeme", "password", "example", "secret", "your_api_key_here",
    "xxxxxxxx", "00000000", "12345678", "placeholder", "todo", "redacted",
    "insert_key_here", "replace_me", "test", "dummy",
}


# ---------------------------------------------------------------------------
# Entropy core (section 3.2)
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """H(X) = -sum_b p_b * log2(p_b) over the symbols actually present in `data`."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def classify_charset(token: str) -> str:
    chars = set(token)
    if chars <= HEX_CHARSET:
        return "hex"
    if chars <= BASE64_CHARSET:
        return "base64"
    return "generic"


def entropy_threshold_for(token: str) -> float:
    return ENTROPY_THRESHOLDS_BITS_PER_CHAR[classify_charset(token)]


def is_high_entropy(token: str) -> bool:
    return shannon_entropy(token) >= entropy_threshold_for(token)


def _looks_like_placeholder(token: str) -> bool:
    lowered = token.lower()
    if lowered in PLACEHOLDER_VALUES:
        return True
    if len(set(token)) <= 2:  # e.g. "aaaaaaaa", "01010101"
        return True
    if token.isdigit() and (token == token[0] * len(token) or token in ("12345678", "123456789", "0123456789")):
        return True
    return False


def mask_value(token: str) -> str:
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}…{token[-4:]} ({len(token)} chars)"


# ---------------------------------------------------------------------------
# Rule model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KnownFormatRule:
    rule_id: str
    pattern: Pattern[str]
    category: str
    description: str


@dataclass(frozen=True)
class AssignmentRule:
    rule_id: str
    pattern: Pattern[str]
    category: str
    description: str
    capture_group: int = 1


GENERIC_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9+/_\-]{20,}")

KNOWN_FORMAT_RULES: Tuple[KnownFormatRule, ...] = (
    KnownFormatRule("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "cloud_credential", "AWS access key ID literal."),
    KnownFormatRule("private_key_header", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----"), "private_key", "PEM private key block header."),
    KnownFormatRule("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "token", "JSON Web Token literal."),
    KnownFormatRule("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "vcs_credential", "GitHub personal access token literal."),
    KnownFormatRule("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "saas_credential", "Slack API token literal."),
)

ASSIGNMENT_RULES: Tuple[AssignmentRule, ...] = (
    # \w* (not \b) on either side of the keyword so identifiers like
    # "db_password" or "AWS_API_KEY_ID" still match - underscore is a \w
    # character, so a \b boundary would not fire directly before "password"
    # in "db_password".
    AssignmentRule(
        "generic_api_key_assignment",
        re.compile(r"(?i)\w*(api[_-]?key|access[_-]?key)\w*\s*[:=]\s*['\"]([A-Za-z0-9_\-/+=]{12,})['\"]"),
        "generic_credential", "Variable named like an API key assigned a literal value.",
        capture_group=2,
    ),
    AssignmentRule(
        "generic_secret_assignment",
        re.compile(r"(?i)\w*(secret|token|password|passwd|client[_-]?secret)\w*\s*[:=]\s*['\"]([A-Za-z0-9_\-/+=]{8,})['\"]"),
        "generic_credential", "Variable named like a secret/password assigned a literal value.",
        capture_group=2,
    ),
)


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    finding_id: str
    file_path: str
    line_number: int
    rule_id: str
    category: str
    charset: str
    entropy: float
    confidence: str  # high | medium
    masked_value: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _make_finding_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _build_finding(file_label: str, line_number: int, rule_id: str, category: str, token: str, confidence: str) -> SecretFinding:
    return SecretFinding(
        finding_id=_make_finding_id(file_label, str(line_number), rule_id, mask_value(token)),
        file_path=file_label,
        line_number=line_number,
        rule_id=rule_id,
        category=category,
        charset=classify_charset(token),
        entropy=round(shannon_entropy(token), 3),
        confidence=confidence,
        masked_value=mask_value(token),
    )


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_lines(lines: Sequence[str], file_label: str) -> List[SecretFinding]:
    findings: List[SecretFinding] = []

    for line_number, line in enumerate(lines, start=1):
        reported_spans: List[Tuple[int, int]] = []

        for rule in KNOWN_FORMAT_RULES:
            for match in rule.pattern.finditer(line):
                findings.append(_build_finding(file_label, line_number, rule.rule_id, rule.category, match.group(0), "high"))
                reported_spans.append(match.span())

        for rule in ASSIGNMENT_RULES:
            for match in rule.pattern.finditer(line):
                span = match.span(rule.capture_group)
                if any(span[0] >= s and span[1] <= e for s, e in reported_spans):
                    continue  # already captured by a known-format rule above
                token = match.group(rule.capture_group)
                if _looks_like_placeholder(token):
                    continue
                entropy = shannon_entropy(token)
                threshold = entropy_threshold_for(token)
                if entropy < threshold:
                    continue
                confidence = "high" if entropy >= threshold + 0.5 else "medium"
                findings.append(_build_finding(file_label, line_number, rule.rule_id, rule.category, token, confidence))
                reported_spans.append(span)

        for match in GENERIC_TOKEN_PATTERN.finditer(line):
            span = match.span()
            if any(span[0] >= s and span[1] <= e for s, e in reported_spans):
                continue  # already captured by a more specific rule above
            token = match.group(0)
            if _looks_like_placeholder(token):
                continue
            if not is_high_entropy(token):
                continue
            findings.append(_build_finding(file_label, line_number, "generic_high_entropy_token", "unlabeled_high_entropy", token, "medium"))

    return findings


def scan_file(path: Path) -> List[SecretFinding]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return scan_lines(text.splitlines(), str(path))


def scan_directory(root: Path, extensions: Optional[Sequence[str]] = None) -> List[SecretFinding]:
    allowed = set(extensions) if extensions else SCAN_EXTENSIONS
    findings: List[SecretFinding] = []
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in allowed:
            findings.extend(scan_file(path))
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

SELF_TEST_SAMPLE = """\
aws_access_key_id = "AKIAABCDEFGHIJKLMNOP"
-----BEGIN RSA PRIVATE KEY-----
api_key = "kJ8qZpL2vN9xR4wT7yU1mC6bH3dF5gA0"
password = "changeme"
db_password = "12345678"
github_token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"
# just a comment about entropy thresholds, nothing secret here
greeting = "hello world this is a normal sentence"
auth_blob = "Tm90QVNlY3JldEJ1dExvb2tzTGlrZU9uZTEyMzQ1Njc4"
"""


def run_self_test() -> List[SecretFinding]:
    return scan_lines(SELF_TEST_SAMPLE.splitlines(), "<self-test>")


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 5 Shannon entropy credential scanner")
    parser.add_argument("--scan-dir", help="Directory to scan recursively")
    parser.add_argument("--output", help="Optional path to write JSON findings")
    parser.add_argument("--self-test", action="store_true", help="Run against a built-in sample with known secrets and placeholders")
    args = parser.parse_args()

    if not args.scan_dir and not args.self_test:
        parser.error("Provide --scan-dir <path> or --self-test")

    findings = run_self_test() if args.self_test else scan_directory(Path(args.scan_dir))
    payload = [f.to_dict() for f in findings]
    output_text = json.dumps(payload, indent=2)

    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Wrote {len(findings)} findings to {args.output}")
    else:
        print(output_text)
        print(f"\n{len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
