#!/usr/bin/env python3
"""CBAD Stage 4 - AI-based false positive reduction layer.

Implements the Claude verification wrapper from
CBAD_Stage4_TaintTracking_MultiLanguage.md SECTION 4: the alert normalizer,
context extractor, prompt builder, Claude client, response parser, and
verification policy engine (section 4.2), consuming TaintFinding objects
produced by sast_engine.py.

Operating modes:
  - if ANTHROPIC_API_KEY is set, findings are verified by Claude using the
    deterministic (temperature=0) prompt in build_prompt() (section 4.4)
  - if the key is absent, the API call fails, or the model response fails
    JSON schema validation, verification falls back to heuristic_verify(),
    a deterministic approximation of the same validation criteria (section
    4.8: "fallback on non-model heuristics if parsing fails")
  - in both modes, apply_policy_overrides() enforces the hard suppression
    rules from section 4.3 *after* the model/heuristic opinion, so a
    confident high-risk unsanitized flow can never be silently suppressed
    just because the model was uncertain

Usage:
  python stage4/claude_verifier.py --self-test
  python stage4/claude_verifier.py --findings findings.json
  python stage4/claude_verifier.py --findings findings.json --output verified.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from sast_engine import RULES, SourceRule, TaintEvent, TaintFinding

DEFAULT_MODEL = "claude-sonnet-4-6"

HIGH_RISK_CATEGORIES = {"sql_injection", "command_injection", "code_injection", "insecure_deserialization"}

VERIFICATION_CHECKLIST: Tuple[str, ...] = (
    "Does the source trace from an untrusted endpoint parameter, environment variable, or other unauthenticated input?",
    "Does the sink execute raw SQL, an OS command, dynamic code evaluation, or another high-risk operation?",
    "Is there a sanitizer, prepared statement, parameterized API, or safe ORM call anywhere on the path?",
    "Is the path feasible on a normal execution path (not dead code or test-only code)?",
)

REMEDIATION_TEMPLATES: Dict[str, Tuple[str, str, str]] = {
    "sql_injection": (
        "parameterized_query",
        "Use a parameterized query or prepared statement instead of string concatenation, "
        "e.g. cursor.execute(query, (param,)) or preparedStatement.setString(1, param).",
        "high",
    ),
    "command_injection": (
        "shell_argument_escape",
        "Pass arguments as a list/array to the process API instead of a shell string, "
        "e.g. subprocess.run([cmd, arg]) or child_process.execFile(cmd, [arg]).",
        "high",
    ),
    "code_injection": (
        "remove_dynamic_eval",
        "Avoid eval/exec/new Function on user-controlled input; use a safe parser or an explicit allow-list dispatch instead.",
        "medium",
    ),
    "path_traversal": (
        "path_normalization",
        "Resolve and normalize the path against a fixed base directory and reject paths that escape it "
        "(e.g. os.path.normpath plus a prefix check, or Paths.get(base).resolve(input).normalize()).",
        "medium",
    ),
    "xss": (
        "output_encoding",
        "Escape or encode the value before rendering, or rely on the template engine's autoescaping mode.",
        "medium",
    ),
    "ssrf": (
        "url_allowlist",
        "Validate the target URL/host against an allow-list before making the outbound request.",
        "medium",
    ),
    "insecure_deserialization": (
        "safe_deserializer",
        "Use a safe loader (e.g. yaml.safe_load) or a schema-validated deserializer instead of pickle.loads/yaml.load.",
        "high",
    ),
    "log_injection": (
        "log_sanitization",
        "Strip newlines/control characters from the value before logging, or use structured logging fields instead of string interpolation.",
        "low",
    ),
}


# ---------------------------------------------------------------------------
# Data model (section 4.5 wrapper contract)
# ---------------------------------------------------------------------------

@dataclass
class CodeContext:
    file_path: str
    snippet: str
    line_window: List[str] = field(default_factory=list)


@dataclass
class VerificationResult:
    finding_id: str
    verified: bool
    false_positive_risk: str  # low | medium | high
    confidence: float
    suppression_reason: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class FixRecommendation:
    rule_id: str
    file_path: str
    line_range: Tuple[int, int]
    suggested_patch: str
    explanation: str
    fix_type: str = "manual_review"
    fix_confidence: str = "low"


# ---------------------------------------------------------------------------
# Context extractor (section 4.2 "context extractor")
# ---------------------------------------------------------------------------

def build_code_context(finding: TaintFinding, file_lines: Optional[Sequence[str]] = None, window: int = 5) -> CodeContext:
    if file_lines:
        lo = max(0, min(finding.source.line_number, finding.sink.line_number) - 1 - window)
        hi = min(len(file_lines), max(finding.source.line_number, finding.sink.line_number) + window)
        snippet_lines = list(file_lines[lo:hi])
    else:
        snippet_lines = [finding.source.line_text, finding.sink.line_text]
    return CodeContext(file_path=finding.file_path, snippet="\n".join(snippet_lines), line_window=snippet_lines)


# ---------------------------------------------------------------------------
# Prompt builder (section 4.4)
# ---------------------------------------------------------------------------

def build_prompt(finding: TaintFinding, context: CodeContext) -> str:
    checklist = "\n".join(f"{i}. {question}" for i, question in enumerate(VERIFICATION_CHECKLIST, start=1))
    return f"""ALERT SUMMARY
tool: cbad-sast-engine
rule_id: {finding.sink.rule_id}
category: {finding.category}
language: {finding.language}
file: {finding.file_path}
source: {finding.source.rule_id} (line {finding.source.line_number})
sink: {finding.sink.rule_id} (line {finding.sink.line_number})
severity: {finding.severity}

CODE CONTEXT
{context.snippet}

VERIFICATION CHECKLIST
{checklist}

RESPONSE FORMAT
Respond with a single JSON object and nothing else, with exactly these keys:
{{"verified": <bool>, "false_positive_risk": "low"|"medium"|"high", "suppression_reason": <string or null>, "confidence": <number 0-1>, "remediation": <string or null>}}
"""


# ---------------------------------------------------------------------------
# Claude client (section 4.2 "Claude client")
# ---------------------------------------------------------------------------

class ClaudeClient:
    """Thin wrapper around the Anthropic SDK. Deterministic by default
    (temperature=0, per section 4.8) and lazily imports `anthropic` so the
    rest of this module works without the dependency installed.
    """

    def __init__(self, model: str = DEFAULT_MODEL, api_key: Optional[str] = None, max_tokens: int = 1024):
        self.model = model
        self.max_tokens = max_tokens
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None

    def available(self) -> bool:
        return bool(self._api_key)

    def complete(self, prompt: str, request_id: str) -> str:
        if not self.available():
            raise RuntimeError("ANTHROPIC_API_KEY is not set; Claude client unavailable")
        if self._client is None:
            import anthropic  # local import: keeps the dependency optional

            self._client = anthropic.Anthropic(api_key=self._api_key)
        response = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in response.content if hasattr(block, "text"))


# ---------------------------------------------------------------------------
# Response parser (section 4.8 schema validation)
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = {"verified", "false_positive_risk", "confidence"}
_RISK_LEVELS = {"low", "medium", "high"}


def parse_model_response(raw_text: str, finding_id: str) -> Optional[VerificationResult]:
    match = re.search(r"\{.*\}", raw_text, re.DOTALL)
    if not match:
        return None
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or not _REQUIRED_KEYS.issubset(payload.keys()):
        return None
    if payload["false_positive_risk"] not in _RISK_LEVELS:
        return None
    try:
        confidence = float(payload["confidence"])
    except (TypeError, ValueError):
        return None
    return VerificationResult(
        finding_id=finding_id,
        verified=bool(payload["verified"]),
        false_positive_risk=payload["false_positive_risk"],
        confidence=max(0.0, min(1.0, confidence)),
        suppression_reason=payload.get("suppression_reason"),
        remediation=payload.get("remediation"),
    )


# ---------------------------------------------------------------------------
# Heuristic fallback verifier (section 4.8 non-model fallback)
# ---------------------------------------------------------------------------

def _lookup_source_rule(finding: TaintFinding) -> Optional[SourceRule]:
    rule_set = RULES.get(finding.language)
    if rule_set is None:
        return None
    for rule in rule_set.sources:
        if rule.rule_id == finding.source.rule_id:
            return rule
    return None


def heuristic_verify(finding: TaintFinding) -> VerificationResult:
    """Deterministic approximation of the section 4.3 validation criteria,
    used whenever the model is unavailable or its response can't be parsed.
    """
    source_rule = _lookup_source_rule(finding)
    trusted_source = bool(source_rule and source_rule.trust == "trusted")
    high_risk = finding.category in HIGH_RISK_CATEGORIES
    no_sanitizer_evidence = finding.sanitizer is None
    feasible = finding.confidence in {"high", "medium"}

    if trusted_source:
        return VerificationResult(
            finding.finding_id, verified=False, false_positive_risk="high", confidence=0.85,
            suppression_reason="Source originates from a trusted configuration constant.",
        )
    if high_risk and no_sanitizer_evidence and feasible:
        return VerificationResult(
            finding.finding_id, verified=True, false_positive_risk="low",
            confidence=0.75 if finding.confidence == "high" else 0.55,
            remediation=REMEDIATION_TEMPLATES.get(finding.category, (None, None, None))[1],
        )
    if not no_sanitizer_evidence:
        return VerificationResult(
            finding.finding_id, verified=False, false_positive_risk="high", confidence=0.7,
            suppression_reason="Sanitizer or parameterized API evidence present on the path.",
        )
    return VerificationResult(
        finding.finding_id, verified=False, false_positive_risk="medium", confidence=0.5,
        suppression_reason="Insufficient evidence of a feasible, unsanitized path.",
    )


# ---------------------------------------------------------------------------
# Verification policy engine (section 4.3 hard suppression rules)
# ---------------------------------------------------------------------------

def apply_policy_overrides(finding: TaintFinding, result: VerificationResult) -> VerificationResult:
    source_rule = _lookup_source_rule(finding)

    # suppress if the taint originates from a trusted configuration constant,
    # regardless of what the model/heuristic concluded
    if source_rule and source_rule.trust == "trusted":
        return VerificationResult(
            result.finding_id, verified=False, false_positive_risk="high", confidence=0.9,
            suppression_reason="Policy override: source is a trusted configuration constant.",
        )

    # do not suppress if the sink is high-risk and the engine found no sanitizer
    # on the path, even if the model/heuristic reported a false-positive
    if finding.category in HIGH_RISK_CATEGORIES and finding.sanitizer is None and finding.confidence == "high":
        if not result.verified and result.false_positive_risk == "high":
            return VerificationResult(
                result.finding_id, verified=True, false_positive_risk="low",
                confidence=max(result.confidence, 0.6), suppression_reason=None,
                remediation=result.remediation or REMEDIATION_TEMPLATES.get(finding.category, (None, None, None))[1],
            )

    return result


# ---------------------------------------------------------------------------
# Auto-fix recommendation (section 4.7)
# ---------------------------------------------------------------------------

def build_fix_recommendation(finding: TaintFinding) -> FixRecommendation:
    fix_type, explanation, fix_confidence = REMEDIATION_TEMPLATES.get(
        finding.category, ("manual_review", "No automated remediation template is available for this category; manual review required.", "low")
    )
    line_range = (min(finding.source.line_number, finding.sink.line_number), max(finding.source.line_number, finding.sink.line_number))
    return FixRecommendation(
        rule_id=finding.sink.rule_id,
        file_path=finding.file_path,
        line_range=line_range,
        suggested_patch=explanation,
        explanation=f"{finding.category} flow from {finding.source.rule_id} (line {finding.source.line_number}) "
        f"to {finding.sink.rule_id} (line {finding.sink.line_number}).",
        fix_type=fix_type,
        fix_confidence=fix_confidence,
    )


# ---------------------------------------------------------------------------
# Claude verifier wrapper (section 4.5 contract: verifyFinding / suggestFix / evaluateBatch)
# ---------------------------------------------------------------------------

class ClaudeVerifier:
    def __init__(self, client: Optional[ClaudeClient] = None, cache: Optional[Dict[str, VerificationResult]] = None):
        self.client = client or ClaudeClient()
        self._cache: Dict[str, VerificationResult] = cache if cache is not None else {}

    def verify_finding(self, finding: TaintFinding, context: Optional[CodeContext] = None) -> VerificationResult:
        if finding.finding_id in self._cache:
            return self._cache[finding.finding_id]

        context = context or build_code_context(finding)
        result = self._verify_with_model_or_fallback(finding, context)
        result = apply_policy_overrides(finding, result)
        self._cache[finding.finding_id] = result
        return result

    def _verify_with_model_or_fallback(self, finding: TaintFinding, context: CodeContext) -> VerificationResult:
        if not self.client.available():
            return heuristic_verify(finding)
        prompt = build_prompt(finding, context)
        try:
            raw_response = self.client.complete(prompt, request_id=finding.finding_id)
        except Exception:
            return heuristic_verify(finding)
        parsed = parse_model_response(raw_response, finding.finding_id)
        if parsed is None:
            return heuristic_verify(finding)
        return parsed

    def suggest_fix(self, finding: TaintFinding, context: Optional[CodeContext] = None) -> FixRecommendation:
        return build_fix_recommendation(finding)

    def evaluate_batch(self, findings: Sequence[TaintFinding]) -> List[VerificationResult]:
        return [self.verify_finding(finding) for finding in findings]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _finding_from_dict(payload: Dict) -> TaintFinding:
    sanitizer = payload.get("sanitizer")
    return TaintFinding(
        finding_id=payload["finding_id"],
        language=payload["language"],
        category=payload["category"],
        file_path=payload["file_path"],
        source=TaintEvent(**payload["source"]),
        sink=TaintEvent(**payload["sink"]),
        sanitizer=TaintEvent(**sanitizer) if sanitizer else None,
        severity=payload["severity"],
        confidence=payload["confidence"],
        tags=tuple(payload["tags"]),
        description=payload["description"],
    )


def load_findings(path: Path) -> List[TaintFinding]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [_finding_from_dict(item) for item in payload]


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 4 Claude false-positive reduction layer")
    parser.add_argument("--findings", help="Path to a JSON findings file produced by sast_engine.py")
    parser.add_argument("--self-test", action="store_true", help="Run against sast_engine's built-in self-test findings")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--output", help="Optional path to write JSON verification results")
    args = parser.parse_args()

    if not args.findings and not args.self_test:
        parser.error("Provide --findings <file> or --self-test")

    if args.self_test:
        from sast_engine import run_self_test

        findings = run_self_test()
    else:
        findings = load_findings(Path(args.findings))

    verifier = ClaudeVerifier(client=ClaudeClient(model=args.model))
    if not verifier.client.available():
        print("[claude_verifier] ANTHROPIC_API_KEY not set - using heuristic fallback verification\n")

    results = []
    for finding in findings:
        verification = verifier.verify_finding(finding)
        entry: Dict[str, object] = {"finding": finding.to_dict(), "verification": asdict(verification)}
        if verification.verified:
            entry["fix_recommendation"] = asdict(verifier.suggest_fix(finding))
        results.append(entry)

    output_text = json.dumps(results, indent=2)
    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Wrote {len(results)} verification results to {args.output}")
    else:
        print(output_text)

    suppressed = sum(1 for r in results if not r["verification"]["verified"])
    print(f"\n{len(results)} findings processed, {suppressed} suppressed, {len(results) - suppressed} verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
