#!/usr/bin/env python3
"""CBAD Stage 8 - LLM attack planner and simulated DAST execution harness.

Implements CBAD_Stage8_DAST_InterfaceDiscovery.md SECTION 2 ("LLM Attack
Planner & Logical Payloads"): an LLM planner constrained to produce
abstract, non-executable JSON test plans (2.3/2.4), a plan validator that
rejects code-like tokens and concrete exploit strings (2.6), a placeholder
resolver that refuses to invent values for unregistered placeholders
(2.7), and an execution harness that only ever sends benign, resolved
placeholder values to an explicitly authorized sandbox target.

Safety boundaries enforced by this module (section 2.1's "must be enforced
by orchestration"), not just described:
  - generate_plan() never returns an unvalidated plan to the caller; an
    invalid plan is reported via ValidationResult and the harness will
    refuse to execute it
  - PlaceholderResolver.resolve() raises if a placeholder has no operator-
    registered synthetic value - it never fabricates a credential or ID
  - ExecutionHarness.__init__ raises unless SandboxAuthorization.confirmed
    is True; there is no path to executing against an unconfirmed target
  - the harness only issues read-only, idempotent HTTP requests (GET/HEAD)
    by default; mutating verbs require an explicit, separate opt-in
  - "execute simulated DAST payloads" means resolved placeholder values
    (test IDs/tokens) substituted into otherwise-normal API calls to
    observe authorization behavior (IDOR-style probing) - never SQLi/XSS/
    command-injection strings. The plan validator actively rejects those.

Usage:
  python stage8/llm_attack_planner.py self-test
  python stage8/llm_attack_planner.py plan --spec graph.json --operation-id getOrderById --risk idor --output plan.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from interface_ingestor import SELF_TEST_SPEC, APIGraph, Operation, SpecIngestor, build_sample_request

DEFAULT_MODEL = "claude-sonnet-4-6"
SAFE_HTTP_METHODS = ("GET", "HEAD")

RISK_CATEGORIES = ("idor", "auth_bypass", "race_condition", "param_manipulation")
ACTION_TYPES = ("ModifyParam", "Replay", "RaceAttempt", "AuthElevation", "Sequence")
SAFETY_LEVELS = ("low", "medium", "high")

SYSTEM_PROMPT = (
    "You are a defensive testing assistant. When asked to generate adversarial test plans, "
    "output ONLY a JSON structure describing goals, abstract actions, and placeholders. "
    "DO NOT include executable code, specific exploit strings, or step-by-step commands. "
    "Each action must be described at a high level (verb + intent) and include a "
    "`placeholders` array for values. Example output schema: "
    '{"goal":..., "preconditions":..., "actions":[{"type":...,"description":...,"placeholders":[...]}], "risk_level":...}.'
)


# ---------------------------------------------------------------------------
# Plan data model (section 2.4)
# ---------------------------------------------------------------------------

@dataclass
class AbstractAction:
    id: str
    type: str
    description: str
    placeholders: List[str]
    safety_level: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPlan:
    goal: str
    preconditions: List[str]
    actions: List[AbstractAction]
    evidence_requirements: List[str]
    risk_level: str

    def to_dict(self) -> Dict[str, Any]:
        return {**asdict(self), "actions": [a.to_dict() for a in self.actions]}


@dataclass
class ValidationResult:
    valid: bool
    schema_errors: List[str] = field(default_factory=list)
    forbidden_findings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Plan validator (section 2.6)
# ---------------------------------------------------------------------------

PLACEHOLDER_PATTERN = re.compile(r"^<[A-Z0-9_]+>$")

FORBIDDEN_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"`[^`]*`"),                                   # backtick code/shell snippets
    re.compile(r"\beval\s*\("),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\b(SELECT|UNION|DROP|INSERT|DELETE)\b.{0,40}\b(FROM|TABLE|WHERE|INTO)\b", re.IGNORECASE),
    re.compile(r"\b(curl|wget)\b", re.IGNORECASE),
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"https?://"),                                  # concrete URLs - section 2.6: "no exact HTTP lines"
    re.compile(r"\b(rm\s+-rf|nc\s+-e|/bin/sh|/bin/bash)\b"),
    re.compile(r"\.\./\.\."),                                   # path traversal payload
    re.compile(r"' OR '1'='1|\bOR 1=1\b", re.IGNORECASE),       # classic SQLi literal
)


def contains_forbidden_tokens(text: str) -> List[str]:
    return [pattern.pattern for pattern in FORBIDDEN_PATTERNS if pattern.search(text)]


def validate_plan_schema(plan: AttackPlan) -> List[str]:
    errors: List[str] = []
    if not plan.goal:
        errors.append("goal is required")
    if plan.risk_level not in SAFETY_LEVELS:
        errors.append(f"risk_level must be one of {SAFETY_LEVELS}, got {plan.risk_level!r}")
    if not plan.actions:
        errors.append("plan must contain at least one action")
    for action in plan.actions:
        if action.type not in ACTION_TYPES:
            errors.append(f"action {action.id}: type must be one of {ACTION_TYPES}, got {action.type!r}")
        if action.safety_level not in SAFETY_LEVELS:
            errors.append(f"action {action.id}: safety_level must be one of {SAFETY_LEVELS}, got {action.safety_level!r}")
        if not action.description:
            errors.append(f"action {action.id}: description is required")
    return errors


class PlanValidator:
    def validate(self, plan: AttackPlan) -> ValidationResult:
        schema_errors = validate_plan_schema(plan)
        forbidden: List[str] = []

        for action in plan.actions:
            hits = contains_forbidden_tokens(action.description)
            forbidden.extend(f"action {action.id} description matched forbidden pattern: {h}" for h in hits)
            for placeholder in action.placeholders:
                if not PLACEHOLDER_PATTERN.match(placeholder):
                    forbidden.append(f"action {action.id}: '{placeholder}' is not a placeholder token (expected <UPPER_SNAKE_CASE>)")

        return ValidationResult(valid=not (schema_errors or forbidden), schema_errors=schema_errors, forbidden_findings=forbidden)


# ---------------------------------------------------------------------------
# LLM client (mirrors stage4's claude_verifier.py pattern: optional, lazy import)
# ---------------------------------------------------------------------------

class ClaudeClient:
    def __init__(self, model: str = DEFAULT_MODEL, api_key: Optional[str] = None, max_tokens: int = 1024):
        self.model = model
        self.max_tokens = max_tokens
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None

    def available(self) -> bool:
        return bool(self._api_key)

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        if not self.available():
            raise RuntimeError("ANTHROPIC_API_KEY is not set; Claude client unavailable")
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self._api_key)
        response = self._client.messages.create(
            model=self.model, max_tokens=self.max_tokens, temperature=0,
            system=system_prompt, messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(block.text for block in response.content if hasattr(block, "text"))


def build_user_prompt(operation: Operation, risk_category: str) -> str:
    return (
        f"Generate a defensive test plan that attempts to find {risk_category.replace('_', ' ')} issues for the "
        f"`{operation.method} {operation.path_template}` endpoint; do not include exploit strings or runnable "
        "payloads. Use placeholders for user identities and request headers. Output JSON only."
    )


def parse_plan_json(raw_text: str) -> Optional[AttackPlan]:
    match = re.search(r"\{.*\}", raw_text, re.DOTALL)
    if not match:
        return None
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    try:
        actions = [AbstractAction(**a) for a in payload["actions"]]
        return AttackPlan(
            goal=payload["goal"], preconditions=list(payload.get("preconditions", [])),
            actions=actions, evidence_requirements=list(payload.get("evidence_requirements", [])),
            risk_level=payload.get("risk_level", "medium"),
        )
    except (KeyError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Heuristic fallback plans (section 2.5's example, templated per risk category)
# ---------------------------------------------------------------------------

def heuristic_plan(operation: Operation, risk_category: str) -> AttackPlan:
    endpoint = f"{operation.method} {operation.path_template}"
    builders = {
        "idor": lambda: AttackPlan(
            goal=f"Authorization check for {endpoint}",
            preconditions=["Authenticated as user A", "Resource exists and belongs to user B"],
            actions=[
                AbstractAction("a1", "ModifyParam", "Submit a request for a resource ID belonging to another user to see if access is denied", ["<OTHER_USER_ID>"], "medium"),
                AbstractAction("a2", "Sequence", "Authenticate as user A then call the endpoint with the other user's ID while observing response codes and headers", ["<OTHER_USER_ID>", "<AUTH_TOKEN_A>"], "medium"),
            ],
            evidence_requirements=["HTTP status code", "response body size", "authorization header presence"],
            risk_level="medium",
        ),
        "auth_bypass": lambda: AttackPlan(
            goal=f"Authentication enforcement check for {endpoint}",
            preconditions=["No valid session token available"],
            actions=[
                AbstractAction("a1", "ModifyParam", "Call the endpoint with an expired or malformed session token to confirm it is rejected", ["<EXPIRED_TOKEN>"], "medium"),
                AbstractAction("a2", "AuthElevation", "Call the endpoint as a low-privilege role and confirm elevated actions are denied", ["<LOW_PRIV_TOKEN>"], "high"),
            ],
            evidence_requirements=["HTTP status code", "WWW-Authenticate header", "error response body"],
            risk_level="high",
        ),
        "race_condition": lambda: AttackPlan(
            goal=f"Time-of-check/time-of-use race check for {endpoint}",
            preconditions=["A resource with a single-use or limited-quantity constraint exists"],
            actions=[
                AbstractAction("a1", "RaceAttempt", "Issue two concurrent requests against the same resource constraint and observe whether both are accepted", ["<TEST_RESOURCE_ID>", "<AUTH_TOKEN_A>"], "high"),
            ],
            evidence_requirements=["HTTP status code for each concurrent request", "final resource state"],
            risk_level="high",
        ),
        "param_manipulation": lambda: AttackPlan(
            goal=f"Parameter trust boundary check for {endpoint}",
            preconditions=["Authenticated as a standard user"],
            actions=[
                AbstractAction("a1", "ModifyParam", "Submit an out-of-range or unexpected-type value for a numeric/enum parameter and observe handling", ["<OUT_OF_RANGE_VALUE>"], "low"),
                AbstractAction("a2", "Replay", "Replay a previously observed request with one field substituted from a different account context", ["<OTHER_ACCOUNT_FIELD>"], "medium"),
            ],
            evidence_requirements=["HTTP status code", "response schema conformance"],
            risk_level="medium",
        ),
    }
    builder = builders.get(risk_category, builders["idor"])
    return builder()


# ---------------------------------------------------------------------------
# LLM attack planner orchestration
# ---------------------------------------------------------------------------

class LLMAttackPlanner:
    def __init__(self, client: Optional[ClaudeClient] = None, validator: Optional[PlanValidator] = None):
        self.client = client or ClaudeClient()
        self.validator = validator or PlanValidator()

    def generate_plan(self, operation: Operation, risk_category: str) -> Tuple[Optional[AttackPlan], ValidationResult]:
        if risk_category not in RISK_CATEGORIES:
            raise ValueError(f"risk_category must be one of {RISK_CATEGORIES}")

        plan: Optional[AttackPlan] = None
        if self.client.available():
            try:
                raw = self.client.complete(SYSTEM_PROMPT, build_user_prompt(operation, risk_category))
                plan = parse_plan_json(raw)
            except Exception:
                plan = None
        if plan is None:
            plan = heuristic_plan(operation, risk_category)

        result = self.validator.validate(plan)
        if not result.valid:
            return None, result
        return plan, result


# ---------------------------------------------------------------------------
# Placeholder resolver (section 2.2/2.7) - refuses to invent values
# ---------------------------------------------------------------------------

class PlaceholderResolver:
    def __init__(self, test_data: Dict[str, str]):
        self.test_data = test_data

    def resolve(self, placeholder: str) -> str:
        if placeholder not in self.test_data:
            raise KeyError(
                f"no synthetic test value registered for placeholder {placeholder!r}; "
                "refusing to fabricate one - register it explicitly in --test-data"
            )
        return self.test_data[placeholder]


# ---------------------------------------------------------------------------
# Execution harness (section 2.7) - safe-by-construction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SandboxAuthorization:
    confirmed: bool
    target_base_url: str
    authorized_by: str
    authorized_at: str


@dataclass
class ActionResult:
    action_id: str
    action_type: str
    method: str
    path: str
    status_code: Optional[int]
    response_size: Optional[int]
    notes: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# maps each abstract action's placeholders to the sample-request override
# they should drive, e.g. an <OTHER_USER_ID> placeholder substitutes the
# operation's first path parameter
_ID_LIKE_PLACEHOLDER = re.compile(r"_ID>$|_RESOURCE.*>$")
_TOKEN_LIKE_PLACEHOLDER = re.compile(r"_TOKEN.*>$")


class ExecutionHarness:
    def __init__(self, graph: APIGraph, resolver: PlaceholderResolver, authorization: SandboxAuthorization, allow_mutating: bool = False):
        if not authorization.confirmed:
            raise PermissionError("execution refused: sandbox authorization not confirmed")
        if not authorization.target_base_url:
            raise PermissionError("execution refused: no target_base_url provided")
        self.graph = graph
        self.resolver = resolver
        self.authorization = authorization
        self.allow_mutating = allow_mutating

    def execute_plan(self, plan: AttackPlan, validation: ValidationResult, operation_id: str) -> List[ActionResult]:
        if not validation.valid:
            raise PermissionError("execution refused: plan failed validation and must not be executed")
        operation = self.graph.get_operation(operation_id)
        if operation.method not in SAFE_HTTP_METHODS and not self.allow_mutating:
            raise PermissionError(
                f"execution refused: {operation.method} is a mutating verb; pass allow_mutating=True after explicit review"
            )
        return [self._execute_action(action, operation) for action in plan.actions]

    def _execute_action(self, action: AbstractAction, operation: Operation) -> ActionResult:
        overrides: Dict[str, Any] = {}
        for placeholder in action.placeholders:
            value = self.resolver.resolve(placeholder)
            target_param = self._guess_target_param(placeholder, operation)
            if target_param:
                overrides[target_param] = value

        headers: Dict[str, str] = {}
        for placeholder in action.placeholders:
            if _TOKEN_LIKE_PLACEHOLDER.search(placeholder):
                headers["Authorization"] = f"Bearer {self.resolver.resolve(placeholder)}"

        sample = build_sample_request(operation, overrides)
        url = self.authorization.target_base_url.rstrip("/") + sample.path
        status_code, response_size, notes = self._send(sample.method, url, {**sample.headers, **headers})

        return ActionResult(
            action_id=action.id, action_type=action.type, method=sample.method, path=sample.path,
            status_code=status_code, response_size=response_size, notes=notes,
        )

    @staticmethod
    def _guess_target_param(placeholder: str, operation: Operation) -> Optional[str]:
        if not _ID_LIKE_PLACEHOLDER.search(placeholder):
            return None
        path_params = [p.name for p in operation.parameters if p.location == "path"]
        return path_params[0] if path_params else None

    @staticmethod
    def _send(method: str, url: str, headers: Dict[str, str]) -> Tuple[Optional[int], Optional[int], str]:
        req = urllib.request.Request(url, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read()
                return resp.status, len(body), "ok"
        except urllib.error.HTTPError as exc:
            body = exc.read()
            return exc.code, len(body), f"http_error: {exc.reason}"
        except urllib.error.URLError as exc:
            return None, None, f"connection_error: {exc.reason}"


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _start_mock_sandbox_server():
    """A tiny local HTTP server simulating an IDOR-protected /orders/{id}
    endpoint: requests for the 'own' order succeed, requests for the
    'other user's' order are rejected with 403. Local-only (127.0.0.1),
    used purely to give the harness something real to talk to in tests.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    own_id = "own-order-111"
    other_id = "other-order-222"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if own_id in self.path:
                self.send_response(200)
            elif other_id in self.path:
                self.send_response(403)
            else:
                self.send_response(404)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, own_id, other_id


def run_self_test() -> Dict[str, Any]:
    graph = SpecIngestor().ingest_dict(SELF_TEST_SPEC)
    operation = graph.get_operation("getOrderById")

    planner = LLMAttackPlanner()
    plan, validation = planner.generate_plan(operation, "idor")
    assert plan is not None and validation.valid

    # a deliberately unsafe plan (containing a raw SQL literal) must be rejected
    unsafe_plan = AttackPlan(
        goal="bad plan", preconditions=[], risk_level="high",
        actions=[AbstractAction("x1", "ModifyParam", "send id=1' OR '1'='1 to bypass the filter", ["<OTHER_USER_ID>"], "high")],
        evidence_requirements=[],
    )
    unsafe_result = PlanValidator().validate(unsafe_plan)

    server, own_id, other_id = _start_mock_sandbox_server()
    port = server.server_address[1]
    try:
        authorization = SandboxAuthorization(
            confirmed=True, target_base_url=f"http://127.0.0.1:{port}",
            authorized_by="self-test", authorized_at=datetime.now(timezone.utc).isoformat(),
        )
        resolver = PlaceholderResolver({"<OTHER_USER_ID>": other_id, "<AUTH_TOKEN_A>": "synthetic-test-token"})
        harness = ExecutionHarness(graph, resolver, authorization)
        action_results = harness.execute_plan(plan, validation, operation.operation_id)

        unauthorized_attempt_blocked = False
        try:
            ExecutionHarness(graph, resolver, SandboxAuthorization(False, f"http://127.0.0.1:{port}", "x", "x"))
        except PermissionError:
            unauthorized_attempt_blocked = True

        unregistered_placeholder_blocked = False
        try:
            PlaceholderResolver({}).resolve("<UNREGISTERED_TOKEN>")
        except KeyError:
            unregistered_placeholder_blocked = True

        unvalidated_plan_execution_blocked = False
        try:
            harness.execute_plan(unsafe_plan, unsafe_result, operation.operation_id)
        except PermissionError:
            unvalidated_plan_execution_blocked = True

        return {
            "plan_generated_and_valid": validation.valid,
            "plan_action_count": len(plan.actions),
            "unsafe_plan_rejected": not unsafe_result.valid,
            "unsafe_plan_findings": unsafe_result.forbidden_findings,
            "action_results": [r.to_dict() for r in action_results],
            "unauthorized_harness_construction_blocked": unauthorized_attempt_blocked,
            "unregistered_placeholder_blocked": unregistered_placeholder_blocked,
            "unvalidated_plan_execution_blocked": unvalidated_plan_execution_blocked,
        }
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_plan(args: argparse.Namespace) -> int:
    graph = SpecIngestor().ingest_file(Path(args.spec))
    operation = graph.get_operation(args.operation_id)
    planner = LLMAttackPlanner(ClaudeClient())
    if not planner.client.available():
        print("[llm_attack_planner] ANTHROPIC_API_KEY not set - using heuristic fallback plan", file=sys.stderr)
    plan, validation = planner.generate_plan(operation, args.risk)
    if plan is None:
        print(json.dumps({"rejected": True, "validation": asdict(validation)}, indent=2))
        return 1
    output_text = json.dumps(plan.to_dict(), indent=2)
    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Wrote plan to {args.output}")
    else:
        print(output_text)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 8 LLM attack planner")
    subparsers = parser.add_subparsers(dest="mode")

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--spec", required=True)
    plan_parser.add_argument("--operation-id", required=True)
    plan_parser.add_argument("--risk", choices=RISK_CATEGORIES, default="idor")
    plan_parser.add_argument("--output")
    plan_parser.set_defaults(func=_cmd_plan)

    subparsers.add_parser("self-test")

    args = parser.parse_args()
    if args.mode == "self-test":
        print(json.dumps(run_self_test(), indent=2, default=str))
        return 0
    if not args.mode:
        parser.error("Provide a subcommand: plan | self-test")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
