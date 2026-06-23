#!/usr/bin/env python3
"""CBAD Stage 4 - Semantic SAST taint-tracking engine.

Implements the source/sink/sanitizer model, the common rule meta-model, and
the finding schema from CBAD_Stage4_TaintTracking_MultiLanguage.md (sections
1.3-1.6, 1.8, 2.5.1), with concrete Spring Boot/Java, Node.js, and Python
rule vectors drawn from section 2.2-2.4.

Scope and honest limitations (see section 3.1/3.4 - this engine is the
"internal taint engine" pre-filter that runs alongside CodeQL/Semgrep, not a
replacement for them):
  - taint is tracked per-file with a single-pass, line-ordered scan rather
    than full AST/IR construction (section 1.2's `AST / IR extractor` and
    `call graph builder` are out of scope here)
  - propagation is intraprocedural only: assignments and same-line call
    arguments. Cross-function, cross-file, and cross-service propagation
    (sections 1.7.1-1.7.3) are explicitly NOT modeled and are CodeQL's job
  - sink/source matching is by method/property name pattern, not verified
    receiver type, since no symbol table is built - a deliberate
    precision-for-speed tradeoff appropriate for a fast pre-filter
  - sanitizers are modeled as fully neutralizing (the "strong" tier from
    section 1.6.3); weak/conditional residual-taint modeling is not
    implemented

Usage:
  python stage4/sast_engine.py --scan-dir path/to/code
  python stage4/sast_engine.py --scan-dir path/to/code --language python
  python stage4/sast_engine.py --self-test
  python stage4/sast_engine.py --scan-dir path/to/code --output findings.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Sequence, Tuple

Language = str  # "java" | "node" | "python"

EXTENSION_LANGUAGE_MAP: Dict[str, Language] = {
    ".java": "java",
    ".js": "node",
    ".jsx": "node",
    ".ts": "node",
    ".tsx": "node",
    ".py": "python",
}


# ---------------------------------------------------------------------------
# Rule model (section 2.5.1 common rule meta-model)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourceRule:
    rule_id: str
    language: Language
    pattern: Pattern[str]
    taint_label: str
    tags: Tuple[str, ...]
    trust: str = "untrusted"  # untrusted | semi-trusted | trusted


@dataclass(frozen=True)
class SinkRule:
    rule_id: str
    language: Language
    pattern: Pattern[str]
    tags: Tuple[str, ...]
    severity: str  # critical | high | medium | low
    description: str
    parameterized_when_multi_arg: bool = False


@dataclass(frozen=True)
class SanitizerRule:
    rule_id: str
    language: Language
    pattern: Pattern[str]
    sanitizer_type: str
    effect: str  # neutralize | validate | encode | reject


@dataclass(frozen=True)
class LanguageRuleSet:
    sources: Tuple[SourceRule, ...]
    sinks: Tuple[SinkRule, ...]
    sanitizers: Tuple[SanitizerRule, ...]


# ---------------------------------------------------------------------------
# Finding model (section 1.8 path materialization / 2.6 reporting)
# ---------------------------------------------------------------------------

@dataclass
class TaintEvent:
    rule_id: str
    line_number: int
    line_text: str
    variable: Optional[str] = None


@dataclass
class TaintFinding:
    finding_id: str
    language: Language
    category: str
    file_path: str
    source: TaintEvent
    sink: TaintEvent
    sanitizer: Optional[TaintEvent]
    severity: str
    confidence: str  # high | medium | low
    tags: Tuple[str, ...]
    description: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "language": self.language,
            "category": self.category,
            "file_path": self.file_path,
            "source": asdict(self.source),
            "sink": asdict(self.sink),
            "sanitizer": asdict(self.sanitizer) if self.sanitizer else None,
            "severity": self.severity,
            "confidence": self.confidence,
            "tags": list(self.tags),
            "description": self.description,
        }


# ---------------------------------------------------------------------------
# Rule registries (section 2.2 Java, 2.3 Node.js, 2.4 Python)
# ---------------------------------------------------------------------------

def _re(pattern: str) -> Pattern[str]:
    return re.compile(pattern)


JAVA_RULES = LanguageRuleSet(
    sources=(
        SourceRule("java_http_get_parameter", "java", _re(r"\.getParameter\("), "user_input", ("user-controlled", "http")),
        SourceRule("java_http_get_header", "java", _re(r"\.getHeader\("), "user_input", ("user-controlled", "http")),
        SourceRule("java_request_body", "java", _re(r"@RequestBody"), "user_input", ("user-controlled", "http")),
        SourceRule("java_path_variable", "java", _re(r"@PathVariable"), "user_input", ("user-controlled", "http")),
        SourceRule("java_system_getenv", "java", _re(r"System\.getenv\("), "env_input", ("environment",), trust="semi-trusted"),
    ),
    sinks=(
        SinkRule("java_jdbc_statement_query", "java", _re(r"\.executeQuery\("), ("sql_injection", "sql"), "critical", "Tainted value flows into Statement.executeQuery."),
        SinkRule("java_jdbc_statement_update", "java", _re(r"\.executeUpdate\("), ("sql_injection", "sql"), "critical", "Tainted value flows into Statement.executeUpdate."),
        SinkRule("java_jdbctemplate_query", "java", _re(r"JdbcTemplate\.(query|update|execute)\("), ("sql_injection", "sql"), "high", "Tainted value flows into JdbcTemplate execution."),
        SinkRule("java_entitymanager_query", "java", _re(r"\.createNativeQuery\(|\.createQuery\("), ("sql_injection", "jpa"), "high", "Tainted value flows into a JPA query string."),
        SinkRule("java_runtime_exec", "java", _re(r"Runtime\.getRuntime\(\)\.exec\("), ("command_injection", "command"), "critical", "Tainted value flows into Runtime.exec."),
        SinkRule("java_processbuilder", "java", _re(r"new\s+ProcessBuilder\("), ("command_injection", "command"), "critical", "Tainted value flows into ProcessBuilder."),
        SinkRule("java_new_file", "java", _re(r"new\s+File\("), ("path_traversal", "filesystem"), "medium", "Tainted value used to construct a file path."),
        SinkRule("java_logger", "java", _re(r"logger\.(info|error|warn)\("), ("log_injection",), "low", "Tainted value logged without sanitization."),
    ),
    sanitizers=(
        SanitizerRule("java_preparedstatement_set", "java", _re(r"\.setString\(|\.setInt\(|\.setObject\("), "parameterized_query", "neutralize"),
        SanitizerRule("java_namedparam_jdbc", "java", _re(r"NamedParameterJdbcTemplate\.update\("), "parameterized_query", "neutralize"),
        SanitizerRule("java_html_escape", "java", _re(r"StringEscapeUtils\.escapeHtml4\(|HtmlUtils\.htmlEscape\("), "escaper", "encode"),
        SanitizerRule("java_url_encode", "java", _re(r"URLEncoder\.encode\("), "encoder", "encode"),
        SanitizerRule("java_escape_sql", "java", _re(r"StringEscapeUtils\.escapeSql\("), "escaper", "neutralize"),
        SanitizerRule("java_path_normalize", "java", _re(r"\.resolve\(.*\)\.normalize\(\)"), "normalizer", "validate"),
    ),
)

NODE_RULES = LanguageRuleSet(
    sources=(
        SourceRule("node_req_query", "node", _re(r"req\.query\."), "user_input", ("user-controlled", "http")),
        SourceRule("node_req_params", "node", _re(r"req\.params\."), "user_input", ("user-controlled", "http")),
        SourceRule("node_req_body", "node", _re(r"req\.body\."), "user_input", ("user-controlled", "http")),
        SourceRule("node_req_headers", "node", _re(r"req\.headers\."), "user_input", ("user-controlled", "http")),
        SourceRule("node_process_env", "node", _re(r"process\.env\."), "env_input", ("environment",), trust="semi-trusted"),
        SourceRule("node_process_argv", "node", _re(r"process\.argv\["), "cli_input", ("cli",)),
    ),
    sinks=(
        SinkRule("node_db_query", "node", _re(r"\.query\("), ("sql_injection", "sql"), "critical", "Tainted value flows into a database query call."),
        SinkRule("node_child_process_exec", "node", _re(r"child_process\.exec\(|\.execSync\(|\.spawn\(|\.spawnSync\("), ("command_injection", "command"), "critical", "Tainted value flows into a child_process call."),
        SinkRule("node_eval", "node", _re(r"\beval\("), ("code_injection",), "critical", "Tainted value flows into eval()."),
        SinkRule("node_new_function", "node", _re(r"new\s+Function\("), ("code_injection",), "high", "Tainted value flows into dynamic Function construction."),
        SinkRule("node_fs_writefilesync", "node", _re(r"fs\.writeFileSync\("), ("path_traversal", "filesystem"), "medium", "Tainted value used as a file write path."),
        SinkRule("node_template_render", "node", _re(r"ejs\.render\(|pug\.renderFile\(|handlebars\.compile\("), ("xss", "ssti"), "high", "Tainted value flows into template rendering."),
        SinkRule("node_http_client", "node", _re(r"axios\.get\(|axios\.post\(|fetch\("), ("ssrf",), "high", "Tainted value used as an outbound HTTP request URL."),
        SinkRule("node_console_log", "node", _re(r"console\.log\(|logger\.info\("), ("log_injection",), "low", "Tainted value logged without sanitization."),
    ),
    sanitizers=(
        SanitizerRule("node_mysql_escape", "node", _re(r"mysql\.escape\(|mysql\.format\("), "escaper", "encode"),
        SanitizerRule("node_pg_format", "node", _re(r"pg\.format\("), "parameterized_query", "neutralize"),
        SanitizerRule("node_encode_uri", "node", _re(r"encodeURIComponent\(|encodeURI\("), "encoder", "encode"),
        SanitizerRule("node_validator", "node", _re(r"validator\.is\w+\(|joi\.validate\("), "validator", "validate"),
        SanitizerRule("node_knex_where", "node", _re(r"\.where\("), "parameterized_query", "neutralize"),
        SanitizerRule("node_path_normalize", "node", _re(r"path\.normalize\("), "normalizer", "validate"),
    ),
)

PYTHON_RULES = LanguageRuleSet(
    sources=(
        SourceRule("py_flask_args", "python", _re(r"request\.args\.get\("), "user_input", ("user-controlled", "http")),
        SourceRule("py_flask_form", "python", _re(r"request\.form\.get\("), "user_input", ("user-controlled", "http")),
        SourceRule("py_flask_json", "python", _re(r"request\.get_json\("), "user_input", ("user-controlled", "http")),
        SourceRule("py_django_get", "python", _re(r"request\.GET\[|request\.GET\.get\("), "user_input", ("user-controlled", "http")),
        SourceRule("py_django_post", "python", _re(r"request\.POST\[|request\.POST\.get\("), "user_input", ("user-controlled", "http")),
        SourceRule("py_os_environ", "python", _re(r"os\.environ\.get\("), "env_input", ("environment",), trust="semi-trusted"),
        SourceRule("py_sys_argv", "python", _re(r"sys\.argv\["), "cli_input", ("cli",)),
    ),
    sinks=(
        SinkRule(
            "py_cursor_execute", "python", _re(r"cursor\.execute\("), ("sql_injection", "sql"), "critical",
            "Tainted value flows into cursor.execute.", parameterized_when_multi_arg=True,
        ),
        SinkRule(
            "py_session_execute", "python", _re(r"session\.execute\("), ("sql_injection", "sql"), "high",
            "Tainted value flows into a SQLAlchemy session.execute call.", parameterized_when_multi_arg=True,
        ),
        SinkRule("py_subprocess", "python", _re(r"subprocess\.(Popen|run|call)\(|os\.system\("), ("command_injection", "command"), "critical", "Tainted value flows into a subprocess/os.system call."),
        SinkRule("py_eval_exec", "python", _re(r"\beval\(|\bexec\(|\bcompile\("), ("code_injection",), "critical", "Tainted value flows into eval/exec/compile."),
        SinkRule("py_open_path", "python", _re(r"\bopen\("), ("path_traversal", "filesystem"), "medium", "Tainted value used as a file path argument to open()."),
        SinkRule("py_jinja_render", "python", _re(r"render_template\(|\.render\("), ("xss", "ssti"), "high", "Tainted value flows into template rendering."),
        SinkRule("py_requests_get", "python", _re(r"requests\.get\(|requests\.post\(|urlopen\("), ("ssrf",), "high", "Tainted value used as an outbound HTTP request URL."),
        SinkRule("py_pickle_loads", "python", _re(r"pickle\.loads\(|yaml\.load\("), ("insecure_deserialization",), "critical", "Tainted value deserialized without safe-loader constraints."),
        SinkRule("py_logging", "python", _re(r"logging\.(info|warning|error)\(|logger\.(info|warning|error)\("), ("log_injection",), "low", "Tainted value logged without sanitization."),
    ),
    sanitizers=(
        SanitizerRule("py_html_escape", "python", _re(r"html\.escape\("), "escaper", "encode"),
        SanitizerRule("py_url_quote", "python", _re(r"urllib\.parse\.quote_plus\("), "encoder", "encode"),
        SanitizerRule("py_regex_fullmatch", "python", _re(r"re\.fullmatch\("), "validator", "validate"),
        SanitizerRule("py_jinja_escape", "python", _re(r"jinja2\.escape\("), "escaper", "encode"),
        SanitizerRule("py_path_normpath", "python", _re(r"os\.path\.normpath\("), "normalizer", "validate"),
        SanitizerRule("py_yaml_safe_load", "python", _re(r"yaml\.safe_load\("), "safe_deserializer", "neutralize"),
    ),
)

RULES: Dict[Language, LanguageRuleSet] = {
    "java": JAVA_RULES,
    "node": NODE_RULES,
    "python": PYTHON_RULES,
}


# ---------------------------------------------------------------------------
# Line parsing helpers
# ---------------------------------------------------------------------------

ASSIGNMENT_PATTERN = re.compile(
    r"^\s*(?:(?:var|let|const)\s+|(?:[A-Za-z_][\w\.<>\[\],\s]*\s+))?"
    r"([A-Za-z_]\w*)\s*=\s*(.+?);?\s*$"
)


def _first_matching_rule(rules: Sequence, text: str):
    for rule in rules:
        if rule.pattern.search(text):
            return rule
    return None


def _find_tainted_variable(text: str, tainted_vars: Dict[str, TaintEvent]) -> Optional[str]:
    for name in tainted_vars:
        if re.search(rf"\b{re.escape(name)}\b", text):
            return name
    return None


def _extract_call_arguments(line: str, open_paren_index: int) -> Optional[List[str]]:
    """Naive top-level comma split of a call's arguments, starting just after
    the opening '('. Handles nested brackets and quoted strings well enough
    for single-line calls; multi-line calls are not supported.
    """
    depth = 1
    args: List[str] = []
    current: List[str] = []
    in_string: Optional[str] = None
    i = open_paren_index
    while i < len(line) and depth > 0:
        ch = line[i]
        if in_string:
            current.append(ch)
            if ch == in_string and line[i - 1] != "\\":
                in_string = None
        elif ch in "\"'":
            in_string = ch
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                break
            current.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    if depth != 0:
        return None
    if current:
        args.append("".join(current).strip())
    return args


def _is_parameterized_call(line: str, match: re.Match) -> bool:
    open_paren_index = line.find("(", match.start())
    if open_paren_index == -1:
        return False
    args = _extract_call_arguments(line, open_paren_index + 1)
    return bool(args and len(args) >= 2 and args[1])


def _make_finding_id(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return digest[:16]


# ---------------------------------------------------------------------------
# Core taint propagation (single-file, line-ordered)
# ---------------------------------------------------------------------------

def scan_lines(lines: Sequence[str], language: Language, file_label: str) -> List[TaintFinding]:
    """Pure, file-IO-free taint scan over an in-memory list of source lines.

    Kept separate from scan_file() so the propagation logic can be unit
    tested and self-tested without touching the filesystem.
    """
    rule_set = RULES.get(language)
    if rule_set is None:
        return []

    tainted_vars: Dict[str, TaintEvent] = {}
    findings: List[TaintFinding] = []

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n")

        # 1. statement-level sanitizer application neutralizes a referenced tainted var
        sanitizer_rule = _first_matching_rule(rule_set.sanitizers, line)
        if sanitizer_rule:
            referenced = _find_tainted_variable(line, tainted_vars)
            if referenced:
                tainted_vars.pop(referenced, None)

        # 2. assignment of a source expression taints the target variable
        assignment = ASSIGNMENT_PATTERN.match(line)
        if assignment:
            var_name, rhs = assignment.group(1), assignment.group(2)
            source_rule = _first_matching_rule(rule_set.sources, rhs)
            if source_rule:
                tainted_vars[var_name] = TaintEvent(source_rule.rule_id, line_number, line, var_name)

        # 3. sink detection: inline source-to-sink, or tainted-variable-to-sink
        for sink_rule in rule_set.sinks:
            match = sink_rule.pattern.search(line)
            if not match:
                continue

            if sink_rule.parameterized_when_multi_arg and _is_parameterized_call(line, match):
                continue  # parameterized binding - treated as sanitized (section 4.3 suppression rule)

            inline_source_rule = _first_matching_rule(rule_set.sources, line)
            if inline_source_rule:
                source_event = TaintEvent(inline_source_rule.rule_id, line_number, line)
            else:
                tainted_var = _find_tainted_variable(line, tainted_vars)
                if not tainted_var:
                    continue
                source_event = tainted_vars[tainted_var]

            sink_event = TaintEvent(sink_rule.rule_id, line_number, line)
            distance = sink_event.line_number - source_event.line_number
            confidence = "high" if distance <= 10 else "medium"

            findings.append(
                TaintFinding(
                    finding_id=_make_finding_id(file_label, sink_rule.rule_id, str(source_event.line_number), str(sink_event.line_number)),
                    language=language,
                    category=sink_rule.tags[0],
                    file_path=file_label,
                    source=source_event,
                    sink=sink_event,
                    sanitizer=None,
                    severity=sink_rule.severity,
                    confidence=confidence,
                    tags=sink_rule.tags,
                    description=sink_rule.description,
                )
            )

    return findings


def detect_language(path: Path) -> Optional[Language]:
    return EXTENSION_LANGUAGE_MAP.get(path.suffix.lower())


def scan_file(path: Path, language: Optional[Language] = None) -> List[TaintFinding]:
    language = language or detect_language(path)
    if language is None:
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    return scan_lines(text.splitlines(), language, str(path))


def scan_directory(root: Path, languages: Optional[Sequence[Language]] = None) -> List[TaintFinding]:
    allowed = set(languages) if languages else set(RULES.keys())
    findings: List[TaintFinding] = []
    for ext, lang in EXTENSION_LANGUAGE_MAP.items():
        if lang not in allowed:
            continue
        for path in root.rglob(f"*{ext}"):
            findings.extend(scan_file(path, lang))
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

SELF_TEST_SAMPLES: Dict[Language, str] = {
    "java": (
        'String id = request.getParameter("id");\n'
        'Statement stmt = connection.createStatement();\n'
        'ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id=" + id);\n'
        "\n"
        'String safeId = request.getParameter("id");\n'
        "PreparedStatement ps = connection.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n"
        "ps.setString(1, safeId);\n"
        "ps.executeQuery();\n"
    ),
    "node": (
        "const cmd = req.query.cmd;\n"
        "child_process.exec(cmd);\n"
        "\n"
        "const username = req.query.name;\n"
        "db.query('SELECT * FROM users WHERE name = ' + username);\n"
    ),
    "python": (
        "filename = request.args.get('file')\n"
        "f = open(os.path.join(base_dir, filename))\n"
        "\n"
        "user_id = request.args.get('id')\n"
        "cursor.execute(query, (user_id,))\n"
    ),
}


def run_self_test() -> List[TaintFinding]:
    findings: List[TaintFinding] = []
    for language, sample in SELF_TEST_SAMPLES.items():
        findings.extend(scan_lines(sample.splitlines(), language, f"<self-test:{language}>"))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 4 taint-tracking SAST engine")
    parser.add_argument("--scan-dir", help="Directory to scan recursively")
    parser.add_argument("--language", choices=["java", "node", "python", "all"], default="all")
    parser.add_argument("--output", help="Optional path to write JSON findings")
    parser.add_argument("--self-test", action="store_true", help="Run against built-in vulnerable/sanitized samples")
    args = parser.parse_args()

    if not args.scan_dir and not args.self_test:
        parser.error("Provide --scan-dir <path> or --self-test")

    if args.self_test:
        findings = run_self_test()
    else:
        languages = None if args.language == "all" else [args.language]
        findings = scan_directory(Path(args.scan_dir), languages)

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
