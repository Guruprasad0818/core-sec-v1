"""Pydantic response schemas for the CBAD pipeline API.

Each StageNResponse models the stable top-level envelope returned by the
matching core.ingestion.load_stageN() function (verified against its actual
return dict). Deeply-nested content that originates from the untouched
stage1..stage9 engines themselves (Falco matches, taint-tracking source/sink
records, SBOM components, etc.) is kept as Dict[str, Any] / List[Dict[str, Any]]
rather than re-modeling every internal stage dataclass here - those engines
own their own shapes and are out of scope for this API layer.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class StageMeta(BaseModel):
    stage: int
    key: str
    title: str


# ---------------------------------------------------------------------------
# Stage 1 - Pre-Commit Feature Collection (live git log, via server/git_info.py)
# ---------------------------------------------------------------------------

class GitCommitInfo(BaseModel):
    hash: str
    author: str
    message: str
    timestamp: str
    insertions: int
    deletions: int
    files_changed: int
    changed_files: List[str] = []


class Stage1Response(BaseModel):
    source: str
    repo_path: str
    active_branch: str
    is_dirty: bool
    commits: List[GitCommitInfo]
    total_insertions: int
    total_deletions: int


# ---------------------------------------------------------------------------
# Stage 2 - Live Semgrep Vulnerability Scan (via server/security_scanner.py)
# ---------------------------------------------------------------------------

class SemgrepFinding(BaseModel):
    instance_id: str
    finding_id: str
    severity: str
    message: str
    file_path: str
    line_number: int
    end_line: int
    owasp: List[str] = []
    cwe: List[str] = []


class Stage2Response(BaseModel):
    source: str
    repo_path: str
    configs: List[str]
    total_issues: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[SemgrepFinding]
    scan_errors: List[str] = []


# ---------------------------------------------------------------------------
# Stage 3 - Predictive Risk Analytics (via server/risk_engine.py)
# ---------------------------------------------------------------------------

class RiskHistoryPoint(BaseModel):
    timestamp: str
    commit_hash: str
    risk_score: int


class RiskFindingsBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class Stage3Response(BaseModel):
    source: str
    risk_score: int
    risk_band: str
    active_branch: str
    commit_hash: str
    recent_files_count: int
    findings_in_recent_files: RiskFindingsBreakdown
    matched_findings: List[SemgrepFinding]
    history: List[RiskHistoryPoint]


# ---------------------------------------------------------------------------
# Stage 4 - Automated Mitigation / Remediation Center (via
# server/remediation_engine.py). Lists Stage 2/3 findings with a one-click
# fix action; the taint-tracking SAST engine that used to occupy this slot
# is unwired here (its code is untouched, just no longer surfaced as Stage 4).
# ---------------------------------------------------------------------------

class RemediableFinding(SemgrepFinding):
    is_auto_fixable: bool


class Stage4Response(BaseModel):
    source: str
    remediable_findings: List[RemediableFinding]
    fixable_count: int
    total_count: int


class RemediateRequest(BaseModel):
    instance_id: str


class RemediateResponse(BaseModel):
    status: str  # "committed" | "not_auto_fixable" | "error"
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    branch: Optional[str] = None
    commit_hash: Optional[str] = None
    summary: Optional[str] = None
    diff: Optional[str] = None
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Stage 5 - Entropy Secret Scanner + SLSA Attestation
# ---------------------------------------------------------------------------

class EntropyFinding(BaseModel):
    file_path: str
    line_number: int
    rule_id: str
    category: str
    charset: Optional[str] = None
    entropy: float
    confidence: str
    masked_value: Optional[str] = None


class EntropyHistogramBucket(BaseModel):
    bucket: str
    count: int


class EntropyBlock(BaseModel):
    source: str
    repo_path: str
    total_findings: int
    high_confidence_count: int
    medium_confidence_count: int
    entropy_distribution: List[EntropyHistogramBucket]
    findings: List[EntropyFinding]


class SlsaBlock(BaseModel):
    source: str
    summary: Dict[str, Any]
    sbom: Optional[Dict[str, Any]] = None
    provenance: Optional[Dict[str, Any]] = None
    transparency_log: List[Dict[str, Any]]


class Stage5Response(BaseModel):
    entropy: EntropyBlock
    slsa: SlsaBlock


# ---------------------------------------------------------------------------
# Stage 6 - Runtime Syscall Monitoring (via server/runtime_monitor.py)
# ---------------------------------------------------------------------------

class RuntimeSyscallEvent(BaseModel):
    event: Dict[str, Any]
    score: float
    classification: str  # log | elevated | lockdown
    falco_matches: List[Dict[str, Any]]
    is_anomalous: bool


class Stage6Response(BaseModel):
    source: str
    mode: str  # bpftrace | simulated_hybrid
    events_per_sec: float
    total_events: int
    anomalous_events: int
    classification_counts: Dict[str, int]
    recent_events: List[RuntimeSyscallEvent]


# ---------------------------------------------------------------------------
# Stage 7 - Compliance Tracking & Governance (via server/compliance_engine.py)
# ---------------------------------------------------------------------------

class ComplianceViolation(BaseModel):
    control_id: str
    framework: str
    control_title: str
    source_stage: int
    severity: str
    summary: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    finding_ref: Optional[str] = None
    timestamp: str


class ComplianceControlStatus(BaseModel):
    control_id: str
    title: str
    description: str
    status: str  # PASS | FAIL
    violation_count: int
    highest_severity: Optional[str] = None


class ComplianceFrameworkBlock(BaseModel):
    framework: str
    controls: List[ComplianceControlStatus]
    passed: int
    total: int
    readiness_pct: float


class Stage7Response(BaseModel):
    source: str
    generated_at: str
    owasp: ComplianceFrameworkBlock
    soc2: ComplianceFrameworkBlock
    rules_passed: int
    rules_failed: int
    total_violations: int
    violations: List[ComplianceViolation]


# ---------------------------------------------------------------------------
# Stage 8 - Supply Chain Security & SLSA Provenance (via
# server/supply_chain_monitor.py). Replaces the previous DAST/attack-planner
# demo that occupied this slot - stage8/interface_ingestor.py and
# stage8/llm_attack_planner.py are untouched on disk, just no longer
# surfaced as Stage 8's response.
# ---------------------------------------------------------------------------

class SupplyChainDependency(BaseModel):
    name: str
    version: str
    ecosystem: str  # pypi | npm
    purl: Optional[str] = None
    sha256: str
    verified: bool


class DependencyTreeNode(BaseModel):
    name: str
    version: Optional[str] = None
    verified: Optional[bool] = None
    children: Optional[List["DependencyTreeNode"]] = None


class SignatureLogEntry(BaseModel):
    timestamp: str
    method: str
    artifact_digest: str
    verified: bool
    reason: str
    subject_identity: Dict[str, str]
    rekor_uuid: Optional[str] = None
    rekor_log_index: Optional[int] = None


class Stage8Response(BaseModel):
    source: str
    generated_at: str
    attestation_status: str  # PASSED | FAILED
    slsa_level: int
    slsa_level_target: int
    artifact_digest: str
    sbom_completeness_pct: float
    dependency_count: int
    dependencies: List[SupplyChainDependency]
    dependency_tree: DependencyTreeNode
    signature_log: List[SignatureLogEntry]
    transparency_log_entries: int
    rekor_chain_intact: bool


# ---------------------------------------------------------------------------
# Stage 9 - Final Policy Gate & Executive Reporting (via server/policy_gate.py).
# Replaces the previous SBOM/CVE-exposure monitor + OPA event router that
# occupied this slot - stage9/sbom_monitor.py and stage9/opa_event_router.py
# are untouched on disk, just no longer surfaced as Stage 9's response.
# ---------------------------------------------------------------------------

class PolicyCondition(BaseModel):
    condition_id: str
    label: str
    passed: bool
    detail: str


class Stage9Response(BaseModel):
    source: str
    generated_at: str
    deployment_status: str  # APPROVED | BLOCKED
    conditions: List[PolicyCondition]
    failure_reasons: List[str]
    executive_summary: str


STAGE_RESPONSE_MODELS = {
    1: Stage1Response,
    2: Stage2Response,
    3: Stage3Response,
    4: Stage4Response,
    5: Stage5Response,
    6: Stage6Response,
    7: Stage7Response,
    8: Stage8Response,
    9: Stage9Response,
}


# ---------------------------------------------------------------------------
# Overview aggregation
# ---------------------------------------------------------------------------

class StageHealth(BaseModel):
    stage: int
    name: str
    status: str
    level: str
    sub_metric: str
    error: Optional[str] = None


class MetricItem(BaseModel):
    label: str
    value: str
    level: str


class RiskBreakdownRow(BaseModel):
    stage: str
    critical: int
    high: int
    medium: int
    low: int


class FindingRow(BaseModel):
    stage: str
    severity: str
    summary: str


class OverviewResponse(BaseModel):
    pipeline_label: str
    pipeline_level: str
    triage_total: int
    triage_level: str
    deepest_level: str
    stage_health: List[StageHealth]
    critical_metrics: List[MetricItem]
    findings_volume: Dict[str, int]
    risk_breakdown: List[RiskBreakdownRow]
    top_findings: List[FindingRow]
    errors: Dict[int, str]
