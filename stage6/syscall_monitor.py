#!/usr/bin/env python3
"""CBAD Stage 6 - eBPF-pattern syscall telemetry monitor.

Implements the event schema, eBPF attach-point catalog, Falco-style rule
matcher, and threat scoring matrix from CBAD_Stage6_gVisor_eBPF.md SECTION 2
("eBPF & Falco Syscall Telemetry Matrix").

Honest scope: this module does not load real eBPF bytecode into the kernel.
The reference architecture (section 2.2) attaches kprobes/tracepoints via
libbpf/CO-RE from a Go agent. This Python module instead provides two
interchangeable SyscallEventSource implementations:
  - BpftraceSyscallEventSource: drives the same kprobe/tracepoint workflow
    through `bpftrace` (a CO-RE-based eBPF tracer with its own DSL) via
    subprocess, on Linux with bpftrace installed and CAP_BPF/root available.
    The generated script and output parsing are best-effort/illustrative -
    exact tracepoint argument field names vary across kernel and bpftrace
    versions and should be validated against the target kernel before
    relying on this in production.
  - SimulatedSyscallEventSource: a deterministic synthetic event generator,
    required on the Windows machine this was authored and tested on, which
    has no eBPF subsystem at all.

Both sources implement the same interface, so SyscallMonitor, the Falco
rule engine, and the scoring matrix run identically regardless of backend -
swap in a real libbpf/CO-RE Go agent feeding events over a Unix socket for
production without touching this module's logic.

Usage:
  python stage6/syscall_monitor.py --self-test
  python stage6/syscall_monitor.py --mode simulate --output events.jsonl
  python stage6/syscall_monitor.py --mode bpftrace --cgroup /sys/fs/cgroup/runner --output events.jsonl
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Deque, Dict, Iterator, List, Optional, Sequence, Set, Tuple

# section 2.2 "attach kprobes/tracepoints ... for targets"
TARGET_SYSCALLS: Tuple[str, ...] = (
    "execve", "execveat", "openat", "open", "socket", "connect",
    "accept", "sendto", "recvfrom", "ptrace",
)


# ---------------------------------------------------------------------------
# Event schema (section 2.2 field list)
# ---------------------------------------------------------------------------

@dataclass
class SyscallEvent:
    event_id: str
    timestamp: str
    container_id: str
    pid: int
    tid: int
    comm: str
    syscall: str
    args: Dict[str, str]
    return_code: int
    uid: int
    gid: int
    namespaces: Dict[str, str] = field(default_factory=dict)  # mnt, pid, net

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _event_from_dict(payload: Dict[str, object]) -> SyscallEvent:
    return SyscallEvent(
        event_id=str(payload["event_id"]),
        timestamp=str(payload["timestamp"]),
        container_id=str(payload["container_id"]),
        pid=int(payload["pid"]),
        tid=int(payload["tid"]),
        comm=str(payload["comm"]),
        syscall=str(payload["syscall"]),
        args=dict(payload.get("args", {})),
        return_code=int(payload["return_code"]),
        uid=int(payload["uid"]),
        gid=int(payload["gid"]),
        namespaces=dict(payload.get("namespaces", {})),
    )


# ---------------------------------------------------------------------------
# Event sources
# ---------------------------------------------------------------------------

class SyscallEventSource(ABC):
    @abstractmethod
    def events(self) -> Iterator[SyscallEvent]:
        """Yield SyscallEvent records as they become available."""


class BpftraceSyscallEventSource(SyscallEventSource):
    """Drives bpftrace to attach tracepoints for TARGET_SYSCALLS, scoped to a
    cgroup v2 path when provided (section 2.2: "Use cgroup v2 BPF attachment
    where supported to limit tracing to build runner cgroups").
    """

    def __init__(self, container_id: str, cgroup_path: Optional[str] = None, bpftrace_binary: str = "bpftrace"):
        self.container_id = container_id
        self.cgroup_path = cgroup_path
        self.bpftrace_binary = bpftrace_binary

    @staticmethod
    def available(bpftrace_binary: str = "bpftrace") -> bool:
        return shutil.which(bpftrace_binary) is not None

    def _build_script(self) -> str:
        cgroup_filter = f'    if (cgroup != "{self.cgroup_path}") {{ return; }}\n' if self.cgroup_path else ""
        probes = []
        for syscall in TARGET_SYSCALLS:
            probes.append(
                f"tracepoint:syscalls:sys_enter_{syscall}\n"
                "{\n"
                f"{cgroup_filter}"
                f'    printf("EVENT\\t{syscall}\\t%d\\t%d\\t%s\\t%lld\\n", pid, tid, comm, nsecs);\n'
                "}"
            )
        return "\n\n".join(probes) + "\n"

    def events(self) -> Iterator[SyscallEvent]:
        if not self.available(self.bpftrace_binary):
            raise RuntimeError(
                f"'{self.bpftrace_binary}' was not found on PATH. Install bpftrace and run as root/CAP_BPF, "
                "or use --mode simulate."
            )
        script = self._build_script()
        process = subprocess.Popen(
            [self.bpftrace_binary, "-e", script],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert process.stdout is not None
        try:
            for line in process.stdout:
                parsed = self._parse_line(line)
                if parsed is not None:
                    yield parsed
        finally:
            process.terminate()

    def _parse_line(self, line: str) -> Optional[SyscallEvent]:
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 5 or parts[0] != "EVENT":
            return None
        _, syscall, pid, tid, comm = parts[0], parts[1], parts[2], parts[3], parts[4]
        return SyscallEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            container_id=self.container_id,
            pid=int(pid),
            tid=int(tid),
            comm=comm,
            syscall=syscall,
            args={},
            return_code=0,
            uid=-1,
            gid=-1,
        )


class SimulatedSyscallEventSource(SyscallEventSource):
    """Deterministic synthetic event stream covering each Falco example rule
    in section 2.3 plus a frequency spike, for offline development/testing.
    """

    def __init__(self, container_id: str = "sim-container-0001"):
        self.container_id = container_id

    def events(self) -> Iterator[SyscallEvent]:
        base_time = datetime.now(timezone.utc)
        scripted: List[Tuple[str, Dict[str, str], int]] = [
            ("openat", {"path": "/workspace/src/app.py"}, 0),          # benign
            ("openat", {"path": "/output/build.log"}, 0),               # benign
            ("execve", {"binary": "/workspace/bin/build.sh"}, 0),       # benign, whitelisted
            ("openat", {"path": "/etc/passwd"}, 0),                     # violation: outside workspace
            ("execve", {"binary": "/tmp/payload"}, 0),                  # violation: not whitelisted
            ("connect", {"ip": "203.0.113.55", "port": "4444"}, 0),     # violation: external IP
            ("ptrace", {"request": "PTRACE_ATTACH"}, 0),                # violation: introspection
        ]
        for offset, (syscall, args, rc) in enumerate(scripted):
            yield SyscallEvent(
                event_id=str(uuid.uuid4()),
                timestamp=(base_time + timedelta(milliseconds=offset * 50)).isoformat(),
                container_id=self.container_id,
                pid=1000 + offset,
                tid=1000 + offset,
                comm="build-runner",
                syscall=syscall,
                args=args,
                return_code=rc,
                uid=1000,
                gid=1000,
                namespaces={"mnt": "mnt:[4026531840]", "pid": "pid:[4026531836]", "net": "net:[4026531992]"},
            )

        # frequency spike: rapid repeated connect calls from the same pid
        spike_start = len(scripted)
        for i in range(25):
            yield SyscallEvent(
                event_id=str(uuid.uuid4()),
                timestamp=(base_time + timedelta(milliseconds=(spike_start + i) * 5)).isoformat(),
                container_id=self.container_id,
                pid=2000,
                tid=2000,
                comm="build-runner",
                syscall="connect",
                args={"ip": "198.51.100.9", "port": "443"},
                return_code=0,
                uid=1000,
                gid=1000,
            )


# ---------------------------------------------------------------------------
# Falco-style rule engine (section 2.3)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleContext:
    allowed_paths: Tuple[str, ...] = ()
    allowed_binaries: Set[str] = field(default_factory=set)
    allowed_ips: Set[str] = field(default_factory=set)


@dataclass(frozen=True)
class FalcoRule:
    rule_id: str
    description: str
    syscalls: Tuple[str, ...]
    condition: Callable[[SyscallEvent, RuleContext], bool]
    output_template: str
    priority: str  # WARNING | CRITICAL
    tags: Tuple[str, ...]


@dataclass
class FalcoMatch:
    rule_id: str
    priority: str
    output: str
    tags: Tuple[str, ...]
    event_id: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _openat_outside_workspace(event: SyscallEvent, ctx: RuleContext) -> bool:
    path = event.args.get("path", "")
    return bool(path) and not any(path.startswith(prefix) for prefix in ctx.allowed_paths)


def _execve_not_whitelisted(event: SyscallEvent, ctx: RuleContext) -> bool:
    binary = event.args.get("binary", "")
    return bool(binary) and binary not in ctx.allowed_binaries


def _connect_external_ip(event: SyscallEvent, ctx: RuleContext) -> bool:
    ip = event.args.get("ip", "")
    return bool(ip) and ip not in ctx.allowed_ips


def _ptrace_used(event: SyscallEvent, ctx: RuleContext) -> bool:
    return True  # ptrace is denied by default per section 1.4; presence alone is the signal


DEFAULT_RULES: Tuple[FalcoRule, ...] = (
    FalcoRule(
        rule_id="openat_outside_workspace",
        description="Detect openat syscalls opening files outside /workspace or /output",
        syscalls=("openat", "open"),
        condition=_openat_outside_workspace,
        output_template="Open outside workspace (command=%comm file=%path)",
        priority="WARNING",
        tags=("container", "file-access", "policy"),
    ),
    FalcoRule(
        rule_id="execve_not_whitelisted",
        description="Detect execve where the binary is not present in the build manifest",
        syscalls=("execve", "execveat"),
        condition=_execve_not_whitelisted,
        output_template="Execve of unapproved binary (container=%container_id binary=%binary)",
        priority="CRITICAL",
        tags=("exec", "container", "policy"),
    ),
    FalcoRule(
        rule_id="connect_external_ip",
        description="Detect connect to external IPs not in the allowlist",
        syscalls=("connect",),
        condition=_connect_external_ip,
        output_template="Outgoing connect to unexpected IP (container=%container_id ip=%ip port=%port)",
        priority="CRITICAL",
        tags=("network", "ssrf", "egress"),
    ),
    FalcoRule(
        rule_id="ptrace_not_permitted",
        description="Detect ptrace usage, denied by default per the gVisor Sentry hardened configuration",
        syscalls=("ptrace",),
        condition=_ptrace_used,
        output_template="ptrace syscall used (container=%container_id pid=%pid)",
        priority="CRITICAL",
        tags=("introspection", "container", "policy"),
    ),
)


def _render_output(template: str, event: SyscallEvent) -> str:
    values = {"comm": event.comm, "container_id": event.container_id, "pid": str(event.pid), **event.args}
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace(f"%{key}", value)
    return rendered


def evaluate_rules(event: SyscallEvent, rules: Sequence[FalcoRule], context: RuleContext) -> List[FalcoMatch]:
    matches: List[FalcoMatch] = []
    for rule in rules:
        if event.syscall not in rule.syscalls:
            continue
        if rule.condition(event, context):
            matches.append(FalcoMatch(
                rule_id=rule.rule_id,
                priority=rule.priority,
                output=_render_output(rule.output_template, event),
                tags=rule.tags,
                event_id=event.event_id,
            ))
    return matches


# ---------------------------------------------------------------------------
# Threat scoring matrix (section 2.5)
# ---------------------------------------------------------------------------

SYSCALL_CRITICALITY: Dict[str, float] = {
    "execve": 1.0, "execveat": 1.0, "connect": 1.0, "ptrace": 1.0,
    "socket": 0.6, "accept": 0.6, "sendto": 0.5, "recvfrom": 0.5,
    "openat": 0.4, "open": 0.4,
}


@dataclass(frozen=True)
class ScoringWeights:
    syscall_criticality: float = 0.35
    provenance_mismatch: float = 0.35
    frequency_factor: float = 0.15
    entropy_signal: float = 0.15


def score_event(
    event: SyscallEvent,
    falco_matches: Sequence[FalcoMatch],
    frequency_factor: float,
    entropy_signal: float = 0.0,
    weights: ScoringWeights = ScoringWeights(),
) -> float:
    criticality = SYSCALL_CRITICALITY.get(event.syscall, 0.2)
    if any(match.priority == "CRITICAL" for match in falco_matches):
        provenance_mismatch = 1.0
    elif falco_matches:
        provenance_mismatch = 0.5
    else:
        provenance_mismatch = 0.0

    score = (
        weights.syscall_criticality * criticality
        + weights.provenance_mismatch * provenance_mismatch
        + weights.frequency_factor * min(1.0, frequency_factor)
        + weights.entropy_signal * min(1.0, entropy_signal)
    )
    return min(1.0, round(score, 4))


def classify_score(score: float) -> str:
    if score >= 0.8:
        return "lockdown"
    if score >= 0.5:
        return "elevated"
    return "log"


class FrequencyTracker:
    """Per (container_id, syscall) sliding window count, normalized into a
    0-1 'frequency_factor' (section 2.5/2.6: rapid repeated syscalls raise
    the composite score; section 3.5 calls the same idea 'frequency spike').
    """

    def __init__(self, window_seconds: float = 5.0, spike_threshold: int = 20):
        self.window_seconds = window_seconds
        self.spike_threshold = spike_threshold
        self._history: Dict[Tuple[str, str], Deque[datetime]] = defaultdict(deque)

    def record_and_score(self, event: SyscallEvent) -> float:
        key = (event.container_id, event.syscall)
        timestamps = self._history[key]
        now = datetime.fromisoformat(event.timestamp)
        timestamps.append(now)
        cutoff = now - timedelta(seconds=self.window_seconds)
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
        return min(1.0, len(timestamps) / self.spike_threshold)


# ---------------------------------------------------------------------------
# Monitor orchestration
# ---------------------------------------------------------------------------

@dataclass
class ScoredSyscallEvent:
    event: SyscallEvent
    falco_matches: List[FalcoMatch]
    score: float
    classification: str  # log | elevated | lockdown

    def to_dict(self) -> Dict[str, object]:
        return {
            "event": self.event.to_dict(),
            "falco_matches": [m.to_dict() for m in self.falco_matches],
            "score": self.score,
            "classification": self.classification,
        }


def scored_event_from_dict(payload: Dict[str, object]) -> ScoredSyscallEvent:
    return ScoredSyscallEvent(
        event=_event_from_dict(payload["event"]),
        falco_matches=[FalcoMatch(**m) for m in payload.get("falco_matches", [])],
        score=float(payload["score"]),
        classification=str(payload["classification"]),
    )


class SyscallMonitor:
    def __init__(
        self,
        source: SyscallEventSource,
        rules: Sequence[FalcoRule] = DEFAULT_RULES,
        context: RuleContext = RuleContext(),
        weights: ScoringWeights = ScoringWeights(),
        frequency_tracker: Optional[FrequencyTracker] = None,
    ):
        self.source = source
        self.rules = rules
        self.context = context
        self.weights = weights
        self.frequency_tracker = frequency_tracker or FrequencyTracker()

    def run(self) -> Iterator[ScoredSyscallEvent]:
        for event in self.source.events():
            matches = evaluate_rules(event, self.rules, self.context)
            frequency_factor = self.frequency_tracker.record_and_score(event)
            score = score_event(event, matches, frequency_factor, weights=self.weights)
            yield ScoredSyscallEvent(event=event, falco_matches=matches, score=score, classification=classify_score(score))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

SELF_TEST_CONTEXT = RuleContext(
    allowed_paths=("/workspace", "/output"),
    allowed_binaries={"/workspace/bin/build.sh", "/usr/bin/mvn", "/usr/bin/java"},
    allowed_ips={"10.0.0.5"},
)


def run_self_test() -> List[ScoredSyscallEvent]:
    monitor = SyscallMonitor(SimulatedSyscallEventSource(), DEFAULT_RULES, SELF_TEST_CONTEXT)
    return list(monitor.run())


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 6 eBPF-pattern syscall monitor")
    parser.add_argument("--mode", choices=["simulate", "bpftrace"], default="simulate")
    parser.add_argument("--container-id", default="runner-0001")
    parser.add_argument("--cgroup", help="cgroup v2 path to scope bpftrace tracing to (bpftrace mode only)")
    parser.add_argument("--output", help="Optional path to write JSONL scored events")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        scored_events = run_self_test()
    else:
        source: SyscallEventSource
        if args.mode == "bpftrace":
            source = BpftraceSyscallEventSource(args.container_id, cgroup_path=args.cgroup)
        else:
            source = SimulatedSyscallEventSource(args.container_id)
        monitor = SyscallMonitor(source, DEFAULT_RULES, SELF_TEST_CONTEXT)
        scored_events = list(monitor.run())

    lines = [json.dumps(se.to_dict()) for se in scored_events]
    if args.output:
        Path(args.output).write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"Wrote {len(scored_events)} scored events to {args.output}")
    else:
        print("\n".join(lines))

    by_class: Dict[str, int] = defaultdict(int)
    for se in scored_events:
        by_class[se.classification] += 1
    print(f"\n{len(scored_events)} events: {dict(by_class)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
