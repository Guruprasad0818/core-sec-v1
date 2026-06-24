"""Stage 6 - Runtime Syscall Monitoring.

Real eBPF kernel tracing needs privileged kernel access (CAP_BPF/root) that
isn't available under Docker Desktop on Windows (or most unprivileged
container runtimes generally), so this still tries the genuine source first -
stage6/syscall_monitor.py's BpftraceSyscallEventSource, which works if this
ever actually runs on bare-metal Linux with bpftrace installed - and falls
back to LiveHybridEventSource below: a *continuous* generator that blends two
honest ingredients into the exact same SyscallEvent shape stage6/syscall_monitor.py
already defines:

  - real psutil observations of actually-running host processes: real PIDs,
    process names, and (when permission allows) real open file paths or
    network connections. Not fabricated.
  - periodically injected, clearly-synthetic malicious patterns (unauthorized
    /etc/shadow reads, unexpected shell spawns, suspicious egress, ptrace)
    reusing stage6/syscall_monitor.py's existing Falco rules and scoring
    matrix completely unmodified, so a real anomaly and a demo anomaly are
    scored identically by the same rule engine.

The result is exposed two ways from server/main.py:
  - GET /api/v1/stage/6          a snapshot (recent events + summary counts)
  - GET /api/v1/stage/6/stream   a continuous Server-Sent Events feed

Both read from the single RuntimeMonitorService below, which runs the
generation loop once in a background thread for the life of the process and
fans new events out to every connected SSE subscriber.
"""

from __future__ import annotations

import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, Iterator, List, Optional, Set

import psutil

from core.stage_loader import load_module

_sm = load_module("syscall_monitor")
SyscallEvent = _sm.SyscallEvent
SyscallEventSource = _sm.SyscallEventSource
SyscallMonitor = _sm.SyscallMonitor
DEFAULT_RULES = _sm.DEFAULT_RULES
RuleContext = _sm.RuleContext
BpftraceSyscallEventSource = _sm.BpftraceSyscallEventSource

MONITOR_CONTEXT = RuleContext(
    allowed_paths=("/workspace", "/output", "/app", "/usr", "/proc", "/sys", "C:\\"),
    allowed_binaries={"/usr/bin/python3", "/usr/local/bin/python", "node", "next-server"},
    allowed_ips={"127.0.0.1", "::1"},
)

# Deliberately-malicious demo patterns injected periodically into the
# otherwise-real telemetry stream. Same SyscallEvent shape real psutil-derived
# events use, so the Falco rule engine and scoring matrix downstream can't
# special-case them - they're scored exactly like a genuine detection would
# be. Never executed; these are just data describing what an attacker's
# syscalls would look like.
ANOMALY_PATTERNS: List[Dict[str, Any]] = [
    {"syscall": "openat", "args": {"path": "/etc/shadow"}, "comm": "sshd"},
    {"syscall": "openat", "args": {"path": "/etc/passwd"}, "comm": "cron"},
    {"syscall": "execve", "args": {"binary": "/bin/sh"}, "comm": "bash"},
    {"syscall": "execve", "args": {"binary": "/tmp/.hidden/payload"}, "comm": "sh"},
    {"syscall": "connect", "args": {"ip": "185.220.101.7", "port": "4444"}, "comm": "python3"},
    {"syscall": "ptrace", "args": {"request": "PTRACE_ATTACH"}, "comm": "gdb"},
]

ANOMALY_INJECTION_RATE = 8  # roughly 1 in N generated events is a synthetic anomaly
EVENT_INTERVAL_SECONDS = 0.4  # ~2.5 events/sec baseline pace
HISTORY_MAX = 200
RATE_WINDOW_SECONDS = 5.0


def _real_process_sample() -> Optional[psutil.Process]:
    pids = psutil.pids()
    if not pids:
        return None
    for _ in range(5):
        try:
            return psutil.Process(random.choice(pids))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def _event_from_real_process(proc: psutil.Process, container_id: str) -> Optional[Any]:
    """Synthesizes a SyscallEvent from genuinely live psutil data - real PID,
    real process name, and (when permitted) a real open file path or network
    connection. Falls back openat -> connect -> execve so something real is
    always available even when deeper introspection is permission-denied
    (the common case for other users' processes, especially on Windows)."""
    try:
        name = proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

    now = datetime.now(timezone.utc).isoformat()
    base: Dict[str, Any] = dict(
        event_id=str(uuid.uuid4()), timestamp=now, container_id=container_id,
        pid=proc.pid, tid=proc.pid, comm=name, return_code=0, uid=0, gid=0,
    )

    try:
        files = proc.open_files()
        if files:
            picked = random.choice(files)
            return SyscallEvent(**base, syscall="openat", args={"path": picked.path})
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        conns = proc.net_connections(kind="inet")
        remote = [c for c in conns if c.raddr]
        if remote:
            picked = random.choice(remote)
            return SyscallEvent(**base, syscall="connect", args={"ip": picked.raddr.ip, "port": str(picked.raddr.port)})
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    try:
        cmdline = " ".join(proc.cmdline()[:3]) or name
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        cmdline = name
    # Deliberately not "execve" here: this process was already running, not
    # freshly launched, so claiming execve would be inaccurate AND would
    # spuriously trip execve_not_whitelisted for every ordinary OS process on
    # a real desktop (none of which are in MONITOR_CONTEXT.allowed_binaries).
    # "socket" carries no Falco rule and a moderate criticality weight, so a
    # quiet observation stays "log" instead of flooding the demo with
    # false-positive "elevated" noise.
    return SyscallEvent(**base, syscall="socket", args={"process": cmdline})


def _synthetic_anomaly_event(container_id: str) -> Any:
    pattern = random.choice(ANOMALY_PATTERNS)
    now = datetime.now(timezone.utc).isoformat()
    pid = random.randint(20000, 60000)
    return SyscallEvent(
        event_id=str(uuid.uuid4()), timestamp=now, container_id=container_id,
        pid=pid, tid=pid, comm=pattern["comm"], syscall=pattern["syscall"],
        args=pattern["args"], return_code=0, uid=0, gid=0,
    )


class LiveHybridEventSource(SyscallEventSource):
    """Continuous (never-ending) event source - real psutil observations of
    the host, with synthetic attack patterns injected periodically so the
    demo always has interesting anomalies to show. See module docstring."""

    def __init__(self, container_id: str = "host-live-0001"):
        self.container_id = container_id
        self._tick = 0

    def events(self) -> Iterator[Any]:
        while True:
            self._tick += 1
            event = None
            if self._tick % ANOMALY_INJECTION_RATE == 0:
                event = _synthetic_anomaly_event(self.container_id)
            else:
                proc = _real_process_sample()
                if proc is not None:
                    event = _event_from_real_process(proc, self.container_id)
            if event is not None:
                yield event
            time.sleep(EVENT_INTERVAL_SECONDS)


@dataclass
class _Stats:
    total_events: int = 0
    anomalous_events: int = 0
    classification_counts: Dict[str, int] = field(default_factory=lambda: {"log": 0, "elevated": 0, "lockdown": 0})


class RuntimeMonitorService:
    """Owns the single continuous monitor loop (started once at app startup)
    and fans new events out to every connected SSE client via per-subscriber
    asyncio queues, plus keeps a bounded history for the snapshot endpoint."""

    def __init__(self) -> None:
        self.history: Deque[Dict[str, Any]] = deque(maxlen=HISTORY_MAX)
        self.stats = _Stats()
        self._subscribers: Set[Any] = set()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._loop: Optional[Any] = None
        self._recent_timestamps: Deque[float] = deque(maxlen=200)
        self.mode = "bpftrace" if BpftraceSyscallEventSource.available() else "simulated_hybrid"

    def _build_source(self) -> Any:
        if self.mode == "bpftrace":
            try:
                return BpftraceSyscallEventSource("host-0001")
            except Exception:
                pass
        return LiveHybridEventSource()

    def start(self, loop: Any) -> None:
        if self._thread is not None:
            return
        self._loop = loop
        monitor = SyscallMonitor(self._build_source(), DEFAULT_RULES, MONITOR_CONTEXT)
        self._thread = threading.Thread(target=self._run, args=(monitor,), daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self, monitor: Any) -> None:
        try:
            for scored in monitor.run():
                if self._stop.is_set():
                    return
                self._publish(scored)
        except Exception as exc:  # noqa: BLE001 - keep failures visible instead of dying silently
            print(f"[runtime_monitor] generation loop stopped: {exc}")

    def _publish(self, scored: Any) -> None:
        is_anomalous = scored.classification in ("elevated", "lockdown")
        payload = {**scored.to_dict(), "is_anomalous": is_anomalous}
        with self._lock:
            self.history.append(payload)
            self.stats.total_events += 1
            if is_anomalous:
                self.stats.anomalous_events += 1
            self.stats.classification_counts[scored.classification] = (
                self.stats.classification_counts.get(scored.classification, 0) + 1
            )
            self._recent_timestamps.append(time.monotonic())
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._fanout, payload)

    def _fanout(self, payload: Dict[str, Any]) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(payload)
            except Exception:  # noqa: BLE001 - a full/closed queue shouldn't break other subscribers
                pass

    def subscribe(self) -> Any:
        import asyncio

        q: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=200)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: Any) -> None:
        self._subscribers.discard(q)

    def events_per_second(self) -> float:
        now = time.monotonic()
        with self._lock:
            recent = [t for t in self._recent_timestamps if now - t <= RATE_WINDOW_SECONDS]
        return round(len(recent) / RATE_WINDOW_SECONDS, 2) if recent else 0.0

    def snapshot(self) -> Dict[str, Any]:
        # events_per_second() takes self._lock itself - compute it before
        # opening the lock again below, since Lock isn't reentrant.
        events_per_sec = self.events_per_second()
        with self._lock:
            return {
                "source": "live_runtime_monitor",
                "mode": self.mode,
                "events_per_sec": events_per_sec,
                "total_events": self.stats.total_events,
                "anomalous_events": self.stats.anomalous_events,
                "classification_counts": dict(self.stats.classification_counts),
                "recent_events": list(self.history)[-50:],
            }


monitor_service = RuntimeMonitorService()
