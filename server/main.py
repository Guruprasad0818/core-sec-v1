"""CBAD Pipeline API - FastAPI backend serving the 9-stage DevSecOps
telemetry that used to be rendered directly inside the Streamlit dashboard.

Run with (from the server/ directory):
    uvicorn main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, AsyncIterator, Dict

import bootstrap

bootstrap.bootstrap()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from aggregation import STAGE_META, build_overview
from compliance_engine import record_remediation, run_compliance_check
from entropy_monitor import run_entropy_scan
from git_info import get_live_git_info
from policy_gate import run_policy_gate
from remediation_engine import is_auto_fixable, remediate_finding
from risk_engine import compute_risk_trend
from runtime_monitor import monitor_service
from schemas import OverviewResponse, RemediateRequest, RemediateResponse, STAGE_RESPONSE_MODELS, StageMeta
from security_scanner import run_semgrep_scan
from supply_chain_monitor import run_supply_chain_check

from core import ingestion  # noqa: E402 - requires bootstrap() to have run first

app = FastAPI(title="CBAD Pipeline API", version="1.0.0")

_origins = os.environ.get("CBAD_CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 60s was fine for native filesystem access; under Docker Desktop on Windows
# the bind-mounted volume makes Semgrep's directory walk ~10x slower (see
# security_scanner.py's SCAN_TIMEOUT_SECONDS comment), so a short TTL would
# mean almost every overview/stage load re-triggers a ~90s rescan.
_CACHE_TTL_SECONDS = 300
_cache: Dict[int, tuple[float, Any]] = {}


def _warm_or_fresh(stage_num: int, fresh: Any) -> Any:
    now = time.monotonic()
    cached = _cache.get(stage_num)
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]
    return fresh()


def _compute_stage3() -> Any:
    # Stage 3 correlates Stage 1's git history with Stage 2's Semgrep
    # findings - reuse their cached results when still warm instead of
    # re-running the semgrep scan a second time within the same window.
    git_info = _warm_or_fresh(1, get_live_git_info)
    semgrep_result = _warm_or_fresh(2, run_semgrep_scan)
    return compute_risk_trend(git_info, semgrep_result)


def _compute_stage4() -> Any:
    # Stage 4 is the remediation center for Stage 2's findings - same
    # warm-cache reuse as Stage 3, so loading the overview doesn't trigger
    # three independent semgrep scans back to back.
    semgrep_result = _warm_or_fresh(2, run_semgrep_scan)
    findings = semgrep_result.get("findings", [])
    remediable = [{**f, "is_auto_fixable": is_auto_fixable(f["finding_id"])} for f in findings]
    return {
        "source": "live_remediation_center",
        "remediable_findings": remediable,
        "fixable_count": sum(1 for f in remediable if f["is_auto_fixable"]),
        "total_count": len(remediable),
    }


def _compute_stage5() -> Any:
    # Live entropy/secrets scan over the whole repo (entropy_monitor.py)
    # supersedes ingestion.load_stage5's entropy half, which only covered
    # stage1../stage9/ and fell back to a fixture if that came up empty. The
    # SLSA attestation half is untouched - still sourced from ingestion, just
    # discarding the entropy half it also computes internally.
    slsa_block = ingestion.load_stage5()["slsa"]
    return {"entropy": run_entropy_scan(), "slsa": slsa_block}


def _compute_stage7() -> Any:
    # Stage 7 maps Stage 2/5/6's live findings onto OWASP Top 10 and SOC 2
    # CC6.1/CC6.3 (compliance_engine.py) - reuse their cached results when
    # still warm, same pattern as Stage 3/4/5, instead of re-running the
    # semgrep/entropy scans a second time within the same window. Stage 6's
    # snapshot is never cached (see _UNCACHED_STAGES) so this always reads
    # current runtime telemetry.
    semgrep_result = _warm_or_fresh(2, run_semgrep_scan)
    entropy_result = _warm_or_fresh(5, _compute_stage5)
    runtime_result = _warm_or_fresh(6, monitor_service.snapshot)
    return run_compliance_check(semgrep_result, entropy_result, runtime_result)


def _compute_stage8() -> Any:
    # Stage 8 attests the SBOM built from server/requirements.txt +
    # frontend/package.json (supply_chain_monitor.py), tagging the
    # provenance with the current commit - reuse Stage 1's warm git info
    # instead of shelling out to git a second time within the same window.
    git_info = _warm_or_fresh(1, get_live_git_info)
    commit = git_info.get("commits", [{}])[0].get("hash", "unknown")
    return run_supply_chain_check(commit)


def _compute_stage9() -> Any:
    # Stage 9 is the terminal Go/No-Go gate over Stage 2/5/7/8's live
    # results (policy_gate.py) - reuse their cached results when still warm,
    # same pattern as every other cross-stage computation in this file.
    # Nothing downstream depends on Stage 9 itself, so there's no further
    # fan-out to coordinate past this point.
    semgrep_result = _warm_or_fresh(2, run_semgrep_scan)
    entropy_result = _warm_or_fresh(5, _compute_stage5)
    compliance_result = _warm_or_fresh(7, _compute_stage7)
    supply_chain_result = _warm_or_fresh(8, _compute_stage8)
    return run_policy_gate(semgrep_result, entropy_result, compliance_result, supply_chain_result)


STAGE_LOADERS = {
    1: get_live_git_info,  # live git log, not the persisted-hook-artifact ingestion.load_stage1
    2: run_semgrep_scan,  # live Semgrep vulnerability scan, not the persisted-hook DGT scoring
    3: _compute_stage3,  # live commit/vulnerability risk correlation, not the CVE ensemble predictor
    4: _compute_stage4,  # live one-click remediation center, not the SAST taint-tracking engine
    5: _compute_stage5,  # live entropy/secrets scan, not the STAGE_SOURCE_DIRS-only ingestion.load_stage5
    6: monitor_service.snapshot,  # live runtime syscall monitor, not the persisted-hook self-test
    7: _compute_stage7,  # live compliance mapping (OWASP/SOC2), not the Cosign/K8s-admission demo
    8: _compute_stage8,  # live SBOM + SLSA attestation + signing, not the DAST/attack-planner demo
    9: _compute_stage9,  # live Go/No-Go policy gate, not the SBOM/CVE-exposure + OPA router demo
}

# Stage 6's snapshot is a cheap in-memory read of an always-running
# background monitor - caching it would mean "live" telemetry going stale
# for up to _CACHE_TTL_SECONDS, defeating the point.
_UNCACHED_STAGES = {6}


async def _cached_load(stage_num: int) -> Any:
    if stage_num in _UNCACHED_STAGES:
        return await run_in_threadpool(STAGE_LOADERS[stage_num])
    now = time.monotonic()
    cached = _cache.get(stage_num)
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]
    # Stage loaders can block (Stage 2 shells out to the semgrep CLI and
    # waits on it) - run them in a worker thread so the event loop, and
    # therefore every other concurrent request, stays responsive.
    data = await run_in_threadpool(STAGE_LOADERS[stage_num])
    _cache[stage_num] = (now, data)
    return data


async def _safe_load(stage_num: int) -> tuple[Any, str | None]:
    try:
        return await _cached_load(stage_num), None
    except Exception as exc:  # noqa: BLE001 - surface any stage failure in the API, don't crash the request
        return None, str(exc)


@app.on_event("startup")
async def _start_runtime_monitor() -> None:
    # Stage 6 streams continuously regardless of whether any client is
    # connected - one background thread generates events for the lifetime of
    # the process, fanning out to SSE subscribers as they come and go.
    monitor_service.start(asyncio.get_event_loop())


@app.get("/api/v1/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/stages", response_model=list[StageMeta])
def list_stages() -> list[StageMeta]:
    return [StageMeta(stage=n, key=f"stage{n}", title=title) for n, title in STAGE_META.items()]


@app.get("/api/v1/overview", response_model=OverviewResponse)
async def overview() -> OverviewResponse:
    results: Dict[int, Any] = {}
    errors: Dict[int, str] = {}
    for n in STAGE_LOADERS:
        data, err = await _safe_load(n)
        if err:
            errors[n] = err
        else:
            results[n] = data
    return build_overview(results, errors)


@app.get("/api/v1/stage/{stage_num}")
async def get_stage(stage_num: int):
    if stage_num not in STAGE_LOADERS:
        raise HTTPException(status_code=404, detail=f"Unknown stage {stage_num}; valid range is 1-9")

    data, err = await _safe_load(stage_num)
    if err:
        raise HTTPException(status_code=502, detail=f"Stage {stage_num} loader failed: {err}")

    model = STAGE_RESPONSE_MODELS[stage_num]
    return model.model_validate(data)


@app.get("/api/v1/stage/6/stream")
async def stream_stage6() -> StreamingResponse:
    queue = monitor_service.subscribe()

    async def event_generator() -> AsyncIterator[str]:
        try:
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(payload)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"  # SSE comment line - keeps idle connections/proxies alive
        finally:
            monitor_service.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/v1/stage/4/remediate", response_model=RemediateResponse)
async def remediate(payload: RemediateRequest) -> RemediateResponse:
    semgrep_result = await run_in_threadpool(_warm_or_fresh, 2, run_semgrep_scan)
    lookup = {f["instance_id"]: f for f in semgrep_result.get("findings", [])}

    try:
        result = await run_in_threadpool(remediate_finding, payload.instance_id, lookup)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if result["status"] == "committed":
        # The working tree changed (new branch checked out + file patched) -
        # every stage derived from it must be rescanned on next load. Stage
        # 4's only auto-fix category rewrites a hardcoded secret into an env
        # var placeholder, which can also resolve a Stage 5 entropy finding
        # on the same line, a Stage 7 compliance control derived from it,
        # Stage 8's provenance, which is tagged with the commit hash that
        # just changed (a new commit was made even though dependencies
        # themselves didn't), and Stage 9's gate verdict, which is entirely
        # derived from Stages 2/5/7/8.
        _cache.pop(2, None)
        _cache.pop(3, None)
        _cache.pop(4, None)
        _cache.pop(5, None)
        _cache.pop(7, None)
        _cache.pop(8, None)
        _cache.pop(9, None)
        await run_in_threadpool(record_remediation, result)

    return RemediateResponse(**result)


@app.post("/api/v1/cache/clear")
def clear_cache() -> Dict[str, str]:
    _cache.clear()
    return {"status": "cleared"}
