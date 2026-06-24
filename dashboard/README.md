# CBAD Pipeline Dashboard

A single-pane-of-glass Streamlit dashboard for the 9-stage CBAD DevSecOps
pipeline (`stage1/` - `stage9/`). It is a thin presentation layer: every
stage's actual Python module is imported and called directly (the dashboard
ships no duplicated business logic), and the JSON/JSONL schemas it renders
match exactly what each stage's own CLI produces.

## What it shows

| Page | Stage source | Content |
|---|---|---|
| Overview | all stages | Unified security posture, critical-finding counts, findings-volume chart, combined high-severity table |
| Stage 1 | `cbad_feature_collector.py`, `local_feature_store.py` | Persisted pre-commit/pre-push behavioral feature payloads, plus a "run live collector" button |
| Stage 2 | `dgt_engine.py`, `quarantine_manager.py` | Dependency trust scores, quarantine/block/review/allow summary |
| Stage 3 | `cve_predictor.py`, `predict_risk.py` | CVE risk score/band from the trained XGBoost ensemble, feature contributions |
| Stage 4 | `sast_engine.py`, `claude_verifier.py` | Active taint paths (source -> sink), Claude verifier output, suggested fixes |
| Stage 5 | `entropy_scanner.py`, `slsa_attestor.py` | High-entropy secret findings, SBOM/provenance/transparency-log attestation status |
| Stage 6 | `syscall_monitor.py`, `mitigation_engine.py` | Scored/blocked syscall events, Falco rule hits, mitigation decisions and audit log |
| Stage 7 | `cosign_wrapper.py`, `k8s_admission_validator.py` | Keyless signing + Rekor transparency log, Kubernetes admission validation log |
| Stage 8 | `interface_ingestor.py`, `llm_attack_planner.py` | Ingested OpenAPI surface, generated/validated/executed attack plans |
| Stage 9 | `opa_event_router.py`, `sbom_monitor.py` | SBOM CVE exposure findings, Guardian event routing + evidence archive |

## How data gets in (ingestion strategy)

`core/ingestion.py` has one `load_stageN()` function per stage. Each one
tries, in order:

1. **Persisted artifacts** the stage already writes to a fixed path when run
   from its own CLI, e.g.:
   - `.git/cbad/features/*.json` (Stage 1)
   - `stage5/attestation_artifacts/{sbom,provenance,transparency_log}.json*`
   - `stage6/mitigation_artifacts/audit_log.jsonl`
   - `stage7/rekor_sim_artifacts/log.jsonl`
   - `stage9/evidence_artifacts/archive.jsonl`
2. **A live, read-only call into the stage's real Python API** against this
   repository - e.g. Stage 4/5 scan the actual `stage1/`-`stage9/` source
   tree for taint findings and secrets; Stage 2 scores the real
   `requirements.txt`/`package.json` if present.
3. **The stage module's own `run_self_test()` fixture** as a last resort,
   only when no real artifact or live target is available (e.g. Stage 6's
   syscall stream has no real eBPF/bpftrace source on a dev machine, so it
   uses the module's built-in `SimulatedSyscallEventSource`).

Every page tells you which of these three applies via a "Source: ..." caption
so you never mistake demo data for a real finding.

### Feeding it real pipeline runs

To see your own pipeline output instead of the built-in fixtures, just run the
stage CLIs as normal and the dashboard will pick the files up automatically
on next refresh (no restart needed - results are cached for 60s):

```bash
# Stage 5: writes stage5/attestation_artifacts/*
python stage5/slsa_attestor.py attest --artifact dist/app.jar --output-dir stage5/attestation_artifacts ...

# Stage 6: writes stage6/mitigation_artifacts/audit_log.jsonl as events are handled
python stage6/mitigation_engine.py --events scored_events.jsonl

# Stage 9: writes stage9/evidence_artifacts/archive.jsonl as events are routed
python stage9/opa_event_router.py --events events.jsonl
```

You can also feed Stage 3 (upload repo metadata JSON) and Stage 8 (upload an
OpenAPI spec) directly from their dashboard pages via file-upload widgets, and
Stage 2 automatically scores your real `requirements.txt`/`package.json` from
the repo root if one exists.

## Running locally

```bash
cd dashboard
pip install -r requirements.txt
streamlit run app.py
```

Open http://localhost:8501. The app reads `core/stage_loader.py:REPO_ROOT`
(two directories up from `dashboard/app.py`) to locate `stage1/`-`stage9/`,
so no extra configuration is needed if you keep the standard repo layout.

Requirements: Python 3.10+, and `git` on `PATH` if you want to use the Stage 1
"run live collector" button (it shells out to `git`).

## Running with Docker

The Dockerfile must be built with the **repository root** as build context
(not `dashboard/`), because the dashboard imports sibling modules from every
`stageN/` directory. `docker-compose.yml` already does this for you:

```bash
cd dashboard
docker compose up --build
```

This builds the image from the repo root, mounts the whole repository
read-write into the container (so newly written artifacts such as
`stage6/mitigation_artifacts/audit_log.jsonl` show up without a rebuild), and
serves the dashboard at http://localhost:8501.

To build/run without compose:

```bash
# from the repo root
docker build -f dashboard/Dockerfile -t cbad-dashboard .
docker run -p 8501:8501 -v "$(pwd):/app" cbad-dashboard
```

Note: without the `-v` volume mount, the container only has the snapshot of
the repo copied in at build time, and the Stage 1 live-collector button won't
have a `.git` directory to inspect (everything else still works from the
self-test/repo-scan fallbacks).

## Project layout

```
dashboard/
  app.py                 # Overview / unified posture page
  pages/                 # One Streamlit page per stage (1-9)
  core/
    stage_loader.py       # sys.path bootstrap so `import sast_engine` etc. resolve
    ingestion.py           # load_stage1..load_stage9 - the data ingestion layer
    utils.py                # JSON-safe conversion + JSON/JSONL file readers
  requirements.txt
  Dockerfile
  docker-compose.yml
```
