# CBAD DevSecOps Pipeline

A 9-stage security pipeline (`stage1/` .. `stage9/`) with two independent UI options on top of the same telemetry:

- **`server/` + `frontend/`** - decoupled FastAPI backend + Next.js/Tailwind frontend (recommended).
- **`dashboard/`** - the original all-in-one Streamlit app. Still fully functional; kept as a fallback/reference.

Both UIs read the exact same on-disk pipeline artifacts via `dashboard/core/ingestion.py` - nothing in `stage1/` through `stage9/` was changed.

## Architecture

```
stage1/ .. stage9/      pipeline engines (unchanged)
dashboard/core/         ingestion.py + stage_loader.py - reads stage artifacts, no UI framework dependency
server/                 FastAPI app - imports dashboard/core/ingestion.py, exposes it as JSON
frontend/               Next.js (App Router) + Tailwind - consumes the API
dashboard/              original Streamlit app (independent, untouched)
```

`server/` never duplicates the stage-loading logic - `server/bootstrap.py` puts `dashboard/` on `sys.path` and imports `core.ingestion` directly, the same module the Streamlit app uses.

## Option A: FastAPI + Next.js (recommended)

### Run locally (no Docker)

**Backend:**
```bash
cd server
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```
Verify: `curl http://localhost:8000/api/v1/health` -> `{"status":"ok"}`

**Frontend** (separate terminal):
```bash
cd frontend
npm install
cp .env.local.example .env.local   # NEXT_PUBLIC_API_BASE=http://localhost:8000
npm run dev
```
Open http://localhost:3000.

### Run with Docker Compose

```bash
docker compose up --build
```
This builds and starts:
- `backend` on http://localhost:8000 - the whole repo root is bind-mounted read-write into the container (`./:/app`) so GitPython (Stage 1) and Semgrep (Stage 2/3/4) always see the host's live `.git` history and working tree, with no rebuild needed after editing any stage's code.
- `frontend` on http://localhost:3000 - runs `next dev` (not a production build) inside the container, with `./frontend` bind-mounted for hot reload on source edits. `node_modules`/`.next` are excluded from that mount via anonymous volumes so the container's own Linux-built copies aren't shadowed by the host's.

> **Two different API base URLs are in play.** The frontend container's own Next.js process (Server Components doing the initial page fetch) runs *inside* the Docker network and reaches the backend at `http://backend:8000` (`INTERNAL_API_BASE`, resolved via Docker's internal service-name DNS). The browser rendering that page runs on your host machine, outside that network, and calls the backend at `http://localhost:8000` (`NEXT_PUBLIC_API_BASE`, the port published to the host) for client-side actions like Stage 4's Remediate button. Both are set as plain runtime environment variables in `docker-compose.yml` - no build-time ARG juggling needed since the frontend container runs the dev server rather than a prebuilt production bundle.

### API surface

| Endpoint | Description |
|---|---|
| `GET /api/v1/health` | Liveness check |
| `GET /api/v1/stages` | List of the 9 stage IDs + titles |
| `GET /api/v1/overview` | Aggregated KPIs, stage health, risk breakdown, top findings (same computation `dashboard/app.py` used to do) |
| `GET /api/v1/stage/{1..9}` | Raw data for one stage, validated against the Pydantic schema in `server/schemas.py` |
| `GET /api/v1/stage/6/stream` | Server-Sent Events feed of Stage 6's live runtime syscall telemetry (`server/runtime_monitor.py`) |
| `POST /api/v1/cache/clear` | Clears the in-memory response cache |

Interactive docs: http://localhost:8000/docs

### Frontend structure

- `app/page.tsx` - overview dashboard (KPI cards, stage health grid, trend/risk charts, top findings)
- `app/stage/[num]/page.tsx` - generic stage detail page: auto-detects list-shaped fields in the stage's JSON and renders each as a dense TanStack Table grid (with severity-aware coloring when a recognizable severity column is present), falling back to a raw JSON viewer for anything non-tabular. This one template covers all 9 stages rather than 9 bespoke hand-built pages, since each stage engine returns a different shape - see `server/schemas.py`'s module docstring for the same reasoning on the API side.
- `components/ui/` - hand-authored shadcn-style primitives (Card, Badge, Button) - no shadcn CLI dependency, just the same convention (Tailwind + `class-variance-authority` + `cn()`)
- `components/data-grid.tsx` - TanStack Table-based high-density grid
- `components/charts/` - Recharts trend area + stacked risk bar, styled with the steel/crimson/amber palette
- `lib/risk.ts` - TypeScript port of `server/risk.py`'s severity classification (keep both in sync if the vocabulary changes)

**Known trade-off:** `npm audit` reports a residual moderate advisory in Next.js's own bundled copy of `postcss` (XSS via unescaped `</style>` in CSS stringification). It only matters for apps that interpolate untrusted CSS at runtime, which this app does not do; the suggested "fix" is a major Next.js downgrade that would break the App Router APIs in use, so it's accepted as-is.

## Option B: Streamlit (`dashboard/`)

Unchanged - see `dashboard/Dockerfile` / `dashboard/docker-compose.yml`, or:
```bash
cd dashboard
pip install -r requirements.txt
streamlit run app.py
```

## What's intentionally out of scope

- **Kafka/Zookeeper**: no stage currently produces/consumes from a broker (only mentioned in stage docs), so the compose file doesn't stand up empty containers for it. Add them when a stage actually streams events.
- **9 bespoke stage pages**: the frontend uses one generic, data-driven stage template instead (see above) given how differently shaped each stage's payload is.
