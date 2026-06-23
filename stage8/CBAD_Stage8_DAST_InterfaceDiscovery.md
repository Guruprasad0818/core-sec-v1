# CBAD Stage 8 — AI-Driven DAST: Interface Discovery & State Machine Mapping

## SECTION 1 — Interface Discovery & State Machine Mapping

### 1.1 Objective
Design an automated engine that programmatically ingests API specifications (OpenAPI/Swagger), live service introspection, and UI crawling artifacts to build a comprehensive State Machine model of the target application. The State Machine is used by later DAST orchestration to plan authenticated flows, detect logic vulnerabilities, and generate AI-guided attack sequences.

### 1.2 High-level architecture
Components:
- `Spec Ingestor`: accepts OpenAPI/Swagger (v2/v3), AsyncAPI, GraphQL schema and normalizes into an internal API graph
- `Live Recon Collector`: active probes, HTTP probing, link extraction, and headless-browser crawl (Playwright) to discover undocumented endpoints and UI-driven flows
- `Auth Context Analyzer`: identifies authentication schemes (API key, Bearer/JWT, OAuth2 flows, cookie sessions, SAML) and maps how tokens/credentials are acquired and used
- `Schema Resolver`: normalizes request/response schemas (JSON Schema), parameter types, and required/optional fields
- `State Machine Constructor`: converts API graph + auth flows + resource models into a directed state machine (nodes=states, edges=transitions)
- `Constraint Solver/Parameter Suggester`: fills form fields and constructs valid payloads using type inference, semantic models, and sample value generation
- `Delta Monitor`: compares live responses across runs to identify side-effecting endpoints and idempotency
- `Planner/Orchestrator`: plans attack sequences using the state model, test harness, and AI guidance
- `Telemetry & Evidence Store`: stores discovered states, transitions, examples, and response snapshots

### 1.3 Normalizing OpenAPI and live discovery
- Parse OpenAPI into canonical Operation objects: (method, path, parameters, requestBody schema, responses)
- Convert path templates into graph nodes: `/users/{id}` yields a resource node `User(id)` and transitions like `GET /users/{id}` (read), `PUT /users/{id}` (update)
- Live discovery augments spec parsing: probe for 401/403 -> attempt auth; follow HATEOAS links and Link headers; expose undocumented endpoints discovered by fuzzing or UI
- Use heuristics to collapse semantically equivalent endpoints (aliasing) and mark canonical resource representations

### 1.4 Authentication & session modeling
- Detect auth types from spec/securitySchemes and runtime headers/cookies
- Model token acquisition as state transitions: e.g., `START -> (POST /auth/login with creds) -> AUTHENTICATED(token)`
- Represent scope/claim constraints (OAuth scopes, role claims) as state attributes that gate transitions
- For OAuth flows, model both authorization code and client_credentials flows including redirect/callback states
- For JWTs, extract claims (exp, scope, subject) and model token refresh/expiry transitions

### 1.5 State Machine formal model
- Define state S = (auth_context, resource_snapshot, session_cookies, csrf_tokens, ephemeral_nonce_values)
- Define transition T: S -> S' triggered by Operation O with parameter vector P and producing observation R
- Maintain transition metadata: preconditions, side-effects, idempotency hints, taint sources, and success/failure conditions
- State graph G = (S_nodes, T_edges). Annotate edges with cost (time/complexity), confidence, and required capabilities (auth role, token)

### 1.6 Constructing transitions from operations
- For each Operation O in the API graph:
  - enumerate parameter spaces: path params, query params, header params, body fields
  - generate symbolic parameter templates and concrete example vectors via the Constraint Solver
  - issue dry-run probes to observe response codes, location headers, set-cookie, and side-effects (resource creation)
  - annotate edge T with observed response semantics (201 created, 204 no-content, 4xx error)

### 1.7 Constraint solving and payload generation
- Use type-driven generators for primitives (integers, strings, dates) and structure-driven generators for objects
- Integrate sample-based seeding: use example values in OpenAPI, observed live values, and project-level baselines
- Use small SMT/constraint-solver (Z3) for complex field constraints (e.g., ranges, regex, conditional fields) when available
- Use AI-assisted suggestions for semantic fields (e.g., email-like values, usernames) and for crafting potentially dangerous inputs (SQL-like strings, path traversal payloads)

### 1.8 Modeling side-effects and idempotency
- Track resource creation endpoints: operations returning 201 with Location or resource IDs are marked as state-mutating
- Use Delta Monitor: after executing O, compute diff between resource representations or list responses to assert creation/deletion
- Record idempotency tokens and retry semantics; model retry transitions explicitly

### 1.9 Handling UI-driven workflows
- Use headless browser (Playwright) to capture sequences of DOM events and API calls triggered by frontend
- Map UI actions to API operations by intercepting XHR/fetch and correlating network calls to state transitions
- Extract CSRF tokens, dynamic parameters, and client-side calculations to include in the state model

### 1.10 Dealing with non-determinism and flakiness
- Run repeated probes to compute response stability scores; mark edges with `stability` metric
- For flaky endpoints, capture multiple sample responses and attempt to canonicalize resource representations
- Use confidence thresholds to avoid polluting the state graph with low-confidence transitions

### 1.11 Graph pruning and abstraction
- To maintain tractability, apply these reductions:
  - merge states that are observationally equivalent up to canonical fields
  - collapse repetitive cycles that do not introduce new capabilities
  - limit parameter combinatorics using prioritized sampling (boundary values, common inputs, AI-suggested risky inputs)

### 1.12 Attack-plan generation using the State Machine
- Given goal G (e.g., privilege escalation, IDOR, business-logic bypass), compute a minimal-cost path through G from initial state to goal state using A* or Dijkstra with heuristics favoring high-impact transitions
- Planner considers authenticated context upgrades, token exchanges, CSRF bypass steps, and chained operations
- Integrate fuzzing nodes where a transition has a high `vulnerability-likelihood` score

### 1.13 Data structures and algorithms (sketch)
- Operation: {id, method, path_template, params[], request_schema, response_schemas[]}
- State: {id, auth, resource_map, session_tokens, attrs}
- Transition: {from_state, to_state, operation, param_vector, observed_response, cost, confidence}

Pseudocode: building a transition

```
for op in operations:
  for sample in constraint_solver.gen_samples(op):
    resp = http_client.call(op, sample, auth_context)
    new_state = extract_state(resp)
    record_transition(current_state, new_state, op, sample, resp)
```

### 1.14 Scaling and distributed discovery
- Partition discovery by API surface: host, route prefix, or microservice
- Run parallel headless browser instances and collectors; central coordinator merges state graphs using canonical digesting and deduplication
- Use incremental discovery: persist state graphs and run delta probes to discover changes over time

### 1.15 Instrumentation, telemetry, and evidence
- Store canonical request/response pairs, full HARs for UI sessions, and screenshots for sequences involving anti-bot challenges
- Annotate each transition with provenance (spec/scan/timestamp/agent) and hash to support reproducible testing

### 1.16 Security & ethical controls
- Rate-limit automated probes, respect robots.txt and legal boundaries, and require explicit authorization for authenticated scans
- Mask or redact PII in stored artifacts; follow compliance for sensitive environments

### 1.17 Summary
This design produces a deterministic, extensible State Machine model that integrates spec-driven parsing, live discovery, UI-driven mapping, and constraint solving to enable goal-directed DAST orchestration. Next steps: implement `Spec Ingestor` and `State Machine Constructor` prototypes, and connect a lightweight Planner to verify pathfinding and control generation.

## SECTION 2 — LLM Attack Planner & Logical Payloads

### 2.1 Intent and safety boundaries
- Purpose: use an LLM to synthesize high-level, multi-step test plans that exercise business-logic abuse cases (authorization bypasses, IDOR, TOCTOU, parameter manipulation) for defensive testing in fully authorized, sandboxed environments.
- Safety rules (must be enforced by orchestration):
  - The LLM must not produce exploit code, executable payloads, or step-by-step instructions that can be executed against production systems.
  - Output is strictly a structured, abstract plan (JSON) with placeholders and semantic actions only.
  - All plans require human review and explicit approval before any automated concrete test generation or execution.

### 2.2 Architecture
- `LLM Planner`: prompts an LLM to produce structured, non-executable plans.
- `Plan Validator`: enforces safety policies (deny any output containing code-like tokens, URLs, or direct payloads).
- `Placeholder Resolver`: maps abstract placeholders to safe test values or to a sandboxed data store used by the execution harness.
- `Execution Harness` (optional, in staging only): consumes validated plans and executes concrete tests against isolated environments; retains human-in-the-loop gating.
- `Audit & Governance`: logs prompts, LLM outputs, approvals, and execution metadata in immutable storage.

### 2.3 System prompt templates (defensive and non-actionable)
System prompt (example, instructive and restrictive):

"You are a defensive testing assistant. When asked to generate adversarial test plans, output ONLY a JSON structure describing goals, abstract actions, and placeholders. DO NOT include executable code, specific exploit strings, or step-by-step commands. Each action must be described at a high level (verb + intent) and include a `placeholders` array for values. Example output schema: {\"goal\":..., \"preconditions\":..., \"actions\":[{\"type\":...,\"description\":...,\"placeholders\":[...] }], \"risk_level\":... }."

User prompt (example):
"Generate a defensive test plan that attempts to find authorization bypass logic for the `GET /orders/{id}` endpoint; do not include exploit strings or runnable payloads. Use placeholders for user identities and request headers. Output JSON only."

### 2.4 Expected JSON schema (non-actionable)

{
  "goal": "string",              // high-level test intent
  "preconditions": ["string"],  // required auth or state
  "actions": [                    // abstract action list
    {
      "id": "string",
      "type": "ModifyParam|Replay|RaceAttempt|AuthElevation|Sequence",
      "description": "string (high-level, no code)",
      "placeholders": ["<OTHER_USER_ID>", "<SESSION_TOKEN>"],
      "safety_level": "low|medium|high"
    }
  ],
  "evidence_requirements": ["string"],
  "risk_level": "low|medium|high"
}

### 2.5 Example safe plan (sanitized)

{
  "goal": "Authorization check for GET /orders/{id}",
  "preconditions": ["Authenticated as user A", "Order resource exists for user B"],
  "actions": [
    {"id":"a1","type":"ModifyParam","description":"Submit request for orderId belonging to another user to see if access is denied","placeholders":["<OTHER_USER_ID>"],"safety_level":"medium"},
    {"id":"a2","type":"Sequence","description":"Authenticate as user A then call GET /orders/<OTHER_USER_ID> while observing response codes and headers","placeholders":["<OTHER_USER_ID>","<AUTH_TOKEN_A>"],"safety_level":"medium"}
  ],
  "evidence_requirements": ["HTTP status code","response body size","authorization header presence"],
  "risk_level":"medium"
}

### 2.6 Plan validation and enforcement (scripting patterns)
- Validation checks (examples, non-executable descriptions):
  - Deny outputs containing code-like sequences (e.g., backticks with shell snippets, `eval(`, raw SQL keywords inside quotes) or direct exploit payloads.
  - Ensure each action is abstract (no `curl`, `wget`, or exact HTTP lines) and contains placeholders rather than concrete sensitive data.
  - Require that `safety_level` <= allowed level for automated execution; else human approval required.

Pseudocode for enforcement flow:

1. prompt = build_system_prompt() + user_input
2. raw_output = call_llm(prompt)
3. if contains_forbidden_tokens(raw_output): reject and log
4. plan = parse_json(raw_output)
5. if not validate_schema(plan): reject and log
6. persist_plan(plan)
7. send_for_human_review_if_required(plan)

### 2.7 Mapping abstract actions to safe test harness
- The Execution Harness translates abstract actions to concrete test cases only inside an isolated staging environment:
  - `ModifyParam` -> issue a parametrized request using test data store values (no production data)
  - `RaceAttempt` -> spin two concurrent requests in a controlled sandbox with idempotent rollback
  - `AuthElevation` -> attempt role-based transitions using test-role accounts only
- All concrete values are generated by the Placeholder Resolver which ensures values are synthetic or belong to a secure test dataset; no production secrets are used.

### 2.8 Explainability and audit
- For each plan, capture LLM prompt, model version, response, validation logs, human approver ID, and execution results. Store in immutable audit logs for compliance and incident post-mortem.

### 2.9 Summary
This LLM-driven planner produces defensively-scoped, non-actionable test plans that accelerate logical vulnerability discovery while enforcing strict safety, governance, and human-in-the-loop controls.

## SECTION 3 — Chaos Security Injection & Canary Token Validation

### 3.1 Goals
- Introduce controlled chaos experiments (latency, error injection, resource contention) targeted at JVM services to exercise resilience and detect timing/race vulnerabilities relevant to TOCTOU and business-logic races.
- Seed and monitor Canary Tokens (synthetic PII placeholders) to detect unintended data flows or exfiltration attempts during tests.

### 3.2 Chaos for JVM (CMJ) injection patterns (defensive)
- Injection types (applied in staging only):
  - `Latency`: inject artificial thread sleeps or network latency in specific service layers to exercise timing windows
  - `Exception`: force selected methods to throw recoverable exceptions to exercise error handling
  - `ResourceSpike`: temporarily restrict heap or CPU to observe degraded behaviors
  - `Failpoint`: activate application-level failpoints (if instrumented) to simulate partial failures
- Implementation approach:
  - Use a controlled CMJ agent or lightweight instrumentation hooks that operate under authorization and RBAC
  - Orchestrate experiments via a central controller that schedules experiments with TTL and rollback hooks
  - Ensure experiments are idempotent and reversible; run only against cloned staging environments or blue-green test clusters

### 3.3 Canary token design & placement
- Canary tokens are synthetic, unique markers (e.g., fake email, document ID) placed in test datasets and SBOMs. Each token has a unique identifier and monitoring webhook URL to receive hits.
- Placement strategies:
  - Embedded in sample user records in staging DBs
  - Included as fields in SBOM or configuration files used by the build process
  - Planted as dummy credentials in low-privilege test accounts
- Canary generation policy:
  - Per-experiment unique tokens with metadata (experiment_id, placement_path)
  - Short TTLs and rotation per experiment

### 3.4 Detection & alerting pipeline
- A lightweight receiver service collects canary hits (via webhook or pull logs) and correlates with experiment context.
- On detection:
  - enrich event with Pod/Node metadata, experiment_id, and recent DAST activity
  - if event occurs during an active chaos experiment, mark as `expected` and store evidence; if outside scheduled testing, escalate as potential compromise
  - capture request metadata (source IP, headers, payload snippet) and store in secure evidence store

### 3.5 Orchestration model
- Controller responsibilities:
  - Schedule experiment timeline, target JVM services, and define injection vectors and canary placements
  - Maintain experiment state machine: `planned -> running -> completed -> verified`
  - Enforce prechecks: snapshot baseline metrics, notify stakeholders, and ensure rollback paths
- Execution steps (high-level):
  1. provision test canaries and record mapping
  2. snapshot environment and baseline metrics
  3. run CMJ experiment for configured duration
  4. monitor canary receiver and DAST telemetry for hits
  5. collect evidence and revert instrumentation
  6. produce a report with findings and recommended mitigations

### 3.6 Integration with DAST State Machine
- When a canary triggers unexpectedly during a DAST plan execution, correlate the state-machine path that led to the canary access and include it as evidence for reproducing the event.
- Use the DAST planner to generate follow-up sequences that confirm whether access was accidental, authorized, or exploitable.

### 3.7 Safety, governance, and compliance
- Authorize experiments via the Multi-Party Approval Workflow (Stage 7) before execution.
- Require auditable experiment manifests and TTLs; automatically revoke tokens and scrub test data after completion.

### 3.8 Example orchestration snippet (pseudocode)

```yaml
# experiment manifest (illustrative)
experiment_id: cmj-2026-06-23-01
target_service: orders-service-staging
injections:
  - type: latency
    target: com.company.orders.PaymentProcessor.process()
    delay_ms: 200
    ttl: 300
canaries:
  - token: CTKN-abc123
    placement: db.users.test_user_42.email
    webhook: https://canary-receiver.company.com/hit
approval_required: true
```

### 3.9 Incident handling and post-test verification
- If a canary fires unexpectedly outside test windows, trigger incident lockdown (Stage 5) and capture forensic artifacts.
- Post-test: run automated validators against gathered evidence and produce remediation tickets for developers if findings indicate logic flaws or data-leakage risks.

### 3.10 Summary
Sections 2–3 provide a defensive, governance-first approach to employing LLM-guided logical test planning and targeted chaos experiments with Canary token validation. The designs emphasize non-actionable planning, human approvals, sandboxed execution, and auditable evidence collection to discover complicated logic flaws while minimizing operational risk.

## SECTION 4 — Ephemeral Test Architecture & Reporting

### 4.1 Goals
- Provide automated, ephemeral Kubernetes-based staging environments seeded with synthetic data for safe DAST execution.
- Integrate OWASP ZAP for dynamic scanning, collect artifacts and risk signals, compute risk scores, and create triage tickets automatically in issue trackers (Jira/GitHub Issues).

### 4.2 High-level architecture
- `Environment Orchestrator`: provisions ephemeral namespaces/clusters via Operators or GitOps (ArgoCD/Flux) from templated manifests.
- `Data Seeder`: injects sanitized, synthetic datasets and Canary tokens into DBs, object stores, and application configs.
- `DAST Runner`: runs OWASP ZAP (headless) and the DAST Execution Harness against the ephemeral environment; collects HARs, logs, and ZAP reports.
- `Risk Scoring Engine`: ingests findings (ZAP alerts, state-machine evidence, entropy signals) and computes composite risk scores.
- `Ticketing Adapter`: opens tickets in Jira/GitHub with pre-filled templates, attachments (HAR, ZAP report, state machine path), and severity labels.
- `Teardown Controller`: destroys environment after testing or upon manual retention request.

### 4.3 Kubernetes provisioning patterns
- Two modes:
  - `Namespace-level sandbox`: lightweight, reuses shared cluster resources; create `ephemeral-<id>` namespace, inject network policies and resource quotas.
  - `Cluster-level sandbox`: full isolation via ephemeral clusters (EKS/GKE/AKS) for higher-fidelity tests or risky experiments.
- Use a `sandbox-operator` CRD manifest example:

```yaml
apiVersion: cbad.example.com/v1
kind: Sandbox
metadata:
  name: sandbox-001
spec:
  mode: namespace
  templateRef: git::ssh://repo/sandbox-templates.git//orders-service
  ttl: 4h
  dataSeed: seed-manifest-001
```

### 4.4 Data seeding and Canary population
- Data Seeder capabilities:
  - synthetic PII generation (names, emails, SSN-like tokens) with unique canary values per environment
  - DB fixtures loader (SQL/ORM-based), S3 object uploads, and configmap/secret templating (secrets are synthetic and ephemeral)
  - Canary token registry: map token -> placement -> experiment_id
- Seed example flow:
  1. create test user with email `canary-<id>@example.com`
  2. insert sample orders referencing canary token into staging DB
  3. store canary metadata in Canary Registry (internal service)

### 4.5 OWASP ZAP integration and orchestration
- Run ZAP in Docker or Kubernetes (ZAP baseline + ZAP full scan depending on depth).
- Use `ZAP API` or `zap-baseline.py` and `zap-full-scan.py` orchestrators with these enhancements:
  - authenticated scanning using session cookies or OAuth tokens provisioned by Auth Context Analyzer
  - correlate ZAP alerts to State Machine transitions by mapping target URLs and parameters
  - produce output formats: JSON, HTML, JUnit, and HAR

Example ZAP run command (k8s job):

```bash
docker run --rm -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-baseline.py -t https://sandbox-001.orders.svc.cluster -r zap-report.html -J zap-report.json
```

### 4.6 Risk scoring engine
- Inputs: ZAP alert severity, CVSS mapping, state-machine reachability score, entropy/ML signals, canary hits, and exploitability heuristics.
- Scoring model (example):

Risk = normalize( w_zap * cvss + w_state * reachability + w_entropy * entropy_score + w_canary * canary_signal )

- Thresholds:
  - `Risk >= 0.9` => P0 (blocker) — open ticket, require immediate fix and re-test
  - `0.7 <= Risk < 0.9` => P1 — open ticket with high priority
  - `0.4 <= Risk < 0.7` => P2 — medium priority
  - `<0.4` => informational

### 4.7 Automated ticket creation workflow
- Ticket payload includes:
  - summary, risk score, affected service and endpoint, reproduction steps (abstract, safe), attachments (ZAP JSON, HAR, state-machine path), and suggested remediation hints
- Integrations:
  - Jira: use Jira REST API to create issues with attachments and labels
  - GitHub: create issue with check run attribution and include triage metadata
- Example ticket creation pseudocode:

1. findings = collect_findings()
2. for f in findings: if f.risk >= threshold: create_ticket(f)

### 4.8 Reporting and dashboards
- Provide dashboards showing:
  - ephemeral environments active, test coverage by endpoint, recent high-risk findings
  - mean time to detection and remediation, risk trend per service
  - canary hit timelines and correlation to DAST runs
- Exportable reports per-run with evidence bundle (ZAP HTML, HAR, state-machine trace) for compliance

### 4.9 Teardown, retention, and reproducibility
- Teardown rules:
  - auto-destroy after TTL unless retained for investigation
  - if retained, snapshot environment metadata and store a read-only copy of artifacts
- Reproducibility:
  - store IaC template commit, data-seed manifest, and planner JSON to reproduce environment and test run

### 4.10 Safety and governance
- Require multirole approval for tests that touch production-like data or that have high-risk safety_level
- Enforce network egress policies to prevent accidental data exfiltration; limit outbound access to test-only endpoints

### 4.11 Example minimal README for a sandbox run

```bash
# provision namespace sandbox
kubectl apply -f sandbox-cr.yaml
# wait for services
./wait-for-health.sh sandbox-001
# seed data
python data_seeder.py --manifest seed-manifest-001
# run DAST
docker run --rm owasp/zap2docker-stable zap-baseline.py -t https://sandbox-001.orders.svc.cluster -r zap-report.html -J zap-report.json
# upload report and create tickets
python report_uploader.py --report zap-report.json --score-threshold 0.7
# teardown
kubectl delete sandbox sandbox-001
```

### 4.12 Summary
Section 4 describes a complete ephemeral test architecture that provisions isolated Kubernetes sandboxes, seeds synthetic data and canaries, runs OWASP ZAP and DAST harnesses, computes risk scores, and automates ticketing and reporting while enforcing safety, reproducibility, and governance.
