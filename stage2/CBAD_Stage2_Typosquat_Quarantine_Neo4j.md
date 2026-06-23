# CBAD Stage 2 — Typosquat Detection, Artifact Quarantine, and Neo4j Graph Model

## SECTION 3 — Typosquat Detection Engine

### 3.1 Objective

The Typosquat Detection Engine identifies suspicious dependency names and package metadata likely created to deceive humans or automation. It must operate in real time for artifact admission, detect both obvious and subtle squatting attacks, and produce explainable risk signals.

### 3.2 Multi-layered ruleset design

The engine uses a layered detection pipeline:
1. exact and prefix/suffix blacklist matching
2. syntax normalization and tokenization
3. string similarity scoring (Levenshtein, Jaro-Winkler)
4. keyboard adjacency scoring
5. visual similarity and homoglyph detection
6. ML transformer ranking for context and false-positive reduction

#### 3.2.1 Name normalization

- canonicalize package names by lowercasing, trimming punctuation, and collapsing repeated separators
- remove common noise tokens such as `js`, `py`, `lib`, `node`, `python`
- normalize Unicode to NFKC
- extract lexical tokens from compound names using camelCase and snake_case splitting

Example normalizations:
- `Reqeusts` -> `requests`
- `expresss` -> `express`
- `angular1` -> `angular`
- `go-aws-sdk` -> `aws sdk`

### 3.3 Similarity metrics

#### 3.3.1 Levenshtein distance

- compute normalized Levenshtein distance `L_norm = 1 - (levenshtein / max_len)`
- apply thresholds based on name length:
  - if length < 6: require `L_norm >= 0.67`
  - if length 6-12: require `L_norm >= 0.78`
  - if length > 12: require `L_norm >= 0.85`
- compute both single-edit and multi-edit variants

Use Levenshtein primarily for substitutions, insertions, deletions.

#### 3.3.2 Jaro-Winkler similarity

- compute `JW_score` to emphasize common prefixes and transpositions
- apply prefix scaling factor `p=0.1` and maximum prefix length 4
- good for catching small name variations like `expresss` vs `express`

Thresholds:
- `JW_score > 0.92` for strong suspicion
- `0.86 < JW_score <= 0.92` for medium suspicion requiring additional signals

#### 3.3.3 Keyboard adjacency score

- use QWERTY physical adjacency matrix for ASCII letters and digits
- compute substitution cost based on adjacency distance
- penalize substituting adjacent keys less than distant keys

Algorithm:
- for each character pair in aligned strings, assign cost:
  - exact match = 0
  - adjacent key substitution = 0.5
  - same keyboard row but non-adjacent = 0.8
  - other substitution = 1

Normalized keyboard score:
```
K_score = 1 - (keyboard_cost / max_cost)
```

This detects typos like `googel` or `pypi` -> `pip`.

#### 3.3.4 Visual similarity and homoglyph attacks

- normalize Unicode confusables using a visual mapping table (e.g. `0` vs `O`, `l` vs `1`, `rn` vs `m`)
- compute a `visually_equivalent` normalized string for candidate and target names
- detect homoglyph substitutions in both ASCII and Unicode domains
- incorporate common script mixing patterns such as Cyrillic `а` in place of Latin `a`

Scoring:
- if `normalized_visual_name` matches a trusted package: `V_score = 1.0`
- if visual similarity is partial: `V_score = 0.8`

Examples:
- `rnpm` vs `npm`
- `microsоft` (Cyrillic `o`) vs `microsoft`

#### 3.3.5 Composite typosquatting score

Combine signals into a unified suspicion score:

```
Typosquat_score = max(
  0.35 * L_norm +
  0.25 * JW_score +
  0.15 * K_score +
  0.15 * V_score +
  0.10 * contextual_similarity
)
```

Where `contextual_similarity` is derived from package metadata similarity to an internal or known trusted package, including description and keyword overlap.

### 3.4 Contextual features

- package description similarity to trusted package descriptions
- keyword overlap with known package categories
- author/maintainer alignment with the legitimate package family
- package creation date relative to legitimate package age
- version timeline anomalies (very low version number on a new package with similar name)

#### 3.4.1 Metadata and ownership signals

- check if package homepage, repository URL, or author email match the trusted package family
- compute `owner_similarity` between candidate and target maintainers
- flag packages with empty or generic metadata fields

### 3.5 Transformer model enhancement

An ML Transformer model improves the ruleset by modeling semantic and contextual similarity beyond string metrics.

#### 3.5.1 Model role

- embed package names, descriptions, README snippets, and author metadata
- learn patterns of deceptive package naming and content reuse
- reduce false positives by understanding legitimate name variants and language patterns
- detect adversarial synonyms and brand impersonation not caught by exact string similarity

#### 3.5.2 Architecture

- small transformer encoder with tokenized package text inputs
- input tokens:
  - normalized package name
  - package description and summary
  - repository URL domain tokens
  - author/maintainer identifiers
- shared embedding space for package identity and developer context
- output: `contextual_similarity` score in `[0,1]`

Training data:
- labeled sets of known typosquatting pairs and safe similar-name packages
- synthetic variants generated using keyboard adjacency, homoglyphs, and insertion/deletion attacks
- legitimate name variations from internal package naming conventions

#### 3.5.3 Integration with rules pipeline

- use transformer output as a final ranking signal
- if `Typosquat_score` is near threshold, use the transformer score to decide whether to quarantine or allow
- for packages with `name_similarity` and `metadata_similarity` both high, transformer provides disambiguation
- store attention-based explainability vectors for analyst review

#### 3.5.4 Advantages of Transformer enhancement

- generalizes across ecosystems and naming conventions
- detects sophisticated impersonation beyond edit-distance
- handles noisy metadata, abbreviations, and brand terms
- learns from evolving attack patterns using continuous training

#### 3.5.5 Production considerations

- run transformer inference asynchronously for non-blocking cache admission when possible
- use distilled transformer model or ONNX runtime for low-latency policy checks
- retrain periodically with newly observed attack vectors and false-positive feedback
- combine with hard rules for deterministic blocking on high-risk cases

### 3.6 Risk categories and actions

Based on `Typosquat_score`, map to actions:
- `0-24`: allow
- `25-49`: review only, annotate with `typo_suspect`
- `50-74`: quarantine pending manual analyst review
- `75-100`: block admission and reject artifact synchronization

Critical conditions for immediate block:
- exact visual match to a trusted package with different ownership
- known malicious package name from threat intel feed
- `internal_name_conflict` with higher similarity than threshold

## SECTION 4 — Artifact Quarantine Workflow

### 4.1 Workflow objectives

The Artifact Quarantine workflow isolates suspicious packages before they can enter production caches or be consumed by builds. It must support automated evaluation, human review, and safe promotion after validation.

### 4.2 Workflow architecture

#### 4.2.1 Ingestion path

1. `Package Request` arrives from build tool or cache sync.
2. `Admission Controller` performs metadata validation and initial policy checks.
3. If package is suspicious, route to `Quarantine Queue`.
4. `Quarantine Service` stores the package and metadata in isolated quarantine storage.
5. `Risk Engine` computes detailed scores and may invoke `Typosquat Detection Engine` and `DGT Engine`.
6. `Review Workflow` assigns the package to security reviewers or automation.
7. Outcome: `approve`, `reject`, or `escalate`.

#### 4.2.2 Quarantine zones

- `Transient quarantine` for packages awaiting automated triage (short-lived, strict access controls)
- `Persistent quarantine` for packages requiring manual investigation
- `Shadow cache` where quarantined packages are cached separately from production artifacts

#### 4.2.3 Artifact metadata capture

For each quarantined artifact, capture:
- package name, version, namespace
- source registry / origin URL
- checksum and signature metadata
- ingestion timestamp and source request ID
- DGT_score and Typosquat_score with component breakdowns
- provenance evidence (maintainer identity, repo links, package metadata)
- quarantine reason and assigned reviewer

### 4.3 Automated quarantine decision logic

Rules:
- if `Typosquat_score >= 50` and `DGT_score <= 60` => quarantine
- if package name conflicts with internal namespace => quarantine immediately
- if package is sourced from untrusted public feed and `S_CVE < 70` => quarantine for secondary verification
- if artifact metadata or checksum mismatch occurs => quarantine and block usage until resolved

Use a risk threshold matrix combining name-based and dependency trust signals.

### 4.4 Review and release lifecycle

- `Automated triage` may approve lower-risk quarantined packages using policy rules and heuristics
- `Manual review` is triggered for packages with composite risk above the high threshold
- Reviewers inspect:
  - package ownership and maintainer history
  - release changelog and artifact contents
  - signature provenance and build reproducibility evidence
  - internal dependency exposure and transitive risk
- Approved artifacts are promoted to the `Trusted Cache` with metadata tags and audit records
- rejected artifacts are blacklisted and the requesting pipeline is notified

### 4.5 Audit and evidence

- store a full audit trail for each quarantine event
- record reviewer decisions, timestamps, and justification
- preserve package payloads and metadata in immutable audit logs
- enable replay of quarantine decisions for compliance reviews

### 4.6 Scalability and operations

- use message queues for quarantine intake and processing
- shard quarantine state by package namespace and organization
- employ autoscaled review service and automated triage bots
- integrate with ticketing for analyst assignment and SLA tracking

## SECTION 5 — Neo4j Graph Database Model

### 5.1 Objective

Use Neo4j as the canonical graph store for artifact lineage, maintainer relationships, release history, vulnerability sources, and trust signals.

### 5.2 Core nodes and relationships

#### Nodes
- `:Package` with properties:
  - `name`
  - `namespace`
  - `ecosystem`
  - `latest_version`
  - `DGT_score`
  - `Typosquat_score`
  - `trust_category`
  - `first_seen_at`
  - `last_seen_at`
  - `is_quarantined`

- `:Release` with properties:
  - `version`
  - `released_at`
  - `checksum`
  - `signature_status`
  - `is_quarantined`
  - `risk_reasons`

- `:Maintainer` with properties:
  - `name`
  - `username`
  - `organization`
  - `account_status`
  - `public_key_fingerprint`
  - `trust_score`
  - `last_activity_at`

- `:Repository` with properties:
  - `url`
  - `host`
  - `visibility`
  - `security_policy`
  - `last_scan_at`

- `:Vulnerability` with properties:
  - `cve_id`
  - `cvss_score`
  - `published_at`
  - `severity`
  - `status`

- `:AuditEvent` with properties:
  - `event_id`
  - `event_type`
  - `created_at`
  - `actor`
  - `outcome`
  - `details`

#### Relationships
- `(:Maintainer)-[:MAINTAINS]->(:Package)`
- `(:Package)-[:HAS_RELEASE]->(:Release)`
- `(:Release)-[:BASED_ON]->(:Package)` for dependency edges with properties `scope`, `optional`, `version_constraint`, `depth`
- `(:Release)-[:PUBLISHED_FROM]->(:Repository)`
- `(:Package)-[:ASSOCIATED_WITH]->(:Repository)`
- `(:Package)-[:AFFECTED_BY]->(:Vulnerability)`
- `(:Release)-[:QUARANTINED_BY]->(:AuditEvent)`
- `(:Maintainer)-[:AUTHORED]->(:AuditEvent)`
- `(:Package)-[:SUSPECTED_TYPO]->(:Package)` with properties `similarity_score`, `attack_type`
- `(:Package)-[:INTERNAL_ALIAS_OF]->(:Package)` for intended internal/external equivalence tracking

### 5.3 Graph model details

#### 5.3.1 Maintainer-to-Package

- `MAINTAINS` edges are typed and weighted by `activity_score` and `response_time`
- maintain multiple edges to capture historical ownership, delegated maintainers, and organizational ownership
- store `verified = true/false` on edges when maintainers are cryptographically validated

#### 5.3.2 Package-to-Release lineage

- each package can have hundreds of releases
- `HAS_RELEASE` edges carry `release_type` (`stable`, `prerelease`, `patch`)
- `Release` nodes include `checksum` and `signature_status` to validate artifact provenance

#### 5.3.3 Dependency graph

- use `BASED_ON` edges to represent direct dependency relationships from release nodes to package nodes
- edge properties:
  - `scope` = `compile`, `runtime`, `test`, `dev`
  - `version_constraint`
  - `depth`
  - `transitive_distance`
  - `criticality`

- compute shortest paths and attack surface exposure using Neo4j algorithms

#### 5.3.4 Quarantine and audit relationships

- `QUARANTINED_BY` edges link suspicious releases to audit events
- audit events retain `decision`, `reviewer_id`, `workflow_step`, `review_notes`
- maintain a history of quarantine state transitions via `:AuditEvent` and `:Release` properties

#### 5.3.5 Typosquat relationship graph

- `SUSPECTED_TYPO` edges connect candidate packages to trusted lookup packages
- edge properties:
  - `similarity_score`
  - `rule_vector` = `{levenshtein, jaro_winkler, keyboard, visual, transformer}`
  - `attack_type` = `typo` / `homoglyph` / `brand_imitation` / `internal_conflict`

This graph allows query patterns like:
- find all packages within 2 hops of a known internal name
- detect clusters of suspicious names targeting the same brand
- identify packages with both high DGT risk and typosquat association

### 5.4 Neo4j storage schema and constraints

#### Node key design
- `Package` key: `ecosystem + namespace + name`
- `Release` key: `package_key + version`
- `Maintainer` key: `host + username` or `email`
- `Repository` key: `url`
- `Vulnerability` key: `cve_id`
- `AuditEvent` key: `event_id`

#### Indexes
- `CREATE INDEX package_idx ON :Package(namespace, name)`
- `CREATE INDEX release_idx ON :Release(version)`
- `CREATE INDEX maintainer_idx ON :Maintainer(username)`
- `CREATE INDEX repo_idx ON :Repository(host)`
- `CREATE INDEX vuln_idx ON :Vulnerability(cve_id)`
- `CREATE INDEX audit_idx ON :AuditEvent(event_id)`

#### Constraints
- `CREATE CONSTRAINT ON (p:Package) ASSERT p.package_key IS UNIQUE`
- `CREATE CONSTRAINT ON (r:Release) ASSERT r.release_key IS UNIQUE`
- `CREATE CONSTRAINT ON (m:Maintainer) ASSERT m.maintainer_key IS UNIQUE`
- `CREATE CONSTRAINT ON (v:Vulnerability) ASSERT v.cve_id IS UNIQUE`
- `CREATE CONSTRAINT ON (a:AuditEvent) ASSERT a.event_id IS UNIQUE`

### 5.5 Query patterns

#### High-risk package discovery
```
MATCH (p:Package)
WHERE p.DGT_score < 50 OR p.Typosquat_score >= 50
RETURN p.name, p.namespace, p.ecosystem, p.DGT_score, p.Typosquat_score
```

#### Suspicious dependency chain
```
MATCH path = (root:Package {name: 'internal-lib'})<-[:BASED_ON*1..4]-(r:Release)
WHERE r.is_quarantined = true OR r.DGT_score < 60
RETURN path
```

#### Maintainer risk surface
```
MATCH (m:Maintainer)-[:MAINTAINS]->(p:Package)
WHERE m.trust_score < 60
RETURN m.username, p.name, p.namespace, p.DGT_score
```

#### Typosquat cluster analysis
```
MATCH (p:Package)-[s:SUSPECTED_TYPO]->(target:Package)
WHERE s.similarity_score > 0.8
RETURN p.name, target.name, s.attack_type, s.rule_vector
```

### 5.6 Operational integration

- ingest package metadata and release events from artifact cache sync jobs into Neo4j
- update maintainer and repository signals on each discovery or scan
- use Neo4j algorithms for risk propagation, connected component clustering, and path impact analysis
- feed query results into quarantine automation, policy dashboards, and threat hunting workflows

### 5.7 Enterprise considerations

- enable multi-database Neo4j deployment or database-per-tenant in large enterprises
- tier graph storage with cold/hot separation for historical release lineage
- encrypt Neo4j data at rest and in transit
- control access via role-based security for analysts, engineers, and audit teams
- periodically snapshot graph state for forensic replay and compliance

---

This Stage 2 deliverable provides a production-grade Typosquat Detection Engine, automated artifact quarantine workflow, and a complete Neo4j graph database model for artifact trust and provenance tracking.
