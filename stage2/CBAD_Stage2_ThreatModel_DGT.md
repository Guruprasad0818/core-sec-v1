# CBAD Stage 2 — Zero-Trust Artifact Cache

## SECTION 1 — Threat Model & Attack Surface

### 1.1 Overview

Stage 2 defines a Zero-Trust Artifact Cache designed to replace Nexus/Artifactory in environments with elevated supply chain risk. The architecture must assume that public package ecosystems, internal build artifacts, and third-party mirrors are all potentially hostile.

The threat model is based on adversaries targeting artifact integrity, provenance, availability, and trust inference. The attack surface includes package repositories, package metadata, mirror caches, build systems, CI/CD pipelines, container registries, and developer workstations.

### 1.2 Threat Categories

#### 1.2.1 Typosquatting

Typosquatting occurs when an attacker publishes a malicious package whose name closely resembles a legitimate dependency name (e.g. `reqeusts` vs `requests`). This exploits human or automation-based package selection errors.

Attack surface:
- package name resolution in package managers (npm, PyPI, Maven, NuGet, Go, Rust)
- transitive dependency resolution in build tools
- dependency inference by automation rules and CI templates
- package search and suggestion engines

Adversary capabilities:
- register near-identical names in public repositories
- craft plausible package descriptions, metadata, and documentation
- leverage automated publishing to create a family of typosquatting packages

Enterprise implications:
- supply chain compromise via transitive installs
- lateral escalation when malicious package executes during build/test
- data exfiltration from development or CI environment

Mitigations:
- strict allowlist/denylist on package names
- dependency name similarity scoring and alerting
- cache-level name collision blocking for suspicious variants
- developer training and secure-by-default manifest fixity

#### 1.2.2 Dependency Confusion

Dependency Confusion arises when an internal package name is also publishable in public package feeds, and build systems resolve the public package instead of the internal one.

Attack surface:
- package manager search order and registry precedence
- missing private package registry authentication
- package names shared between internal and external namespaces
- non-deterministic resolution when using wildcard version constraints

Adversary capabilities:
- publish a package to npm/PyPI/Maven Central using an internal package name
- choose a higher semantic version than internal artifacts
- exploit lower precedence of corporate private registries by injecting public sources first

Enterprise implications:
- execution of externally sourced code under trusted internal package names
- confidentiality breach via stolen CI credentials or secrets from build environments
- undermining of internal artifact isolation

Mitigations:
- enforce registry source order with private caches first
- block resolution of external packages with internal-only names
- synchronize internal namespace metadata with public registry feeds
- scan for unknown upstream packages that conflict with internal names

#### 1.2.3 Repository Hijacking

Repository Hijacking is the takeover of an upstream source control repository or package publishing account to push malicious releases.

Attack surface:
- code repository ownership and maintainer access controls
- upstream package release signing and publishing credentials
- mirrors and proxies that synchronize upstream package metadata
- differential dependency update automation

Adversary capabilities:
- compromise maintainer credentials via phishing or credential stuffing
- exploit repo provider vulnerabilities to gain push access
- take over third-party packages through orphaned or abandoned maintainers

Enterprise implications:
- trusted dependency suddenly delivering malicious payloads
- long-lived supply chain persistence through update chains
- risk of build or runtime compromise in production

Mitigations:
- enforce package provenance verification and signature validation
- model and score maintainer trust and account health
- require reproducible builds and signed deployment artifacts
- apply expiration and rotation to upstream package metadata

#### 1.2.4 Cache Poisoning

Cache Poisoning is the injection of malicious or tampered artifacts into the internal artifact cache.

Attack surface:
- artifact ingestion and synchronization pipelines
- cache HTTP endpoints, upload interfaces, and package pull-through proxying
- build system cache-backed dependency resolution
- CI/CD agent local caches and remote shared caches

Adversary capabilities:
- exploit unauthenticated cache endpoints to insert artifacts
- tamper with cache storage backing (object storage, filesystem)
- trigger mirror replication of poisoned metadata and binaries
- use malformed metadata to bypass validation

Enterprise implications:
- broad distribution of poisoned artifacts across internal consumers
- high-impact compromise of developer machines and builds
- stealthy persistence through cache refresh and replication

Mitigations:
- authenticate and authorize all cache write operations
- validate artifact checksums, signatures, and provenance before admission
- separate read-only proxying and writable cache zones
- implement cache immutability and retention rules for trusted artifacts

#### 1.2.5 Malicious Maintainers

Malicious Maintainers are insiders or third-party developers who intentionally publish backdoored or vulnerable code.

Attack surface:
- open-source package maintainers and organization-scoped packages
- continuous deployment of package releases with low vetting
- social engineering of maintainer accounts
- repository collaborators and automation bots with publish privileges

Adversary capabilities:
- embed backdoors directly in source code
- release malicious features under legitimate package names
- periodically trigger updates to evade detection

Enterprise implications:
- direct introduction of malicious logic through trusted components
- difficulty distinguishing between legitimate bugs and sabotage
- reputational or regulatory damage upon disclosure

Mitigations:
- compute maintainer trust score and bus factor metrics
- enforce signed commits and package release attestations
- require package review evidence and code audit metadata
- quarantine new maintainer uploads until vetted

#### 1.2.6 Backdoored Releases

Backdoored Releases are legitimate packages compromised by attackers post-approval or during release packaging.

Attack surface:
- build artifact generation pipelines and release signing
- CI secrets used to publish packages
- package tarball composition and metadata bundling
- release automation scripts and post-processing hooks

Adversary capabilities:
- insert malicious payload during build or packaging
- compromise CI/CD agents or artifact signing keys
- poison downstream consumers via package update mechanisms

Enterprise implications:
- trusted release artifacts become attack vectors
- supply chain integrity undermined after initial trust decisions
- propagation of malicious payloads to production environments

Mitigations:
- require reproducible builds and deterministic artifact hashing
- verify package signatures and notary metadata
- enforce separation of duties in release pipelines
- scan release artifacts for suspicious files and scripts

#### 1.2.7 Namespace Takeovers

Namespace Takeovers happen when a package namespace is abandoned or not renewed, allowing attackers to claim it and publish malicious versions.

Attack surface:
- orphaned package names in public ecosystems
- weak package ownership transfer controls
- internal references to external namespaces with drift

Adversary capabilities:
- claim abandoned names and publish new releases
- use similar package metadata to preserve trust
- poison version ranges that resolve to takeover packages

Enterprise implications:
- unexpected dependency substitution via transitive resolution
- supply chain disruption when public names are reused maliciously
- high-risk exposure for loosely pinned dependencies

Mitigations:
- map and monitor dependency namespaces for abandonment signals
- enforce fixed-version pinning for sensitive internal names
- block newly claimed external packages that match internal conventions
- proactively mirror or reserve critical namespaces internally

### 1.3 Attack Surface Matrix

| Asset | Threat | Attack Vector | Enterprise Impact | Controls |
|---|---|---|---|---|
| Package name resolution | Typosquatting | malicious package name variants | arbitrary code execution | name similarity scanning, allowlist/denylist |
| Registry precedence | Dependency Confusion | public package override | internal code exfiltration | private registry first, internal name block |
| Source repo credentials | Repo Hijacking | maintainer account compromise | trusted package compromise | provenance validation, account health scoring |
| Cache sync pipeline | Cache Poisoning | malicious artifact insertion | broad artifact distribution | write auth, checksum validation, immutability |
| Maintainer identity | Malicious Maintainers | insider/backdoor publishing | direct supply chain subversion | trust scoring, review evidence |
| Release pipeline | Backdoored Releases | compromised CI/signing | trusted artifact compromise | reproducible builds, signatures |
| Namespace ownership | Namespace Takeover | abandoned package takeover | transitive dependency compromise | namespace reservation, pinning |

### 1.4 Trust and Zero-Trust Assumptions

The design assumes no implicit trust:
- public feeds are untrusted unless validated
- mirrored packages must be verified on ingestion
- metadata alone is insufficient for trust decisions
- developer appliance and CI environments can be compromised

Trust decisions require multiple independent signals:
- package provenance and artifact integrity
- maintainer reliability and account security posture
- historical vulnerability and release patterns
- community signals and corporate sponsorship
- internal topology and dependency role

## SECTION 2 — Dependency Graph Trust (DGT) Engine

### 2.1 Objective

The Dependency Graph Trust Engine computes a normalized trust score `DGT_score` in the range `0-100` for each dependency node, package family, and transitive path. This score is used by the Zero-Trust Artifact Cache to prioritize, quarantine, block, or require additional review.

DGT is explicitly structured as a weighted composite of 10 dimensions:
1. CVE history
2. maintainer count
3. bus factor
4. release frequency
5. code review presence
6. community trust
7. corporate backing
8. dependency depth
9. test coverage
10. documentation quality

### 2.2 Score formula

For a dependency node `d`, compute each dimension score `S_i(d)` in `[0,100]`, then combine them using fixed weights.

```
DGT_raw = 0.18*S_CVE + 0.12*S_maintainers + 0.10*S_bus + 0.10*S_release + 0.12*S_review + 0.10*S_community + 0.08*S_corporate + 0.08*S_depth + 0.07*S_tests + 0.05*S_docs
```

Finally:

```
DGT_score = clip(round(DGT_raw, 0), 0, 100)
```

The weights sum to 100%.

### 2.3 Dimension definitions and calculation

#### 2.3.1 `S_CVE` — CVE History Score (18%)

Measures the historical vulnerability footprint of the package and its direct dependency subtree.

Inputs:
- `cve_count_1y` = count of CVEs in the last 12 months
- `cve_severity_sum` = sum of CVSS v3 base scores for those CVEs
- `cve_age_weighted` = sum of `max(0, 10 - months_since_publish)` per CVE
- `transitive_cve_factor` = 1 + 0.25 * direct_transitive_cve_count

Compute raw risk:

```
risk_CVE = min(1, (0.6 * normalized(cve_count_1y) + 0.3 * normalized(cve_severity_sum) + 0.1 * normalized(cve_age_weighted)) * transitive_cve_factor)
```

Then score:

```
S_CVE = 100 * (1 - risk_CVE)
```

Where `normalized(x)` maps the metric to `[0,1]` using capped percentiles or logistic scaling.

#### 2.3.2 `S_maintainers` — Maintainer Count Score (12%)

Evaluates the number and diversity of maintainers.

Inputs:
- `owner_count` = number of unique commit authors with recent activity
- `org_count` = number of distinct organizations contributing
- `maintainer_activity_index` = fraction of maintainers with activity in the last 90 days

Scoring:

```
maintainer_strength = clip((owner_count / 5) * 0.6 + org_count * 0.2 + maintainer_activity_index * 0.2, 0, 1)
S_maintainers = 100 * maintainer_strength
```

Fewer than 2 maintainers, or a single organization, reduce the score. High maintainer churn lowers `maintainer_activity_index`.

#### 2.3.3 `S_bus` — Bus Factor Score (10%)

Quantifies resilience against knowledge concentration.

Inputs:
- `top_contributor_ratio` = proportion of contributions from the top 3 contributors
- `recent_commit_diversity` = unique contributors in last 180 days / 10
- `maintainer_depth` = count of active maintainers with publish permissions

Score function:

```
bus_risk = clip(0.4*top_contributor_ratio + 0.3*(1 - recent_commit_diversity) + 0.3*(1 - normalized(maintainer_depth)), 0, 1)
S_bus = 100 * (1 - bus_risk)
```

A lower bus factor produces a lower score.

#### 2.3.4 `S_release` — Release Frequency Score (10%)

Measures release cadence and stability.

Inputs:
- `release_interval_days` = median days between releases
- `release_volume` = releases/year
- `churned_major_releases` = count of major backwards-incompatible releases in 12 months
- `patch_density` = ratio of patch releases to total releases

Score formula:

```
freq_score = clip(0.5 * exp(-release_interval_days / 90) + 0.3 * tanh(release_volume / 20) + 0.2 * patch_density, 0, 1)
stab_penalty = min(0.4, 0.1 * max(0, churned_major_releases - 2))
S_release = 100 * (freq_score - stab_penalty)
```

A healthy release cadence is regular patch releases with moderate volume and low major churn.

#### 2.3.5 `S_review` — Code Review Presence Score (12%)

Scores evidence of review and governance.

Inputs:
- `pr_review_rate` = percent of merged PRs with review approvals
- `review_depth` = average number of reviewers per merge
- `review_latency_days` = average days between PR open and merge
- `reviewed_release_ratio` = percent of releases linked to reviewed PRs

Calculation:

```
review_signal = 0.4*pr_review_rate + 0.3*clip(review_depth / 2, 0, 1) + 0.2*(1 - sigmoid(review_latency_days/7)) + 0.1*reviewed_release_ratio
S_review = 100 * review_signal
```

Low review rates or high latency reduce trust.

#### 2.3.6 `S_community` — Community Trust Score (10%)

Measures ecosystem confidence and user adoption.

Inputs:
- `download_rank` = normalized download volume percentile among category peers
- `issue_activity` = normalized ratio of resolved issues to total open issues
- `stars_forks_score` = normalized GitHub stars/forks measure
- `community_age` = months since first release / 24, capped at 1

Formula:

```
community_signal = 0.45*download_rank + 0.25*issue_activity + 0.2*stars_forks_score + 0.1*community_age
S_community = 100 * community_signal
```

Community signals are strong but capped to prevent popularity from overriding security risks.

#### 2.3.7 `S_corporate` — Corporate Backing Score (8%)

Evaluates enterprise sponsorship and organizational support.

Inputs:
- `corporate_sponsor` = binary: 1 if owned/maintained by a known corporation
- `paid_support_available` = binary
- `security_program_presence` = 0 to 1 evidence of published security policy or security contact
- `enterprise_adoption` = normalized count of known enterprise users or integrations

Formula:

```
corp_signal = 0.4*corporate_sponsor + 0.2*paid_support_available + 0.3*security_program_presence + 0.1*enterprise_adoption
S_corporate = 100 * corp_signal
```

Corporate backing improves trust, but is not sufficient alone.

#### 2.3.8 `S_depth` — Dependency Depth Score (8%)

Penalizes deep transitive dependency chains that expand risk surface.

Inputs:
- `dependency_depth` = maximum transitive depth
- `transitive_count` = total number of transitive packages
- `critical_dependency_ratio` = ratio of high-sensitivity transitive packages

Calculation:

```
depth_risk = clip(0.5*sigmoid((dependency_depth - 4)/2) + 0.3*sigmoid((transitive_count - 20)/20) + 0.2*critical_dependency_ratio, 0, 1)
S_depth = 100 * (1 - depth_risk)
```

Shallow trees with fewer transitive hops score higher.

#### 2.3.9 `S_tests` — Test Coverage Score (7%)

Scores the package’s automated quality signal.

Inputs:
- `coverage_percent` = normalized test coverage of source code
- `ci_status` = ratio of recent passing CI runs to total runs
- `thin_tests_flag` = 1 if tests exist but are minimal or absent

Formula:

```
test_signal = 0.5*normalized(coverage_percent) + 0.3*ci_status + 0.2*(1 - thin_tests_flag)
S_tests = 100 * test_signal
```

Low coverage or unstable CI reduces trust.

#### 2.3.10 `S_docs` — Documentation Quality Score (5%)

Assesses documentation and package guidance quality.

Inputs:
- `docs_presence` = binary for README / docs site existence
- `docs_depth` = normalized count of examples and API docs
- `docs_freshness` = recency of docs updates relative to releases

Formula:

```
docs_signal = 0.5*docs_presence + 0.3*docs_depth + 0.2*docs_freshness
S_docs = 100 * docs_signal
```

Documentation is useful but lower weight compared to security and governance signals.

### 2.4 Trust score adjustments and policies

#### 2.4.1 Critical penalty overrides

If any of the following conditions are true, apply a fixed penalty to the raw score before clipping:
- `has_unpatched_high_severity_CVE` => `-20`
- `maintainer_account_unverified` => `-10`
- `release_signature_missing` for signed-package policy => `-15`
- `namespace_conflict_with_internal_name` => `-30`

#### 2.4.2 Dependency path attenuation

For transitive dependencies, apply path attenuation based on chain length and criticality:

```
path_factor = max(0.25, 1 - 0.05 * dependency_depth)
DGT_effective = DGT_score * path_factor
```

This reduces the effective trust of deeply nested, indirect dependencies.

#### 2.4.3 Environment-specific bias

For high-security environments, apply a conservative bias:
- `env_bias = 1 - 0.10` for production-critical caches
- `DGT_final = DGT_score * env_bias`

This ensures stricter vetting for environments with stricter risk tolerance.

### 2.5 Use cases for DGT score

- admission control in Zero-Trust Artifact Cache
- filtering package metadata during registry sync
- generating risk-based artifact quarantine policies
- prioritizing manual review for suspicious dependencies
- tuning cache replication and promotion rules

### 2.6 Output and integration

The DGT engine produces:
- `DGT_score` in `0-100`
- component scores for each dimension: `S_CVE`, `S_maintainers`, ..., `S_docs`
- `trust_category` = `trusted` / `caution` / `risk` / `blocked`
- `narrative_reasons` with top risk factors
- `path_factor` for transitive dependencies
- `policy_action` recommendation such as `allow`, `review`, `quarantine`, `block`

This output is persisted in the internal metadata store and attached to dependency graph nodes for every artifact request.

### 2.7 Example scoring scenario

A package with:
- moderate CVE history
- 2 maintainers and moderate bus factor
- frequent patch releases
- weak code review evidence
- strong community adoption
- no corporate sponsorship
- deep dependency tree
- good test coverage
- acceptable docs

Would produce a DGT score around `65-72`, categorized as `caution` and requiring review before promotion into production caches.

---

This Stage 2 deliverable defines the enterprise-grade threat model and mathematically grounded Dependency Graph Trust Engine for a secure artifact cache.
