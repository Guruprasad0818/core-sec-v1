# CBAD: Threat Scoring, Token Provenance, WORM Audit Storage, and Enterprise Scale

## SECTION 5 — Threat Scoring Engine

### 5.1 Scoring objectives

CBAD computes a consolidated threat score in the range `0-100` for each commit event. The score reflects behavioral anomaly risk across five primary factors:
- unusual time patterns
- module/package impact
- volume/size variations
- language patterns
- geolocation / country anomalies

The score is a weighted linear combination of normalized sub-scores plus rule-based overrides.

### 5.2 Score formula

Let:
- `T_time` = unusual time score
- `T_module` = module impact score
- `T_volume` = volume anomaly score
- `T_lang` = language pattern score
- `T_geo` = geolocation/country score
- `O_rule` = override penalty from critical rules
- `M_drift` = developer drift multiplier

The raw score is:

```
S_raw = w_time * T_time + w_module * T_module + w_volume * T_volume + w_lang * T_lang + w_geo * T_geo
```

The final threat score is:

```
Score = clip( round( (S_raw * M_drift) + O_rule, 0, 100 ) )
```

Where weights are calibrated once per deployment:
- `w_time = 0.20`
- `w_module = 0.25`
- `w_volume = 0.20`
- `w_lang = 0.20`
- `w_geo = 0.15`

The multiplier and overrides are defined as:

- `M_drift = 1 + min(0.5, drift_factor)` where `drift_factor` = developer-specific drift score normalized to `[0,0.5]`
- `O_rule = 0` normally, plus `+15` for critical rule matches (e.g. `hook_bypass_flag`, `sensitive_path_change_flag`, `secret_finding_high`), and `+30` for compliance-critical violations.

### 5.3 Sub-score definitions

#### 5.3.1 `T_time` — Unusual Time Score

Compute `T_time` from the normalized deviation of commit timing relative to developer baseline:

- `hour_z = zscore(commit_hour_local, baseline_hour_mean, baseline_hour_std)`
- `day_z = zscore(commit_day_of_week, baseline_day_mean, baseline_day_std)`
- `cadence_z = zscore(commit_cadence_per_week, baseline_cadence_mean, baseline_cadence_std)`
- `late_night = 1` if late_night_commit_flag else `0`
- `weekend = 1` if weekend_commit_flag else `0`
- `holiday = 1` if holiday_commit_flag else `0`

```
T_time = clip( 100 * (0.35 * sigmoid(|hour_z|) + 0.25 * sigmoid(|day_z|) + 0.20 * sigmoid(|cadence_z|) + 0.10*late_night + 0.05*weekend + 0.05*holiday), 0, 100 )
```

#### 5.3.2 `T_module` — Module / Package Impact Score

Compute module impact from top changed modules, sensitive path access, and code ownership:

- `module_sensitive = 1` if change touches protected modules or ownership boundaries.
- `module_complexity_z = zscore(cyclomatic_complexity_delta, baseline, stddev)`
- `module_entropy_z = zscore(code_entropy_delta, baseline, stddev)`
- `module_ownership = 1` if changed files are outside developer’s usual ownership surface

```
T_module = clip( 100 * (0.40 * module_sensitive + 0.30 * sigmoid(module_complexity_z) + 0.20 * sigmoid(module_entropy_z) + 0.10 * module_ownership ), 0, 100 )
```

#### 5.3.3 `T_volume` — Volume / Size Anomaly Score

Volume score is based on changed files, lines, churn, and diff structure:

- `files_z = zscore(files_changed_count, baseline, stddev)`
- `lines_z = zscore(lines_added + lines_deleted, baseline, stddev)`
- `churn_z = zscore(churn_ratio, baseline, stddev)`
- `hunk_var_z = zscore(patch_hunk_size_variance, baseline, stddev)`
- `new_file_ratio = new_file_count / max(files_changed_count, 1)`

```
T_volume = clip( 100 * (0.30*sigmoid(files_z) + 0.30*sigmoid(lines_z) + 0.20*sigmoid(churn_z) + 0.10*sigmoid(hunk_var_z) + 0.10*new_file_ratio ), 0, 100 )
```

#### 5.3.4 `T_lang` — Language Pattern Score

Language score captures shifts in language usage, syntax anomalies, and toolchain changes:

- `lang_shift = 1` if new_language_introduction_flag
- `lang_entropy = sigmoid(language_mix_entropy / 2.0)`
- `syntax_z = zscore(syntax_error_count, baseline, stddev)`
- `linter_z = zscore(linter_violation_delta, baseline, stddev)`
- `toolchain_change = 1` if build_tool_changes_flag or security_tooling_changes_flag

```
T_lang = clip( 100 * (0.30*lang_shift + 0.25*lang_entropy + 0.20*sigmoid(syntax_z) + 0.15*sigmoid(linter_z) + 0.10*toolchain_change ), 0, 100 )
```

#### 5.3.5 `T_geo` — Geolocation / Country Score

Geolocation score measures impossible travel and country mismatches:

- `country_mismatch = 1` when commit origin country != baseline country set
- `ip_suspicious = 1` for known anonymizer / VPN IPs
- `timezone_mismatch = 1` if local timezone differs from baseline profile
- `impossible_travel_index` = min(1, travel_distance_km / 5000)

```
T_geo = clip( 100 * (0.40*country_mismatch + 0.25*impossible_travel_index + 0.20*ip_suspicious + 0.15*timezone_mismatch), 0, 100 )
```

### 5.4 Final threat classification

Use thresholds to classify the score:
- `0-29` = Low
- `30-54` = Medium
- `55-74` = High
- `75-100` = Critical

Apply escalation rules:
- If `hook_bypass_flag` or `secret_finding_high`: raise severity by one band.
- If `anomaly_score > 90` and `T_geo > 70`: require immediate push block or manual review.
- If `M_drift > 1.30`: annotate the score as drift-amplified.

### 5.5 Operational scoring details

- Store normalized sub-scores and component weights in the event payload for explainability.
- Persist per-feature contributions so analysts can reconstruct why a commit reached a given score.
- Use rolling score smoothing on a developer timeline to avoid transient spikes from single commits.

## SECTION 6 — Token Provenance

### 6.1 Objectives

Token Provenance detects credential misuse by analyzing developer identity, machine signals, and session metadata. It is focused on:
- impossible travel
- device mismatch
- new machine signatures
- VPN / proxy anomalies

This layer is part of commit event enrichment and is used both for scoring and for restrictive policy decisions.

### 6.2 Signal collection

Collect the following provenance signals per commit event:
- `author_email` and verified `developer_id`
- `device_fingerprint_hash` from local agent metadata
- `git_client_version` and `git_user_config_changes_flag`
- `ip_address` and derived `geo_country`, `geo_region`, `geo_city`
- `network_type` = `direct` / `vpn` / `proxy` / `tor`
- `machine_id` = hashed hardware signature or local agent installation ID
- `session_start_timestamp`
- `commit_timestamp`

### 6.3 Impossible travel detection

Define `impossible_travel_score` using temporal and geographic distance.

- `travel_time_hours = |commit_time_utc - previous_commit_time_utc|`
- `distance_km` between previous and current geo points
- `max_travel_speed_kmh = distance_km / max(travel_time_hours, 0.25)`

If `max_travel_speed_kmh > 1000`:
- `impossible_travel_index = clip((max_travel_speed_kmh - 1000) / 9000, 0, 1)`
- otherwise `0`

If commit sequence indicates cross-border travel in under 2 hours with different country and same device, assign a high anomaly component.

### 6.4 Device mismatch detection

- Compare current `device_fingerprint_hash` to the developer’s historical fingerprint set.
- Use a similarity threshold:
  - `device_match = 1` if exact fingerprint seen before
  - `device_similar = 0.5` if same OS / same git client version but different hardware hash
  - `device_new = 1` if completely unseen combination

- `T_device = 100 * (0.6*device_new + 0.4*(1 - device_similarity_score))`

If a commit originates from a known trusted device, reduce provenance risk by 30%.

### 6.5 New machine signatures

- Create a fingerprint entry for each unique machine:
  - `machine_id` = SHA256(`hardware_id || os_name || git_client_version || local_agent_version`)
- Maintain a cache of the last `K=10` machines per developer.
- Flag `new_machine_flag` when machine_id is not in the cache.
- Assign `new_machine_score = 100 * sigmoid(days_since_last_known_machine / 30)`.

Combine with baseline familiarity:
- If `new_machine_flag` and `prior_anomaly_rate > 0.05`, escalate provenance score.

### 6.6 VPN / proxy / anonymizer anomalies

- Classify `network_type` using local endpoint detection and IP metadata services.
- Define `vpn_proxy_score`:
  - `0.8` if IP belongs to a known VPN / proxy ASN or anonymizer list
  - `0.4` if IP resolves to a cloud provider not previously used by the developer
  - `0.0` for stable trusted IP ranges

- If `git_remote_endpoint_type` is `ssh` and origin IP is anonymized, add extra suspicion.

### 6.7 Provenance composite score

```
P_score = clip( 100 * (0.4 * impossible_travel_index + 0.25 * T_device/100 + 0.20 * new_machine_score/100 + 0.15 * vpn_proxy_score), 0, 100)
```

- Attach `P_score` to both threat scoring and anomaly event enrichment.
- Use `P_score > 70` as a trigger for multi-factor review or temporary push throttling.

### 6.8 Provenance policy actions

- If `P_score > 85` and `country_mismatch = 1`: require secondary verification before merge.
- If `device_new = 1` and `network_type = vpn`: send a low-latency developer notification.
- If `impossible_travel_index > 0.5`: create a dedicated `ProvenanceAlert` audit event.

## SECTION 7 — WORM Audit Storage

### 7.1 Immutable log storage architecture

CBAD uses write-once-read-many storage for audit evidence and incident investigation. The architecture is designed for AWS, but is portable to other object stores supporting immutability.

#### 7.1.1 AWS S3 Object Lock and Glacier vaults

- Primary audit archive is stored in AWS S3 with Object Lock enabled in `Compliance` mode.
- Each audit artifact is stored as an object with metadata:
  - `x-amz-object-lock-mode=COMPLIANCE`
  - `x-amz-object-lock-retain-until-date`
  - `x-amz-object-lock-legal-hold` where required
- Object types:
  - `commit_event/{commit_id}.json`
  - `anomaly_event/{event_id}.json`
  - `secret_finding/{finding_id}.json`
  - `provenance_event/{event_id}.json`

- Use S3 Lifecycle policies to transition older archive objects to `GLACIER_IR`, then `GLACIER` or `DEEP_ARCHIVE`.

#### 7.1.2 Cryptographic integrity and versioning

- Each object is content-hashed with SHA-256 and stored in metadata field `x-amz-meta-sha256-hash`.
- Maintain a separate catalog index in PostgreSQL or DynamoDB for fast lookup by commit or event id.
- Use S3 versioning enabled in combination with Object Lock to preserve historical revisions and support immutable snapshots.

### 7.2 Audit storage engineering logic

- Ingestion pipeline writes audit objects via a hardened service account with minimal IAM privileges:
  - `s3:PutObject`, `s3:PutObjectRetention`, `s3:PutObjectLegalHold`, `s3:ListBucket`, `s3:GetObject`
- Only the audit ingestion service can set object lock; no developer-facing process has direct S3 write access.
- For each commit/anomaly event, store both the JSON payload and an index record.
- Persist `audit_index` with fields:
  - `artifact_id`
  - `artifact_type`
  - `commit_id`
  - `event_id`
  - `developer_id`
  - `created_at`
  - `s3_uri`
  - `sha256_hash`
  - `retention_expiry`

### 7.3 Validation and compliance

- Implement a periodic audit job to validate S3 object lock compliance and hash integrity.
- For AWS, use `GetObjectRetention` and `GetObjectLegalHold` to verify policies.
- For on-prem or other clouds, use equivalent immutable storage capabilities and a detached audit proof store.
- Provide immutable evidence to security and compliance teams with export packages containing signed metadata and object hashes.

## SECTION 8 — Enterprise Scale

### 8.1 Scaling architecture patterns

CBAD scales from small teams to large enterprises through a modular, elastic architecture.

#### 8.1.1 Core scale dimensions

- `developers`: 10 → 10,000
- `repositories`: 5 → 5,000
- `commits/day`: 200 → 150,000
- `events/day`: 500 → 500,000

#### 8.1.2 Infrastructure design

- Use horizontally scalable microservices for:
  - Git hook ingestion
  - feature extraction
  - model scoring and ensemble aggregation
  - secret scanning orchestration
  - provenance enrichment
  - audit storage ingestion

- Data stores:
  - PostgreSQL for transactional metadata and index catalogs
  - MongoDB or DynamoDB for document-structured event payloads and developer profiles
  - OpenSearch / Elasticsearch for search and investigation
  - AWS S3 for WORM audit archives

- Messaging and orchestration:
  - Kafka or Kinesis for event buses
  - AWS SQS / SNS for workflow decoupling
  - Kubernetes for service autoscaling and deployment

#### 8.1.3 Caching and locality

- Use Redis or Memcached for hot baseline lookups and recent developer/session state.
- Deploy local scoring cache near Git host proxies for low-latency pre-push decisions.
- Cache provenance IP geography and ASN lookups to avoid repeated external calls.

### 8.2 Performance and availability

- Design services for 99.9% availability and 95th percentile scoring latency < 200ms for local path.
- Enforce backpressure on ingestion queues when scan or model services are saturated.
- Use circuit breakers and degradations: audit-only mode if the model store is unavailable.
- Partition repository metadata by organization and shard developer baselines by region.

### 8.3 Multi-tenant enterprise considerations

- Isolate workloads by organization/tenant using logical namespaces and RBAC.
- Encrypt sensitive data at rest with per-tenant KMS keys.
- Provide per-tenant model tuning and policy overrides.
- Support enterprise SSO / SCIM integration for developer identity mapping.

### 8.4 Implementation roadmap

#### MVP

- Core Git hook architecture with local `pre-commit`, `commit-msg`, `pre-push` instrumentation.
- Feature Collection Engine capturing 50+ features and storing commit payloads.
- BehaviorProfile and CommitFeatures data model in PostgreSQL.
- Basic 3-sigma threat scoring and anomaly events.
- Simple secret scanning via regex and Gitleaks in local hooks.
- Immutable audit storage prototype using S3 with Object Lock.
- Single-tenant deployment for up to `100 developers`.

#### Phase 2 — Production readiness

- Add Isolation Forest and Autoencoder models with ONNX local scoring.
- Add server-side `pre-receive` / `post-receive` enforcement.
- Add provenance detection and geolocation enrichment.
- Add developer baseline drift monitoring and model versioning.
- Add enterprise-grade logging, RBAC, and multi-tenancy support.
- Scale to `1,000 developers` with Kafka-based event pipelines.

#### Phase 3 — Enterprise scale

- Add CI / pipeline integration and repo-level secret scanning at scale.
- Build full WORM audit catalog with search and compliance reporting.
- Deploy a global service mesh supporting `10,000 developers` and `500,000 events/day`.
- Add advanced analytics: trend dashboards, false positive feedback, and playbook automation.
- Add offline / air-gapped mode for high-security environments.
- Add SSO / SCIM, tenant-specific model tuning, and federated storage patterns.

#### Phase 4 — Optimization and expansion

- Add adaptive model retraining and self-healing baselines.
- Expand secret detection to historical repo scans and supply chain intelligence.
- Add partner integrations (GitHub Enterprise, GitLab, Azure DevOps, Bitbucket).
- Add drift-based alerting, analyst workflow integration, and API-first extensibility.
- Harden to regulatory requirements with audit certifications and compliance evidence exports.

### 8.5 Enterprise deployment patterns

- Start with a single region Kubernetes cluster and scale service replicas by CPU/memory and queue depth.
- Use multi-AZ databases and cross-region storage replication for disaster recovery.
- Partition tenant data and event routing by organization ID.
- Instrument capacity forecasting based on commit volume, scan batch size, and retention.
- Maintain a centralized operations dashboard with health metrics for ingestion latency, model scoring throughput, secret scan coverage, and audit write completion.

### 8.6 Summary

Stage 1 is complete with an end-to-end design that includes threat scoring, token provenance, immutable audit storage, and a clear roadmap from MVP to enterprise scale. This provides the foundation for a commercial-grade CBAD product capable of supporting thousands of developers with strong security and compliance controls.
