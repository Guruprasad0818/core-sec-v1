# CBAD: Commit Behavioral Anomaly Detection

## SECTION 1 — Architecture

### 1.1 Git Hook Architecture Overview

CBAD is architected as an integrated Git-aware behavioral security platform with both client-side and server-side enforcement. Its hook architecture is designed for production-grade reliability, low friction, and strong developer identity modeling.

Architecture layers:
- Local Git Hook Agent
- Feature Collection Engine
- Local Feature Cache and Baseline Manager
- Remote scoring and server-side policy enforcement
- Observability / telemetry integration

#### 1.1.1 Client-side Git Hooks

1. pre-commit
  - Runs before Git creates an index commit object.
  - Functionality:
    - Calculate lightweight diff and staged file feature metrics.
    - Enforce repository policy for file type restrictions, large-file thresholds, and sensitive path changes.
    - Capture developer environment metadata (Git client version, OS, tooling signatures).
    - Run fast static checks only on staged changes.
  - Outcome:
    - Abort commit if a critical local policy is violated.
    - Emit a pre-commit feature record into the local feature collection engine.

2. commit-msg
  - Runs after commit message is created but before commit is finalized.
  - Functionality:
    - Validate semantic structure and issue-link conventions.
    - Extract text features: token counts, sentiment, anomaly keywords, message length, JIRA/issue patterns, co-author lines.
    - Detect commit message reuse or template anomalies.
  - Outcome:
    - Annotated commit message feature payload.
    - Integrated commit metadata for anomaly scoring.

3. pre-push
  - Runs before pushing refs to remote.
  - Functionality:
    - Aggregate commit-level features for the outgoing batch.
    - Evaluate branch provenance and push timing anomalies.
    - Query local baseline and remote model service for early anomaly scoring.
    - Optionally block push if the commit batch exceeds low-latency risk thresholds.
  - Outcome:
    - Commit payload and developer identity context forwarded to remote scoring.
    - Local event log entry with `pre-push` stage verdict.

#### 1.1.2 Server-side Hook Architecture

Server-side enforcement is based on Git host integration and CI orchestration, with both immediate and eventual evaluation.

1. update / pre-receive
  - Trigger point: remote receive of refs pushed to the repository.
  - Functionality:
    - Validate the pushed commit graph against repository policy.
    - Enforce branch protection rules, required status checks, and code-owner change alerts.
    - Perform a first-pass anomaly check on the pushed commit objects.
  - Deployment:
    - Kubernetes sidecar or Git hosting plugin for GitLab/GitHub Enterprise.

2. post-receive
  - Trigger point: after refs are updated.
  - Functionality:
    - Materialize the final commit features into the central analytics cluster.
    - Recompute historical baselines if high-risk behavior is detected.
    - Enqueue AnomalyEvent creation for persistent auditing.
    - Trigger alerting and workflow automation when score thresholds are exceeded.

3. CI / pipeline integration
  - Trigger on pull request / merge request creation and push events.
  - Perform deeper behavioral verification with full repository context.
  - Cross-check commit features with build/test outcomes, security scan results, and dependency changes.

#### 1.1.3 Hook Execution Model

- Hooks are shipped as an extensible agent package installed into repositories or global Git config.
- Hooks communicate with a local feature store and optionally a remote scoring endpoint.
- Client-side hooks are designed to be idempotent, fast, and safe to bypass only under explicit admin policy.
- Server-side hooks are authoritative: they can reject pushes and raise AnomalyEvents.

#### 1.1.4 Deployment Modes

- Managed SaaS mode: remote model inference and baseline storage in cloud.
- Hybrid on-prem mode: local feature extraction with server-side scoring cluster in customer network.
- Air-gapped support: commit metadata export/import with offline scoring and periodic reconnection.

### 1.2 Feature Collection Engine

The Feature Collection Engine is the core observability plane for CBAD. It captures commit and developer behavior signals across six domains: Time, Code, Repository, Developer, Language, and Tooling.

#### 1.2.1 Core Components

- Collector adapters
  - `GitDiffCollector`
  - `CommitMessageCollector`
  - `RepositoryMetadataCollector`
  - `EnvironmentMetadataCollector`
  - `DeveloperIdentityCollector`
  - `LanguageFeatureCollector`

- Feature pipeline
  - `extract` → `normalize` → `enrich` → `serialize`
  - Supports both synchronous hook mode and asynchronous batch mode

- Feature store
  - Local persistent feature cache in `~/.cbad/` or repository `.git/cbad/`
  - Central feature store in PostgreSQL + object storage for raw diffs

- Baseline manager
  - Maintains moving windows and summary statistics per developer and branch
  - Supports incremental updates, decay, and covariance tracking

- Model service interface
  - Exposes gRPC/HTTP scoring API
  - Accepts feature payloads and returns anomaly score + explanation vectors

#### 1.2.2 Feature Domains and Metrics

##### Time Domain

1. commit_timestamp_utc
2. commit_day_of_week
3. commit_hour_local
4. commit_minute_bucket
5. time_since_last_commit_seconds
6. time_since_last_push_seconds
7. commit_cadence_per_week
8. commit_cadence_percentile
9. work_hour_ratio
10. weekend_commit_flag
11. holiday_commit_flag
12. late_night_commit_flag
13. branch_age_days
14. commit_age_since_repo_creation_days
15. burst_commit_count_last_24h

##### Code Domain

16. files_changed_count
17. lines_added
18. lines_deleted
19. net_line_delta
20. churn_ratio
21. binary_file_change_count
22. executable_file_change_count
23. renamed_file_count
24. new_file_count
25. deleted_file_count
26. changed_file_ext_count
27. top_filetype_change_ratio
28. average_file_change_size
29. max_file_change_size
30. cyclomatic_complexity_delta
31. code_entropy_delta
32. TODO_FIXME_comment_delta
33. comment_to_code_ratio_delta
34. test_file_change_ratio
35. src_to_test_change_ratio
36. patch_hunk_count
37. patch_hunk_size_variance
38. documentation_file_change_count
39. security_file_change_count
40. dependency_manifest_delta
41. license_file_change_flag
42. path_depth_change_mean
43. code_style_violation_count
44. formatting_diff_ratio

##### Repository Domain

45. branch_protection_state
46. push_protection_state
47. branch_distance_from_default
48. merge_base_distance_commits
49. repo_commit_rate_change
50. repo_issue_link_density
51. open_pr_count
52. active_reviewer_count
53. repo_size_mb
54. source_to_test_ratio
55. repo_language_mix_entropy
56. recent_security_scan_findings_count
57. recent_build_failure_rate
58. package_dependency_delta_count
59. submodule_change_flag
60. monorepo_topology_flag
61. sensitive_path_change_flag
62. hidden_file_change_flag

##### Developer Domain

63. developer_id_hash
64. author_email_domain
65. author_username_stability_score
66. device_fingerprint_hash
67. git_client_version
68. commit_authoring_latency_seconds
69. author_experience_days
70. developer_role_vector
71. prior_anomaly_count
72. prior_anomaly_rate
73. commit_size_vs_baseline_zscore
74. developer_commit_distribution_entropy
75. author_pairing_signal
76. author_change_of_significant_files
77. identity_drift_score
78. timezone_drift_flag
79. author_reviewer_delta
80. prior_failed_build_ratio
81. approved_merge_count_last_30d

##### Language Domain

82. primary_language
83. file_language_mix_ratio
84. new_language_introduction_flag
85. syntax_error_count
86. linter_violation_delta
87. language_specific_security_flag
88. language_feature_usage_vector
89. language_dependency_risk_score
90. language_typing_intensity_change
91. language_linted_files_ratio

##### Tooling Domain

92. devtool_signature_hash
93. pre_commit_toolchain_used_flag
94. formatter_used_flag
95. ci_skipped_flag
96. hook_bypass_flag
97. git_commit_template_used_flag
98. git_user_config_changes_flag
99. local_config_changes_flag
100. build_tool_changes_flag
101. security_tooling_changes_flag
102. git_remote_endpoint_type
103. ssh_key_type
104. git_push_transport
105. codegen_file_change_flag
106. package_manager_lockfile_change_flag

#### 1.2.3 Feature Extraction and Enrichment

- Raw signals are extracted from Git metadata, diff parsers, commit message parsers, language analyzers, and local environment collectors.
- Enrichment layers add external context:
  - issue tracker metadata
  - geographic location of developer IP (optional)
  - team assignment and role metadata
  - repository policy classification
- Feature normalization is applied at extraction time using baseline statistics to produce `zscore`, `rank_percentile`, and `anomaly_delta` values.
- Each feature is tagged with provenance metadata: `source`, `stage`, `version`, `domain`, and `confidence`.

#### 1.2.4 Feature Lifecycle

- Client-side hooks persist draft feature payloads to a local feature cache.
- On pre-push, the engine bundles commit feature vectors and sends them to the remote scoring endpoint.
- Server-side hooks receive the final commit graph and materialize features into the central behavior store.
- The Baseline Manager updates developer profiles and drift indicators continuously.
- AnomalyEvent records are generated for commits that exceed configured thresholds or match high-risk signatures.

#### 1.2.5 Operational Guarantees

- Low-latency evaluation for `pre-commit` and `pre-push` through optimized feature extraction.
- Deterministic commit metadata capture for reproducibility.
- Hook failure tolerance: when the feature engine is unavailable, hooks degrade to non-blocking audit mode with telemetry.
- Tamper-evident data collection by signing feature payloads and commit metadata.

## SECTION 2 — Data Model

## SECTION 2 — Data Model

### 2.1 BehaviorProfile Schema

BehaviorProfile tracks developer-specific behavioral baselines and long-term profile statistics.

#### JSON Schema

```json
{
  "$id": "https://cba d.example.com/schemas/behaviorprofile.json",
  "$schema": "http://json-schema.org/draft/2020-12/schema#",
  "title": "BehaviorProfile",
  "type": "object",
  "properties": {
    "profile_id": {"type": "string", "format": "uuid"},
    "developer_id": {"type": "string"},
    "repository_id": {"type": ["string", "null"]},
    "profile_window_days": {"type": "integer", "minimum": 1},
    "feature_summary": {
      "type": "object",
      "properties": {
        "mean": {"type": "object", "additionalProperties": {"type": "number"}},
        "stddev": {"type": "object", "additionalProperties": {"type": "number"}},
        "skew": {"type": "object", "additionalProperties": {"type": "number"}},
        "kurtosis": {"type": "object", "additionalProperties": {"type": "number"}},
        "percentile_50": {"type": "object", "additionalProperties": {"type": "number"}},
        "percentile_90": {"type": "object", "additionalProperties": {"type": "number"}}
      },
      "required": ["mean", "stddev"]
    },
    "drift_metrics": {
      "type": "object",
      "properties": {
        "feature_drift_score": {"type": "number"},
        "identity_drift_score": {"type": "number"},
        "cadence_drift_score": {"type": "number"},
        "recent_anomaly_rate": {"type": "number", "minimum": 0, "maximum": 1}
      },
      "required": ["feature_drift_score", "identity_drift_score", "cadence_drift_score", "recent_anomaly_rate"]
    },
    "baseline_hash": {"type": "string"},
    "feature_count": {"type": "integer", "minimum": 0},
    "window_start": {"type": "string", "format": "date-time"},
    "window_end": {"type": "string", "format": "date-time"},
    "last_updated_at": {"type": "string", "format": "date-time"},
    "model_version": {"type": "string"},
    "tags": {"type": "array", "items": {"type": "string"}},
    "metadata": {"type": "object", "additionalProperties": true}
  },
  "required": ["profile_id", "developer_id", "feature_summary", "drift_metrics", "feature_count", "window_start", "window_end", "last_updated_at"]
}
```

#### PostgreSQL SQL Schema

```sql
CREATE TABLE cbad.behavior_profiles (
  profile_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  developer_id text NOT NULL,
  repository_id text,
  profile_window_days integer NOT NULL DEFAULT 90,
  feature_summary jsonb NOT NULL,
  drift_metrics jsonb NOT NULL,
  baseline_hash text NOT NULL,
  feature_count integer NOT NULL DEFAULT 0,
  window_start timestamptz NOT NULL,
  window_end timestamptz NOT NULL,
  last_updated_at timestamptz NOT NULL DEFAULT now(),
  model_version text NOT NULL,
  tags text[] NOT NULL DEFAULT ARRAY[]::text[],
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_behavior_profiles_developer_id ON cbad.behavior_profiles (developer_id);
CREATE INDEX idx_behavior_profiles_repository_id ON cbad.behavior_profiles (repository_id);
CREATE INDEX idx_behavior_profiles_last_updated_at ON cbad.behavior_profiles (last_updated_at);
CREATE INDEX idx_behavior_profiles_profile_window ON cbad.behavior_profiles (profile_window_days);
CREATE INDEX idx_behavior_profiles_baseline_hash ON cbad.behavior_profiles USING hash (baseline_hash);
```

#### MongoDB Schema

```json
{
  "collection": "behavior_profiles",
  "schema": {
    "bsonType": "object",
    "required": ["profile_id", "developer_id", "feature_summary", "drift_metrics", "feature_count", "window_start", "window_end", "last_updated_at"],
    "properties": {
      "profile_id": {"bsonType": "binData", "description": "UUID"},
      "developer_id": {"bsonType": "string"},
      "repository_id": {"bsonType": ["string", "null"]},
      "profile_window_days": {"bsonType": "int", "minimum": 1},
      "feature_summary": {
        "bsonType": "object",
        "additionalProperties": {"bsonType": "double"}
      },
      "drift_metrics": {
        "bsonType": "object",
        "properties": {
          "feature_drift_score": {"bsonType": "double"},
          "identity_drift_score": {"bsonType": "double"},
          "cadence_drift_score": {"bsonType": "double"},
          "recent_anomaly_rate": {"bsonType": "double"}
        }
      },
      "baseline_hash": {"bsonType": "string"},
      "feature_count": {"bsonType": "int"},
      "window_start": {"bsonType": "date"},
      "window_end": {"bsonType": "date"},
      "last_updated_at": {"bsonType": "date"},
      "model_version": {"bsonType": "string"},
      "tags": {"bsonType": "array", "items": {"bsonType": "string"}},
      "metadata": {"bsonType": "object"}
    }
  }
}
```

### 2.2 CommitFeatures Schema

CommitFeatures captures the commit-level feature vector, raw metadata, and structured author/repo context.

#### JSON Schema

```json
{
  "$id": "https://cba d.example.com/schemas/commitfeatures.json",
  "$schema": "http://json-schema.org/draft/2020-12/schema#",
  "title": "CommitFeatures",
  "type": "object",
  "properties": {
    "commit_id": {"type": "string"},
    "repository_id": {"type": "string"},
    "branch_name": {"type": "string"},
    "parent_commit_ids": {"type": "array", "items": {"type": "string"}},
    "developer_id": {"type": "string"},
    "author_name": {"type": "string"},
    "author_email": {"type": "string", "format": "email"},
    "author_date": {"type": "string", "format": "date-time"},
    "committer_date": {"type": "string", "format": "date-time"},
    "commit_message": {"type": "string"},
    "commit_message_features": {
      "type": "object",
      "properties": {
        "message_length": {"type": "integer"},
        "sentence_count": {"type": "integer"},
        "issue_reference_count": {"type": "integer"},
        "has_coauthor": {"type": "boolean"},
        "keyword_anomaly_score": {"type": "number"},
        "subject_entropy": {"type": "number"}
      },
      "required": ["message_length", "sentence_count", "issue_reference_count"]
    },
    "diff_features": {
      "type": "object",
      "properties": {
        "files_changed_count": {"type": "integer"},
        "lines_added": {"type": "integer"},
        "lines_deleted": {"type": "integer"},
        "net_line_delta": {"type": "integer"},
        "binary_file_change_count": {"type": "integer"},
        "rename_count": {"type": "integer"},
        "hunk_count": {"type": "integer"},
        "max_hunk_size": {"type": "integer"},
        "avg_hunk_size": {"type": "number"}
      },
      "required": ["files_changed_count", "lines_added", "lines_deleted"]
    },
    "code_metrics": {
      "type": "object",
      "properties": {
        "cyclomatic_complexity_delta": {"type": "number"},
        "comment_to_code_ratio_delta": {"type": "number"},
        "todo_fixme_delta": {"type": "integer"},
        "test_file_change_ratio": {"type": "number"},
        "documentation_change_count": {"type": "integer"}
      }
    },
    "time_features": {
      "type": "object",
      "properties": {
        "commit_day_of_week": {"type": "integer", "minimum": 0, "maximum": 6},
        "commit_hour_local": {"type": "integer", "minimum": 0, "maximum": 23},
        "time_since_last_commit_seconds": {"type": ["integer", "null"]},
        "weekend_commit": {"type": "boolean"},
        "holiday_commit": {"type": "boolean"}
      },
      "required": ["commit_day_of_week", "commit_hour_local"]
    },
    "repository_features": {
      "type": "object",
      "properties": {
        "branch_distance_from_default": {"type": "integer"},
        "merge_base_distance_commits": {"type": "integer"},
        "open_pr_count": {"type": "integer"},
        "recent_build_failure_rate": {"type": "number"}
      }
    },
    "developer_features": {
      "type": "object",
      "properties": {
        "developer_experience_days": {"type": "integer"},
        "prior_anomaly_count": {"type": "integer"},
        "prior_anomaly_rate": {"type": "number"}
      }
    },
    "language_features": {
      "type": "object",
      "properties": {
        "primary_language": {"type": "string"},
        "language_mix_entropy": {"type": "number"},
        "syntax_error_count": {"type": "integer"}
      }
    },
    "tooling_features": {
      "type": "object",
      "properties": {
        "git_client_version": {"type": "string"},
        "formatter_used": {"type": "boolean"},
        "precommit_toolchain_present": {"type": "boolean"},
        "hook_bypass_flag": {"type": "boolean"}
      }
    },
    "feature_vector": {
      "type": "object",
      "additionalProperties": {"type": "number"}
    },
    "raw_diff": {"type": ["string", "null"]},
    "metadata": {"type": "object", "additionalProperties": true},
    "created_at": {"type": "string", "format": "date-time"}
  },
  "required": ["commit_id", "repository_id", "developer_id", "author_date", "committer_date", "commit_message", "feature_vector", "created_at"]
}
```

#### PostgreSQL SQL Schema

```sql
CREATE TABLE cbad.commit_features (
  commit_id text PRIMARY KEY,
  repository_id text NOT NULL,
  branch_name text NOT NULL,
  parent_commit_ids text[] NOT NULL,
  developer_id text NOT NULL,
  author_name text NOT NULL,
  author_email text NOT NULL,
  author_date timestamptz NOT NULL,
  committer_date timestamptz NOT NULL,
  commit_message text NOT NULL,
  commit_message_features jsonb NOT NULL,
  diff_features jsonb NOT NULL,
  code_metrics jsonb NOT NULL,
  time_features jsonb NOT NULL,
  repository_features jsonb NOT NULL,
  developer_features jsonb NOT NULL,
  language_features jsonb NOT NULL,
  tooling_features jsonb NOT NULL,
  feature_vector jsonb NOT NULL,
  raw_diff text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  model_version text NOT NULL,
  anomaly_score numeric,
  anomaly_label text,
  feature_source text
);

CREATE INDEX idx_commit_features_repository ON cbad.commit_features (repository_id);
CREATE INDEX idx_commit_features_developer ON cbad.commit_features (developer_id);
CREATE INDEX idx_commit_features_author_date ON cbad.commit_features (author_date);
CREATE INDEX idx_commit_features_branch_name ON cbad.commit_features (branch_name);
CREATE INDEX idx_commit_features_anomaly_score ON cbad.commit_features (anomaly_score);
CREATE INDEX idx_commit_features_parent_commit_ids ON cbad.commit_features USING gin (parent_commit_ids);
CREATE INDEX idx_commit_features_feature_vector ON cbad.commit_features USING gin (feature_vector jsonb_path_ops);
```

#### MongoDB Schema

```json
{
  "collection": "commit_features",
  "schema": {
    "bsonType": "object",
    "required": ["commit_id", "repository_id", "developer_id", "author_date", "committer_date", "commit_message", "feature_vector", "created_at"],
    "properties": {
      "commit_id": {"bsonType": "string"},
      "repository_id": {"bsonType": "string"},
      "branch_name": {"bsonType": "string"},
      "parent_commit_ids": {"bsonType": "array", "items": {"bsonType": "string"}},
      "developer_id": {"bsonType": "string"},
      "author_name": {"bsonType": "string"},
      "author_email": {"bsonType": "string"},
      "author_date": {"bsonType": "date"},
      "committer_date": {"bsonType": "date"},
      "commit_message": {"bsonType": "string"},
      "commit_message_features": {"bsonType": "object"},
      "diff_features": {"bsonType": "object"},
      "code_metrics": {"bsonType": "object"},
      "time_features": {"bsonType": "object"},
      "repository_features": {"bsonType": "object"},
      "developer_features": {"bsonType": "object"},
      "language_features": {"bsonType": "object"},
      "tooling_features": {"bsonType": "object"},
      "feature_vector": {"bsonType": "object"},
      "raw_diff": {"bsonType": ["string", "null"]},
      "metadata": {"bsonType": "object"},
      "created_at": {"bsonType": "date"},
      "model_version": {"bsonType": "string"},
      "anomaly_score": {"bsonType": ["double", "int", "decimal"]},
      "anomaly_label": {"bsonType": "string"},
      "feature_source": {"bsonType": "string"}
    }
  }
}
```

### 2.3 DeveloperBaseline Schema

DeveloperBaseline stores live baselines, risk thresholds, and per-developer anomaly policy metadata.

#### JSON Schema

```json
{
  "$id": "https://cba d.example.com/schemas/developerbaseline.json",
  "$schema": "http://json-schema.org/draft/2020-12/schema#",
  "title": "DeveloperBaseline",
  "type": "object",
  "properties": {
    "baseline_id": {"type": "string", "format": "uuid"},
    "developer_id": {"type": "string"},
    "repository_id": {"type": ["string", "null"]},
    "baseline_window_days": {"type": "integer", "minimum": 1},
    "feature_statistics": {
      "type": "object",
      "properties": {
        "mean": {"type": "object", "additionalProperties": {"type": "number"}},
        "stddev": {"type": "object", "additionalProperties": {"type": "number"}},
        "min": {"type": "object", "additionalProperties": {"type": "number"}},
        "max": {"type": "object", "additionalProperties": {"type": "number"}},
        "median": {"type": "object", "additionalProperties": {"type": "number"}}
      },
      "required": ["mean", "stddev", "min", "max"]
    },
    "thresholds": {
      "type": "object",
      "properties": {
        "zscore_threshold": {"type": "number"},
        "score_threshold": {"type": "number"},
        "probability_threshold": {"type": "number"},
        "confidence_threshold": {"type": "number"}
      },
      "required": ["zscore_threshold", "score_threshold"]
    },
    "policy_flags": {
      "type": "object",
      "properties": {
        "block_push_on_high_risk": {"type": "boolean"},
        "require_manual_review_on_medium_risk": {"type": "boolean"},
        "allow_offline_mode": {"type": "boolean"}
      }
    },
    "evaluation_state": {
      "type": "object",
      "properties": {
        "last_evaluated_at": {"type": "string", "format": "date-time"},
        "last_score": {"type": "number"},
        "baseline_age_days": {"type": "integer"}
      },
      "required": ["last_evaluated_at", "last_score"]
    },
    "metadata": {"type": "object", "additionalProperties": true}
  },
  "required": ["baseline_id", "developer_id", "baseline_window_days", "feature_statistics", "thresholds", "evaluation_state"]
}
```

#### PostgreSQL SQL Schema

```sql
CREATE TABLE cbad.developer_baselines (
  baseline_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  developer_id text NOT NULL,
  repository_id text,
  baseline_window_days integer NOT NULL DEFAULT 90,
  feature_statistics jsonb NOT NULL,
  thresholds jsonb NOT NULL,
  policy_flags jsonb NOT NULL DEFAULT '{}'::jsonb,
  evaluation_state jsonb NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_developer_baselines_developer_id ON cbad.developer_baselines (developer_id);
CREATE INDEX idx_developer_baselines_repository_id ON cbad.developer_baselines (repository_id);
CREATE INDEX idx_developer_baselines_updated_at ON cbad.developer_baselines (updated_at);
```

#### MongoDB Schema

```json
{
  "collection": "developer_baselines",
  "schema": {
    "bsonType": "object",
    "required": ["baseline_id", "developer_id", "baseline_window_days", "feature_statistics", "thresholds", "evaluation_state"],
    "properties": {
      "baseline_id": {"bsonType": "binData"},
      "developer_id": {"bsonType": "string"},
      "repository_id": {"bsonType": ["string", "null"]},
      "baseline_window_days": {"bsonType": "int", "minimum": 1},
      "feature_statistics": {"bsonType": "object"},
      "thresholds": {"bsonType": "object"},
      "policy_flags": {"bsonType": "object"},
      "evaluation_state": {"bsonType": "object"},
      "metadata": {"bsonType": "object"},
      "created_at": {"bsonType": "date"},
      "updated_at": {"bsonType": "date"}
    }
  }
}
```

### 2.4 AnomalyEvent Schema

AnomalyEvent records anomaly detections, scoring outcomes, and response actions.

#### JSON Schema

```json
{
  "$id": "https://cba d.example.com/schemas/anomalyevent.json",
  "$schema": "http://json-schema.org/draft/2020-12/schema#",
  "title": "AnomalyEvent",
  "type": "object",
  "properties": {
    "event_id": {"type": "string", "format": "uuid"},
    "commit_id": {"type": "string"},
    "repository_id": {"type": "string"},
    "developer_id": {"type": "string"},
    "detected_at": {"type": "string", "format": "date-time"},
    "stage": {"type": "string", "enum": ["pre-commit", "commit-msg", "pre-push", "server-pre-receive", "server-post-receive", "ci", "audit"]},
    "anomaly_score": {"type": "number"},
    "anomaly_label": {"type": "string"},
    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
    "detection_reason": {"type": "string"},
    "feature_contributions": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "feature_name": {"type": "string"},
          "feature_value": {"type": ["number", "string", "boolean", "null"]},
          "contribution_score": {"type": "number"},
          "domain": {"type": "string"}
        },
        "required": ["feature_name", "contribution_score", "domain"]
      }
    },
    "actions": {
      "type": "array",
      "items": {"type": "string"}
    },
    "policy_snapshot": {"type": "object", "additionalProperties": true},
    "model_version": {"type": "string"},
    "review_ticket_id": {"type": ["string", "null"]},
    "metadata": {"type": "object", "additionalProperties": true}
  },
  "required": ["event_id", "commit_id", "repository_id", "developer_id", "detected_at", "stage", "anomaly_score", "severity", "detection_reason"]
}
```

#### PostgreSQL SQL Schema

```sql
CREATE TABLE cbad.anomaly_events (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  commit_id text NOT NULL,
  repository_id text NOT NULL,
  developer_id text NOT NULL,
  detected_at timestamptz NOT NULL DEFAULT now(),
  stage text NOT NULL,
  anomaly_score numeric NOT NULL,
  anomaly_label text NOT NULL,
  severity text NOT NULL,
  detection_reason text NOT NULL,
  feature_contributions jsonb NOT NULL,
  actions text[] NOT NULL DEFAULT ARRAY[]::text[],
  policy_snapshot jsonb NOT NULL,
  model_version text NOT NULL,
  review_ticket_id text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_anomaly_events_commit_id ON cbad.anomaly_events (commit_id);
CREATE INDEX idx_anomaly_events_repository_id ON cbad.anomaly_events (repository_id);
CREATE INDEX idx_anomaly_events_developer_id ON cbad.anomaly_events (developer_id);
CREATE INDEX idx_anomaly_events_detected_at ON cbad.anomaly_events (detected_at);
CREATE INDEX idx_anomaly_events_severity ON cbad.anomaly_events (severity);
CREATE INDEX idx_anomaly_events_anomaly_score ON cbad.anomaly_events (anomaly_score);
```

#### MongoDB Schema

```json
{
  "collection": "anomaly_events",
  "schema": {
    "bsonType": "object",
    "required": ["event_id", "commit_id", "repository_id", "developer_id", "detected_at", "stage", "anomaly_score", "severity", "detection_reason"],
    "properties": {
      "event_id": {"bsonType": "binData"},
      "commit_id": {"bsonType": "string"},
      "repository_id": {"bsonType": "string"},
      "developer_id": {"bsonType": "string"},
      "detected_at": {"bsonType": "date"},
      "stage": {"bsonType": "string"},
      "anomaly_score": {"bsonType": "double"},
      "anomaly_label": {"bsonType": "string"},
      "severity": {"bsonType": "string"},
      "detection_reason": {"bsonType": "string"},
      "feature_contributions": {"bsonType": "array"},
      "actions": {"bsonType": "array", "items": {"bsonType": "string"}},
      "policy_snapshot": {"bsonType": "object"},
      "model_version": {"bsonType": "string"},
      "review_ticket_id": {"bsonType": ["string", "null"]},
      "metadata": {"bsonType": "object"}
    }
  }
}
```
