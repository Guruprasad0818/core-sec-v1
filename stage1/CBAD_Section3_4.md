# CBAD: ML Model Design and Secret Detection Layer

## SECTION 3 — ML Model Design

### 3.1 Overall Engineering Pipeline

CBAD uses a hybrid anomaly-detection stack combining statistical normalization, rule-based boundary detection, tree-based density modeling, and deep reconstruction. The production pipeline has four stages:

1. Feature normalization and baseline generation
2. Statistical anomaly detection using 3-sigma
3. Isolation Forest density-based anomaly scoring
4. Autoencoder reconstruction-error scoring

The final decision is a calibrated ensemble of these outputs, with explainability metadata stored per record.

#### 3.1.1 Data Ingestion and Preprocessing

- Source: `CommitFeatures.feature_vector` plus derived domain summaries.
- Input features are grouped into `time`, `code`, `repository`, `developer`, `language`, and `tooling` subsets.
- Features are labeled as either numerical, categorical ordinal, binary, or count-based.
- Preprocessing steps:
  - Missing-value imputation using domain-specific strategies:
    - numeric: rolling median or developer baseline median
    - categorical: `unknown`
    - counts: zero-fill
  - Outlier winsorization on extreme raw values using configurable quantiles (default 0.5%, 99.5%).
  - Feature log transforms for skewed counts and size metrics.
  - One-hot encoding for small cardinality categorical features (e.g. `git_push_transport`, `primary_language`).
  - Hash-bucket embeddings for high-cardinality text-derived feature names such as `issue_reference_type`.

#### 3.1.2 Feature Normalization

Normalization is required for both statistical anomaly detection and tree-based / neural models.

- `StandardScaler` per feature: `(x - mean) / stddev`
- `MinMaxScaler` for features that must remain bounded in `[0,1]` for the autoencoder
- `RobustScaler` for skewed features with heavy tails, using median and IQR
- Categorical embedding normalization with learned centroids during training

Normalization parameters are persisted in a versioned artifact store under `ml/feature_scalers/{model_version}/`.

#### 3.1.3 Baseline Drift and Adaptive Windowing

- Baseline windows are maintained at 30d, 90d, and 180d.
- Each developer and repo baseline stores mean, variance, min/max, percentile profiles, and covariance for paired features.
- A `BaselineRefreshJob` recomputes summary statistics nightly and triggers model retraining when baseline drift exceeds configured thresholds.
- Drift is calculated by:
  - symmetric KL divergence between baseline percentiles,
  - Mahalanobis distance of latest feature vector from baseline distribution,
  - feature-level shift using population z-scores.

### 3.2 3-Sigma Detection

The 3-sigma detector is the first-tier statistical anomaly guard.

#### 3.2.1 Detection formula

For each normalized numerical feature `f`:

- `z_f = (x_f - mu_f) / sigma_f`
- anomaly if `|z_f| > 3`
- weighted anomaly score: `score_3sigma = sigmoid(sum(w_f * clip(|z_f| - 3, 0, 10)))`

The weights `w_f` are configured by domain importance and learned by historical drift impact.

#### 3.2.2 Pros and Cons

Pros:
- Interpretable and deterministic.
- Fast to compute in local hook or edge mode.
- Low false-positive risk when baselines are stable.

Cons:
- Only captures univariate deviation.
- Sensitive to poor baseline estimation and non-Gaussian distributions.
- Cannot model correlated feature interactions.

#### 3.2.3 Production design

- Implement as a stateless service or embedded Python module with `scikit-learn` style transformers.
- Persist `mu` and `sigma` per feature using keyed JSON.
- Use adaptive thresholding for features with moderate skew: `threshold = 3 + alpha * skewness`.

### 3.3 Isolation Forest

Isolation Forest provides a robust multivariate outlier score.

#### 3.3.1 Architecture

- Model inputs: normalized numerical features, binary indicators, and dense categorical embeddings.
- Training dataset: benign historical commit vectors from the baseline window for each developer/repo segment.
- Hyperparameters:
  - `n_estimators=256`
  - `max_samples='auto'` with minimum `2048`
  - `max_features=0.8`
  - `contamination` calibrated from observed anomaly prevalence (default 0.01)
  - `bootstrap=True`

#### 3.3.2 Scoring

- Compute average path length across trees to produce `anomaly_score_iforest` in [0,1].
- Use the raw score and convert to a probability-like score via logistic scaling.
- Store model-specific contributions via Shapley-inspired path length attribution for top features.

#### 3.3.3 Pros and Cons

Pros:
- Detects multivariate anomalies without requiring labels.
- Handles heterogeneous feature sets well.
- Efficient inference suitable for local execution.

Cons:
- Sensitive to feature scaling and data sparsity.
- Can overfit on small per-developer datasets.
- Harder to explain than univariate rules.

### 3.4 Autoencoder Architecture

The autoencoder is the deep reconstruction component for nonlinear anomaly detection.

#### 3.4.1 Model architecture

- Input dimension: `N` normalized numeric features + dense categorical embeddings.
- Encoder:
  - Dense(256) → BatchNorm → GELU
  - Dense(128) → BatchNorm → GELU
  - Dense(64) → BatchNorm → GELU
  - Dense(32) bottleneck
- Decoder:
  - Dense(64) → BatchNorm → GELU
  - Dense(128) → BatchNorm → GELU
  - Dense(256) → BatchNorm → GELU
  - Dense(N) output

- Loss: weighted reconstruction MSE + sparsity penalty on bottleneck activations.
- Regularization:
  - dropout 0.1 on hidden layers,
  - L2 weight decay 1e-5,
  - early stopping on validation reconstruction error.
- Training schedule:
  - batch size 512,
  - learning rate 1e-3 with cosine decay,
  - warmup for 5 epochs,
  - maximum 200 epochs.

#### 3.4.2 Input handling

- Numerical features are normalized to [0, 1].
- Binary features are passed unchanged.
- Categorical predictors are embedded via learnable dense layers of size `min(32, cardinality//2)`.
- Sparse or high-cardinality fields are encoded through hash embedding, with hashing stable across model versions.

#### 3.4.3 Scoring

- Reconstruction error per feature: `(x - x_hat)^2`
- Weighted sum: `score_ae = sum(w_f * error_f)` where `w_f` is domain importance.
- Normalize score with baseline MSE distribution to generate `autoencoder_zscore`.
- Flag anomalies if `score_ae` exceeds the 99th percentile of the validation set.

#### 3.4.4 Pros and Cons

Pros:
- Models complex nonlinear relationships and joint feature dependencies.
- Good for detecting subtle behavioral drift patterns.
- Can learn developer-specific latent signatures from dense commit vectors.

Cons:
- Higher training and inference cost than simpler methods.
- Requires careful tuning to avoid false positives from rare but legitimate behavior.
- More difficult to explain without additional attribution tooling.

### 3.5 Ensemble and Final Scoring

CBAD composes outputs from the three detectors into a single anomaly verdict.

- `score_final = w1 * score_3sigma + w2 * score_iforest + w3 * score_ae`
- Weights are tuned using validation metrics and may be adjusted per deployment tier.
- Add rule-based overrides for critical features such as `hook_bypass_flag` or `sensitive_path_change_flag`.
- Calibrate output using isotonic regression on a labeled dataset to produce `P(anomaly)`.
- Persist feature contributions from each model for explainability and incident triage.

### 3.6 ONNX Compilation for Lightweight Local Execution

#### 3.6.1 Why ONNX

- Portable across Python, Rust, Go, Java runtimes.
- Enables local hook-side inference with low memory overhead.
- Supports CPU-only execution and accelerators where available.

#### 3.6.2 Export flow

- Train models in Python using `scikit-learn`, `PyTorch`, or `XGBoost`.
- For Isolation Forest:
  - Use `skl2onnx` to convert the trained `IsolationForest` object.
  - Persist normalization pipeline with `onnxruntime` compatible transforms.
- For Autoencoder:
  - Export the PyTorch model using `torch.onnx.export(model, x_dummy, "model.onnx", opset_version=14, input_names=[...], output_names=[...], dynamic_axes={...})`.
- For feature normalization:
  - Compose a preprocessing pipeline using ONNX `Scale`, `Add`, and `OneHotEncoder` nodes.
  - Alternatively export a Scikit-Learn `Pipeline` that includes preprocessing layers.
- For the ensemble:
  - Option A: export each model separately and implement a lightweight aggregator in the local runtime.
  - Option B: compile a final ONNX graph that combines normalized inputs, tree scoring, and weighted output nodes.

#### 3.6.3 Runtime

- Use `onnxruntime` or `onnxruntime-web` on client or server side.
- Local hook agent uses a cached `model.onnx` plus scaler metadata JSON.
- Score requests are made locally with `ort.InferenceSession("model.onnx")`.
- Fallback to remote scoring if local inference fails or the model artifacts are unavailable.

### 3.7 Model Retraining and Versioning

#### 3.7.1 Retraining strategy

- Scheduled retraining weekly for global models.
- Developer-specific and repo-specific baselines retrain nightly or when drift triggers.
- Retraining pipeline stages:
  1. collect labeled and unlabeled feature vectors
  2. clean and impute missing data
  3. update normalization scalers
  4. train 3-sigma stats, Isolation Forest, and Autoencoder
  5. validate on held-out windows and synthetic anomalies
  6. package artifacts, metrics, and model cards

- Use a `ModelTrainingJob` orchestrated by Kubernetes CronJob or Airflow.
- Periodically perform adversarial validation using historical anomaly injections.
- Maintain an `active` and `candidate` model version; only promote after passing acceptance thresholds.

#### 3.7.2 Versioning

- Semantic versioning format: `major.minor.patch+build`.
- Model metadata includes:
  - `model_id`
  - `model_version`
  - `created_at`
  - `training_data_window`
  - `feature_schema_hash`
  - `baseline_snapshot_id`
  - `validation_metrics`
  - `lineage_source`

- Store artifacts in object storage under
  - `s3://cbad-models/iforest/{model_version}/iforest.onnx`
  - `s3://cbad-models/autoencoder/{model_version}/autoencoder.onnx`
  - `s3://cbad-models/preprocessing/{model_version}/scaler.json`

- Maintain a manifest document for each version with promotion status and rollback metadata.
- Support zero-downtime model swapping by providing a `model_manifest.json` to the scoring service.

#### 3.7.3 Validation and rollback

- Validate candidate models with:
  - offline backtesting on the previous 180 days,
  - threshold-based feature drift checks,
  - production shadow scoring comparisons.
- If a model produces >10% more high-severity anomalies than the incumbent without improved precision, trigger rollback.
- Use iterative A/B testing with stable and experimental cohorts for gradual deployment.

## SECTION 4 — Secret Detection Layer

### 4.1 Integration Architecture

The Secret Detection Layer is an orthogonal security service integrated into CBAD to scan commit contents, staged changes, and repository history for sensitive secrets.

#### 4.1.1 Architectural components

- `SecretScanAgent` within local hooks and server-side pipelines
- `Rules Engine` for regex and entropy policies
- `Secret Scanner Orchestrator` to invoke:
  - `gitleaks`
  - `trufflehog`
  - custom entropy analyzer
  - regex engine for provider-specific patterns
- `Scan result normalizer` to convert disparate detections into a unified `SecretFinding` event.
- `SecretPolicyStore` for provider patterns, allowlists, and ignore rules.
- `Telemetry and audit` for scanning coverage, false positives, and scan performance.

#### 4.1.2 Execution modes

- Local pre-commit / pre-push scanning: fast heuristic checks + on-demand deeper scans.
- Server-side pre-receive scanning: authoritative detection before merge/push completion.
- CI pipeline scanning: batch scan of all commit contents and repo history on pull requests.
- Scheduled repository scanning: periodic deep scan across branches and tags.

### 4.2 Detection engines

#### 4.2.1 Gitleaks

- Use Gitleaks as the primary signature-based engine for known secret patterns.
- Deploy as an embedded binary or service via `gitleaks detect`.
- Configure custom rulesets for provider-specific secrets and repo-level allowlists.
- Integrate output into CBAD with normalized fields:
  - `rule_id`, `description`, `file_path`, `commit_id`, `line_number`, `secret_match`, `severity`.

#### 4.2.2 TruffleHog

- Use TruffleHog for entropy-based and high-risk string detection.
- Run on staged patches and commit diff contents.
- Capture both classic regex rules and deep entropy scoring.
- Normalize findings with a risk score derived from entropy and pattern confidence.

#### 4.2.3 Entropy scanning

- Implement a dedicated entropy scanner for raw text and binary patch contents.
- Use Shannon entropy on candidate substrings of length 20–100 bytes.
- Flag strings with entropy > 4.5 and additional pattern context (e.g., `=` or `:` separators).
- Use tunable rules to reduce false positives from base64-encoded assets and certificate blocks.

#### 4.2.4 Regex scanning

- Use a fast regex engine with anchored multiline support.
- Maintain provider-specific regex patterns for AWS, Azure, GCP, GitHub, Stripe, Slack, JWT, and DB credentials.
- Use a staged pattern hierarchy:
  - precise patterns first
  - broad fuzzy patterns second
  - entropy-based review third
- Support safe allowlists for developer names, public test data, and documented public keys.

### 4.3 Provider-specific detection matrix

#### AWS

- AWS Access Key ID: `AKIA[0-9A-Z]{16}`
- AWS Secret Access Key: `(?<![A-Za-z0-9+/=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])`
- AWS session token and S3 presigned URL detection
- CloudFormation hard-coded credentials and assumed-role ARNs

#### Azure

- Azure Storage account key: `[A-Za-z0-9]{44}`
- Azure SDK client secret placeholders
- Azure DevOps PAT and service principal secrets

#### GCP

- Google Cloud service account private keys: `"private_key": "-----BEGIN PRIVATE KEY-----`
- GCP OAuth tokens: `ya29\.[A-Za-z0-9\-_]+`
- GCP API keys: `AIza[0-9A-Za-z\-_]{35}`

#### GitHub

- GitHub personal access tokens: `ghp_[A-Za-z0-9_]{36}`
- GitHub App private keys and webhook secrets
- GitHub Actions secrets in YAML and `secrets.GITHUB_TOKEN` misuse

#### Stripe

- Stripe secret keys: `sk_live_[A-Za-z0-9]{24}`
- Stripe publishable keys: `pk_live_[A-Za-z0-9]{24}`
- Payment webhooks and signing secrets

#### Slack

- Slack bot tokens: `xox[baprs]-[A-Za-z0-9-]+`
- Slack app credentials and webhook URLs

#### JWT

- Base64-encoded JWT tokens in config and code.
- Signatures and private key leaks for `RS256`, `HS256`, `ES256`.
- Detect patterns like `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`

#### Database credentials

- JDBC and connection strings containing `username:password@`
- PostgreSQL URI patterns: `postgres://[^\s@]+:[^\s@]+@`
- MySQL, MSSQL, Redis, MongoDB connection string patterns
- Hard-coded SQL credentials in code and shell scripts

### 4.4 Secret scanning pipeline

1. Pre-filter files and diff hunks using file globs and extension allowlists.
2. Run regex scans on patch contents and raw blob text.
3. Execute Gitleaks with provider-specific and custom rulesets.
4. Execute TruffleHog on candidate changes and historical commits.
5. Apply entropy scoring to suspicious strings from regex matches.
6. Normalize findings and attach result tags:
   - `source`: `gitleaks` / `trufflehog` / `regex` / `entropy`
   - `confidence`: `low` / `medium` / `high`
   - `provider`: AWS / Azure / GCP / GitHub / Stripe / Slack / JWT / DB
   - `location`: file path + line range or commit diff hunk
7. Enforce policy actions:
   - `block_commit`
   - `warn_developer`
   - `require_review`
   - `auto_ignore` when allowlist matches

### 4.5 Operational hardening

- Use `allowlist.json` and `denylist.json` per repository and organization.
- Persist scan metadata to `SecretFinding` records.
- Add rate limiting to local scans to avoid workflow slowdown.
- Use a configurable `scan_depth` for server-side history scans to limit cost.
- For performance-sensitive hooks, use fast regex first and defer deeper entropy scans to PR/CI.

### 4.6 Audit and feedback loops

- Every secret finding is correlated with commit metadata and anomaly events.
- Track false-positive rates by developer and provider pattern.
- Use analyst feedback to refine rule sets and adjust entropy thresholds.
- Maintain a `secret_detection_model_version` in telemetry, analogous to the anomaly model version.

### 4.7 Example unified secret event schema

- `finding_id`
- `commit_id`
- `repository_id`
- `developer_id`
- `scan_stage` (`pre-commit`, `pre-push`, `server`, `ci`, `scheduled`)
- `source` (`gitleaks`, `trufflehog`, `regex`, `entropy`)
- `provider` (`AWS`, `Azure`, `GCP`, `GitHub`, `Stripe`, `Slack`, `JWT`, `DB`)
- `severity` (`low`, `medium`, `high`, `critical`)
- `confidence`
- `rule_id`
- `file_path`
- `line_number`
- `snippet`
- `match_text_hash`
- `action`
- `policy_snapshot`
- `created_at`

This design ensures CBAD captures both behavioral anomalies and secrets risk in a converged, production-grade security pipeline.
