# CBAD Stage 3 — ML Pipeline and Automation

## SECTION 2 — Machine Learning Pipeline

### 2.1 Overview

The CVE Prediction Platform uses a production ML pipeline centered on a gradient boosted decision tree ensemble, with XGBoost as the primary model family. This pipeline is designed for high reliability, repeatability, and explainability in a security-sensitive environment.

The architecture includes:
- feature ingestion and validation
- training data labeling and engineering
- model training and tuning
- model validation and calibration
- explainability generation with SHAP and LIME
- deployment artifact packaging and monitoring

### 2.2 Pipeline architecture

#### 2.2.1 Ingestion & feature store

- raw sources are ingested into a feature warehouse (e.g. Snowflake, BigQuery, or PostgreSQL + parquet lake)
- features are materialized in a feature store with time travel support and lineage metadata
- daily feature bundles are generated for training and inference with stable schemas
- feature validation involves:
  - null rate checks
  - value range checks
  - distribution drift tests
  - uniqueness and referential integrity

#### 2.2.2 Label generation

- label positive examples using historical CVE assignments to packages and repository components
- label windows:
  - `y=1` if a package/repository receives a CVE within the next 30/60/90 days
  - use multiple temporal horizons depending on use case
- exclude artifacts with insufficient history or non-security issue classes
- sample negative class carefully to avoid label leakage from latent vulnerabilities

#### 2.2.3 Model training workflow

1. extract feature vector matrix `X` and label vector `y` from the feature store
2. split by time-based cutoff to simulate production forecasting
3. apply feature transformations:
   - categorical encoding for ecosystem, license, maintainer org
   - target encoding for high cardinality package namespaces
   - scaling for tree-aware features not required, but numeric clipping and quantile normalization help
4. train XGBoost model on historical windows with early stopping
5. compute out-of-time cross-validation metrics
6. calibrate probabilities with isotonic regression or Platt scaling if needed
7. persist model artifacts, feature metadata, and training metrics

#### 2.2.4 Training orchestration

- orchestrate with Airflow, Kubeflow Pipelines, or SageMaker Pipelines
- use containerized steps for reproducibility:
  - data preparation
  - feature engineering
  - model training
  - evaluation
  - explainability computation
  - model packaging
- persist artifacts to versioned object storage with metadata:
  - `model_version`
  - `training_window`
  - `feature_schema_hash`
  - `hyperparameters`
  - `validation_metrics`

### 2.3 XGBoost ensemble design

#### 2.3.1 Model structure

- primary model: XGBoost binary classifier
- objective: `binary:logistic`
- base learner: tree booster
- ensemble: optionally stack multiple XGBoost models trained on different feature subsets or temporal cohorts
- use `TreeMethod=hist` for production speed and memory efficiency

#### 2.3.2 Feature subsets

- stable repository signals: commit velocity, issue velocity, maintainer activity
- vulnerability context signals: CVE age, exploit availability, advisory volume
- release/patch signals: patch latency, release frequency
- churn and maturity signals: contributor churn, repo age
- interaction features: commit_velocity * issue_velocity, maintainer_activity * patch_latency

#### 2.3.3 Hyperparameter tuning space

Use Bayesian optimization or grid search over these parameters:

- `learning_rate`: [0.01, 0.05, 0.1, 0.2]
- `n_estimators`: [200, 400, 800, 1200]
- `max_depth`: [4, 6, 8, 10, 12]
- `min_child_weight`: [1, 3, 5, 7]
- `gamma`: [0, 0.1, 0.2, 0.5]
- `subsample`: [0.6, 0.7, 0.8, 0.9, 1.0]
- `colsample_bytree`: [0.5, 0.6, 0.7, 0.8, 0.9]
- `colsample_bylevel`: [0.5, 0.7, 0.8, 1.0]
- `reg_alpha`: [0, 0.1, 0.5, 1.0]
- `reg_lambda`: [1, 2, 4, 8]
- `scale_pos_weight`: [1, 5, 10, 20, 50]
- `max_delta_step`: [0, 1, 3, 5]

Secondary tuning for ensemble and stacking:
- learning rate of stacked meta-learner
- feature subset selection regularization
- sample weights based on CVE severity and exploit maturity

### 2.4 Model validation

#### 2.4.1 Cross-validation strategy

- time-based validation using temporal splits to simulate forward prediction
- fold definitions: sliding windows with training on `T-365 to T-180`, validation on `T-179 to T-90`, test on `T-89 to T`
- use nested validation for hyperparameter tuning and final estimate
- alternate strategy: grouped CV validation by package namespace to avoid leakage across related artifacts

#### 2.4.2 Metrics for security risk optimization

Given high-critical security vulnerabilities are rare, optimize for:
- precision at high recall ranges for `y=1` class
- recall at top-K predicted risky packages
- AUROC and AUPRC for overall discriminatory power
- `F2` score to emphasize recall over precision for critical CVE detection
- custom `risk-adjusted` score that weights critical CVEs more heavily

Primary metrics:
- `Precision@top10%`
- `Recall@top10%`
- `AUPRC`
- `ROC-AUC`
- `F2-score`
- `CVE-weighted recall` with severity weights

Secondary diagnostics:
- confusion matrix at operational thresholds
- false-positive rate among high-risk predictions
- calibration error (Brier score)
- model stability across release cohorts

### 2.5 Feature importance and selection

#### 2.5.1 Importance computation

- compute feature importance using XGBoost built-in `gain`, `cover`, and `frequency`
- compute SHAP values for global and local importance
- derive permutation importance on holdout data for robustness
- track feature importance over time to identify drift or stale predictors

#### 2.5.2 Explainability layout

Explainability is critical for security operations and analyst trust. Provide:
- global feature importance ranked by mean absolute SHAP values
- per-prediction SHAP explanations for top 10 contributing features
- LIME local interpretation snapshots for selected decision points
- feature interaction explanations for pairs with high SHAP interaction values

Presentation components:
- `SHAP summary plot` for the model
- `SHAP dependence plots` for key features such as `patch_latency_median_90d`
- `force plots` for individual high-risk predictions
- `LIME explanations` for external review when SHAP is unavailable or to validate textual features
- `feature contributions` returned in API payloads

#### 2.5.3 Important feature candidates

Key predictors expected from the feature space:
- `patch_latency_90th_percentile`
- `issue_security_label_count_90d`
- `maintainer_bus_factor`
- `release_security_update_ratio`
- `commit_dependency_change_ratio`
- `repo_age_vs_activity_ratio`
- `issue_vulnerability_triage_completion_rate`
- `exploit_publication_lag`
- `release_signing_ratio`
- `contributor_turnover_rate_90d`

### 2.6 Explainability integration

#### 2.6.1 SHAP integration

- compute SHAP values during evaluation and store them for audit samples
- use `TreeExplainer` for XGBoost models for speed and exactness
- generate SHAP feature contributions in the inference path for high-confidence predictions
- persist `shap_summary`, `shap_values_top_n`, and `shap_interaction_values` in the explainability store

#### 2.6.2 LIME integration

- use LIME for models with feature preprocessing or when text-derived embeddings are included
- maintain LIME explainers for analyst workflows and debugging
- compare LIME explanations to SHAP for consistency checks

#### 2.6.3 Explainability API

Provide explainability responses with fields:
- `prediction_probability`
- `threshold_band`
- `top_contributing_features`
- `shap_values`
- `lime_explanations`
- `feature_reference_dataset`

### 2.7 Production deployment

#### 2.7.1 Model packaging

- serialize XGBoost model to `booster` binary and `ONNX`/`treelite` for low-latency inference
- package preprocessing pipeline and feature metadata with the model
- store artifact bundle in object storage with `model_version` and `schema_hash`

#### 2.7.2 Inference architecture

- use a dedicated scoring service with REST/gRPC endpoints
- support batch inference for daily risk scoring and per-artifact real-time scoring for cache admission
- use a feature cache for fast lookup of precomputed repo/package signals
- apply probability calibration in the inference service

#### 2.7.3 Monitoring and drift

- monitor model input distributions and feature drift daily
- compute prediction distribution drift and adverse prediction rates
- alert on significant changes in key features such as `patch_latency_median_90d`
- schedule retraining when drift exceeds thresholds or new CVE data is available

## SECTION 3 — Action Thresholds & Automation

### 3.1 Overview

This section defines how prediction confidence intervals map to automated actions. The system automates triage, remediation ticket creation, and an upgrade PR bot for predicted high-risk components.

### 3.2 Prediction confidence bands

Define prediction bands based on calibrated probability output `p`:
- `Low risk`: `p < 0.30`
- `Medium risk`: `0.30 <= p < 0.55`
- `High risk`: `0.55 <= p < 0.80`
- `Critical risk`: `p >= 0.80`

For CVE-critical targeting, use adjusted thresholds by severity and business impact:
- if severity weight > 1.5, lower `Critical risk` threshold to `0.70`
- if package is direct production dependency, raise `Medium risk` sensitivity by `0.05`

### 3.3 Automated action mapping

#### 3.3.1 Low risk

- no automatic remediation
- record prediction in risk dashboard
- schedule periodic re-evaluation

#### 3.3.2 Medium risk

- create a diagnostic review item in the platform
- generate an internal alert to security engineering
- optionally request additional telemetry collection or auditing

#### 3.3.3 High risk

- create a Jira ticket in the security backlog
- tag ticket with `CVE-prediction`, `high-risk`, `package-ecosystem`
- send an operational alert to the on-call security response team
- surface remediation recommendations in the dashboard

#### 3.3.4 Critical risk

- create Jira ticket with priority `P1` or `Critical`
- trigger the automated Upgrade PR Bot
- post to stakeholder channels (Slack, Teams) with details
- place artifact/package in a watchlist for continuous monitoring

### 3.4 Functional design of the automated upgrade PR bot

#### 3.4.1 Objective

The PR Bot automatically proposes dependency upgrades for packages predicted to be at high or critical CVE risk. It uses safe remediation heuristics and integrates with source control and dependency management workflows.

#### 3.4.2 Input signals

- package name, ecosystem, current version
- predicted risk probability and feature contributions
- available patched or newer versions from package feeds
- compatibility metadata from release notes and dependency manifests
- package adoption and semantic versioning policies
- repository dependency graph and transitive impact

#### 3.4.3 Bot workflow

1. `Risk event` created when prediction enters `high` or `critical` band.
2. `Upgrade candidate search` queries package feeds for patched versions.
3. `Compatibility check` uses dependency constraints, lockfile analysis, and existing CI workflows.
4. if safe candidate found, `create branch` in target repo
5. update dependency manifest and lockfiles
6. run local or CI-based validation tests
7. open PR with summary, risk rationale, and changelog link
8. optional automated reviewer assignment based on ownership
9. close or update PR on subsequent risk or compatibility changes

#### 3.4.4 PR Bot action rules

- prefer patch or minor versions unless explicit major-version upgrade is needed for security
- avoid upgrades that violate package lockfile semantics or internal version pin policies
- if multiple packages are simultaneously high-risk, group upgrades by repository and dependency scope
- for critical risk with no safe upgrade, create a remediation ticket instead of PR

#### 3.4.5 PR Bot architecture

- service receives events from prediction engine
- uses SCM API (GitHub/GitLab/Bitbucket) and package registry APIs
- includes `dry-run` mode for review before PR creation
- logs all actions and retains decision artifacts
- integrates with Jira API to link PRs to created tickets

#### 3.4.6 Example PR Bot event payload

```json
{
  "artifact_id": "pkg-pypi-requests-2.25.0",
  "prediction_probability": 0.83,
  "risk_category": "critical",
  "ecosystem": "pypi",
  "package_name": "requests",
  "current_version": "2.25.0",
  "recommended_versions": ["2.28.1", "2.29.0"],
  "repository": {
    "repo_id": "repo-123",
    "scm": "github",
    "owner": "acme",
    "name": "acme-backend"
  },
  "dependency_file_paths": ["requirements.txt", "Pipfile.lock"],
  "feature_explanations": {
    "patch_latency_90th_percentile": 0.18,
    "issue_security_label_count_90d": 0.16,
    "maintainer_bus_factor": 0.12
  },
  "timestamp": "2026-06-23T12:00:00Z"
}
```

#### 3.4.7 Jira ticket creation

Ticket payload:
```json
{
  "project_key": "SEC",
  "issuetype": "Task",
  "summary": "High-risk CVE prediction for requests 2.25.0",
  "description": "Predictive model indicates critical CVE risk for requests 2.25.0. Recommended upgrade to 2.28.x. Feature contributions: patch latency, issue velocity, maintainer bus factor.",
  "priority": "Critical",
  "labels": ["cve-prediction", "automated-alert", "requests"],
  "components": ["dependency-management"],
  "customfields": {
    "risk_score": 0.83,
    "predicted_cve_window": "30d"
  }
}
```

#### 3.4.8 Automation guardrails

- require manual approval for upgrades impacting more than `N` repos or major-version bumps
- verify that the package is not in a denylist before PR creation
- ensure PR does not exceed security policy constraints such as disallowed ecosystems or hostnames
- support `opt-out` labels on repos to prevent auto-PR on legacy branches

### 3.5 Confidence interval logic

- calculate calibrated probability intervals using isotonic regression
- represent as `[lower_bound, upper_bound]` for prediction uncertainty
- use intervals to differentiate fuzzy cases from decisive ones

Action mapping:
- `upper_bound < 0.30`: low risk, no action
- `0.30 <= lower_bound < 0.55`: medium risk, review
- `0.55 <= lower_bound < 0.80`: high risk, Jira ticket
- `lower_bound >= 0.80` or `p >= 0.80`: critical risk, Jira + PR bot
- if interval width > 0.20, create human review ticket even if point estimate is moderate

### 3.6 Automation ecosystem

- integrate prediction engine with orchestration systems (Airflow, event bus)
- use webhook-driven event propagation for real-time actioning
- persist action events and their outcomes for feedback into retraining
- close the loop by using remediation outcomes to label future training data and improve precision

### 3.7 Summary

This design captures an end-to-end production XGBoost-based machine learning pipeline for CVE prediction and operational automation. It aligns predictive confidence with ticketing and automated remediation workflows, suited for commercial-grade deployment.
