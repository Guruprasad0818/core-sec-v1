# CBAD Stage 3 — MLOps, Serving, and Data Drift

## SECTION 4 — MLOps, Serving & Data Drift

### 4.1 Overview

Stage 3 MLOps must support a CVE prediction platform with enterprise-grade reliability, observability, and automated retraining. The architecture includes:
- high-performance inference endpoints for real-time and batch scoring
- data drift detection to capture changing developer and attack patterns
- automated retraining pipelines driven by drift and label refresh
- enterprise deployment topology with scale, resiliency, and governance

### 4.2 Model serving architecture

#### 4.2.1 Serving modes

1. `Real-time inference`
   - low-latency scoring for cache admission, security alerts, and remediation automation
   - exposes REST/gRPC endpoints for single package/repository prediction
   - supports feature lookup from feature store caches and preprocessing pipelines

2. `Batch inference`
   - scheduled nightly or hourly scoring of package/repo cohorts
   - supports bulk risk refresh for dashboards and downstream automation
   - writes results to a feature materialization store and event bus

3. `Shadow inference`
   - parallel scoring of production data with candidate models
   - enables model comparison and guardrail validation before promotion

#### 4.2.2 Inference stack

- `API gateway` with authentication, rate limiting, and routing
- `Feature service` for retrieving precomputed feature vectors and filling missing values
- `Model service` running XGBoost inference via `treelite`, `ONNX Runtime`, or `XGBoost` native booster
- `Explainability service` for SHAP payload generation on demand
- `Cache layer` using Redis or Memcached for hot feature and prediction caching
- `Event bus` for logging prediction decisions and downstream action triggers

#### 4.2.3 High-performance endpoint design

- use `FastAPI`, `gRPC`, or equivalent frameworks for low overhead
- deploy model service pods with autoscaling based on request latency and QPS
- leverage CPU-optimized instances with `AVX2` or `AVX512` support for tree inference
- preload serialized model artifacts and feature metadata in warm instances
- use asynchronous request handling for concurrent scoring
- implement request batching where acceptable for throughput improvements

#### 4.2.4 Inference workflow

1. receive inference request with artifact/package context
2. validate request and authenticate tenant
3. fetch feature vector from feature cache or compute on the fly
4. apply deterministic preprocessing and feature mapping
5. score using XGBoost model and calibration layer
6. optionally compute SHAP explanation for actionable predictions
7. return prediction probability, confidence interval, and top contributors
8. emit audit event to the prediction log

#### 4.2.5 Performance optimization

- use `treelite` compiled models for low-latency CPU inference
- apply model distillation if the full ensemble is too heavy for certain services
- reserve a fast-path for top-tier critical predictions with less explainability overhead
- deploy a tiered serving architecture: low-latency endpoint for high-priority requests, asynchronous batch endpoint for bulk scoring

### 4.3 Data drift detection engines

#### 4.3.1 Drift dimensions

The system monitors drift in both input features and target labels to detect changing developer behavior or adversarial patterns.

Drift categories:
- `feature drift`: distribution shift in input features such as patch latency, commit velocity, issue counts
- `target drift`: changes in CVE occurrence rates or severity distributions
- `concept drift`: changes in the relationship between features and CVE risk

#### 4.3.2 Detection components

- `Feature distribution monitor`
  - track rolling statistics: mean, variance, skew, kurtosis per feature
  - compute population divergence metrics: KL divergence, Wasserstein distance, PSI
  - use baseline reference windows (e.g. previous 30d, 90d) for comparison

- `Prediction distribution monitor`
  - monitor score histograms, top-k risk rates, and threshold crossing frequencies
  - alert if the proportion of high-risk predictions changes significantly

- `Residual drift monitor`
  - compare predicted probabilities to eventual observed CVE labels
  - compute calibration drift and model error metrics over time

#### 4.3.3 Drift scoring and alerts

- compute `drift_score_feature` for each feature using an ensemble of divergence metrics
- compute `drift_score_overall` as weighted aggregate:
  - 40% feature distribution drift
  - 30% prediction distribution drift
  - 30% residual/concept drift
- threshold drift alerts at `0.25` for moderate and `0.50` for critical drift in normalized drift space

#### 4.3.4 Operational drift pipeline

1. collect input feature data and predictions in a streaming store
2. aggregate daily and weekly rollups
3. compare against reference windows and historical baseline
4. produce drift reports and time series dashboards
5. trigger retraining pipeline when drift thresholds are exceeded or when label volume grows sufficiently

#### 4.3.5 Adversarial drift considerations

- use attack pattern detection to identify sudden surges in typosquat or dependency confusion signals
- correlate drift with external threat signals such as vulnerability feed spikes or exploit publications
- preserve a holdout dataset of historical adversarial examples for validation

### 4.4 Automated retraining pipeline

#### 4.4.1 Retraining triggers

- scheduled retraining (e.g. weekly or monthly)
- drift-triggered retraining when model input or concept drift is detected
- data refresh-driven retraining when new CVE labels are ingested
- performance decay retraining when key metrics degrade beyond thresholds

#### 4.4.2 Retraining workflow

1. `data ingestion` of fresh features and labels
2. `data validation` for feature completeness, label consistency, and schema stability
3. `training set assembly` with time-based splits and sample weighting
4. `hyperparameter search` using Bayesian or population-based tuning
5. `model evaluation` against out-of-time and adversarial holdout sets
6. `explainability generation` for candidate models
7. `candidate promotion` to staging after passing acceptance criteria
8. `shadow deployment` of candidate model alongside incumbent
9. `online validation` on live traffic and production metrics
10. `promotion` to production once stability and calibration are confirmed

#### 4.4.3 Retraining orchestration

- use MLOps pipeline orchestration tool such as Kubeflow Pipelines, Airflow, or MLflow
- store pipeline state, lineage, and artifact metadata in a central registry
- parallelize hyperparameter search and feature generation using distributed compute
- classify retraining runs by trigger source and assign priority accordingly

#### 4.4.4 Versioning and rollback

- semantic version model artifacts: `v{major}.{minor}.{patch}`
- maintain model registry metadata:
  - `model_id`
  - `training_start`
  - `training_end`
  - `feature_schema_hash`
  - `validation_metrics`
  - `drift_trigger_reason`
  - `artifact_location`
- use blue-green or canary deployment for model swap
- maintain fast rollback path to prior stable model on metric regression

### 4.5 Enterprise-scale deployment map

#### 4.5.1 Core service topology

- `Inference cluster`: stateless model-serving pods behind autoscaled ingress
- `Feature store cluster`: feature storage and serving layer with region-local read caches
- `Model registry`: artifact and metadata storage, integrated with CI/CD
- `Drift monitoring cluster`: ETL jobs and monitoring services for distribution and prediction drift
- `Retraining cluster`: batch compute for training, tuning, and validation
- `Audit/log cluster`: centralized logging, metrics, and alerting system

#### 4.5.2 Scaling strategy

- separate read and write workloads for feature storage
- scale inference horizontally by request volume and latency SLOs
- use region-local caches for frequently accessed features and predictions
- use autoscaling based on CPU, memory, and queue length for retraining workers
- partition feature and prediction data by tenant, ecosystem, or product line for scale

#### 4.5.3 Availability and resiliency

- deploy services in multi-AZ or multi-region clusters
- use stateful backing services with replication and failover: PostgreSQL/Aurora, Redis Sentinel, Cassandra, or cloud-native equivalents
- provide disaster recovery through cross-region model artifact replication and backup
- use health probes and circuit breakers to fail over gracefully when dependencies are degraded

#### 4.5.4 Security and governance

- enforce tenant isolation at the data and API layer
- use mTLS and IAM-based auth for internal service communication
- encrypt feature and model artifacts at rest and in transit
- audit all drift-triggered retraining and model promotions
- provide access control for model registry and explainability dashboards

#### 4.5.5 Example deployment mapping

- `us-east-1`: primary training and inference region, feature store master
- `eu-west-1`: secondary inference region with replicated feature cache and model artifacts
- `ap-southeast-1`: disaster recovery and audit archive
- `global edge`: regional API gateways fronting local inference caches for low-latency risk checks

#### 4.5.6 Observability

- instrument model metrics: latency, throughput, error rate, prediction distribution
- instrument data metrics: feature drift, missing value rates, label arrival rate
- instrument business metrics: ticket creation rate, PR bot actions, remediation cycle time
- use Prometheus/Grafana or cloud monitoring for dashboards and alerts

### 4.6 MLOps operational lifecycle

#### 4.6.1 Continuous training

- ingest new CVE and vulnerability data continuously
- schedule daily retraining candidate generation with the latest labels
- apply incremental model updates when verified and stable

#### 4.6.2 Model governance

- require approval gates for model promotion to production
- maintain model cards documenting training data, features, metrics, and intended use
- version feature transformations and preprocessing code with Git and metadata registry
- enforce audit trails for all production model changes

### 4.7 Summary

This Stage 3 MLOps design delivers a production-ready serving and retraining architecture for a CVE prediction platform. It includes high-performance inference, robust drift detection, automated retraining, and an enterprise-scale deployment map to support secure, resilient predictive risk operations.
