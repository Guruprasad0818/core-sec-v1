# CBAD Stage 9 — Live SBOM CVE Watcher and Production Guardian

## SECTION 1 — Continuous SBOM Lifecycle Monitor

### 1.1 Objectives
- Continuously ingest and normalize SBOM artifacts in CycloneDX and SPDX formats.
- Maintain a time-series inventory of component/material state for all deployed workloads.
- Cross-reference SBOM components against live vulnerability feeds from NVD, OSV, and GitHub Advisories.
- Detect newly exposed CVEs within a 5-minute window and escalate findings to production guardrail workflows.
- Support alerting, remediation tickets, and policy-driven mitigation triggers.

### 1.2 Architectural components
- `SBOM Collector`: receives SBOM pushes from CI/CD, image scanners, runtime agents, and GitOps pipelines.
- `Normalization Engine`: parses CycloneDX/SPDX, canonicalizes package coordinates, deduplicates by package/ecosystem/version.
- `Material Registry`: time-series store of SBOM manifests and component ancestry for active clusters and namespaces.
- `Vulnerability Stream Processor`: ingests external feeds, normalizes advisories, and computes live component-to-CVE mappings.
- `Exposure Engine`: evaluates which deployed assets are affected by current advisories and computes exposure urgency.
- `Guardrail API`: publishes findings, supports webhook notifications, and exposes remediation metadata.
- `Audit Store`: immutable record of SBOM ingestion, enrichment events, CVE matches, and policy decisions.

### 1.3 SBOM ingestion flows
#### 1.3.1 CI/CD and GitOps push
- Pipeline emits signed CycloneDX or SPDX manifest after build/image scan.
- `SBOM Collector` receives artifact over HTTPS or via object store event.
- Collector validates signature, checks schema version, and forwards to `Normalization Engine`.

#### 1.3.2 Runtime/image discovery
- Kubernetes Admission or runtime scanning agents attach SBOM metadata to container images at deployment.
- If SBOM is unavailable, `SBOM Collector` can trigger a fallback artifact fetch from OCI registry using image digest.

#### 1.3.3 Scheduled re-ingestion
- Periodic reconciliation polls cluster workloads and verifies the SBOM inventory with live deployed state.
- If a workload is active but missing an SBOM, it is flagged for prioritized remediation.

### 1.4 SBOM normalizer and canonical model
- Support CycloneDX 1.4+ and SPDX 2.x manifests.
- Normalize package coordinates into a single internal schema:
  - ecosystem: `npm`, `pypi`, `maven`, `golang`, `apk`, `deb`, `rpm`, `os`, `oci-image`
  - name
  - version
  - SHA256 digest / purl
  - metadata: supplier, license, component type, ext identifiers
- Compute a stable `material_id` using normalized purl and digest.
- Preserve provenance: `source_workflow`, `artifact_id`, `cluster`, `namespace`, `pod`, `container_name`, `image_digest`.
- Store a compact time-versioned manifest: `sbom_version`, `ingest_timestamp`, `expiry_timestamp`, `status`.

### 1.5 Vulnerability feed ingestion
- `NVD Poller`: fetch CVE JSON feeds and modified feeds; use the cached 5-minute window with delta snapshots.
- `OSV Stream`: subscribe to Google OSV feed / periodic polling for new advisory batches.
- `GitHub Advisory Bridge`: use GitHub Advisory API and Dependabot alerts if permitted by enterprise subscription.
- Normalize advisories into internal `vulnerability` records:
  - `vuln_id`, `ecosystem`, `package_name`, `affected_versions`, `cvss`, `severity`, `published_at`, `updated_at`, `references`
- Enrich advisories with exploit maturity, exploit detection signals, and patch guidance when available.
- Maintain a `last_seen` cursor for each feed to ensure incremental ingestion and support 5-minute freshness.

### 1.6 Live matching and alerting
- `Exposure Engine` computes matches by evaluating each SBOM material against current vulnerability records.
- Support matching strategies:
  - direct package/version match using semver range semantics
  - package alias normalization (e.g. `js` vs `npm`, Maven groupId/artifactId equivalence)
  - image-layer package inventory for OS packages and language dependencies
- For each match, compute an `exposure_score`:
  - `base_severity` = normalized CVSS or advisory severity
  - `deployment_criticality` = cluster/service priority, namespace sensitivity, workload owner
  - `live_state_factor` = pod restart count, age, replica count, runtime exposure
  - `compensating_controls` = presence of network policy, service mesh mTLS, runtime EDR
- Generate alerts where `exposure_score` exceeds configured thresholds.
- For new CVE hits, target 5-minute detection by pushing incremental updates from the feed processor to the `Exposure Engine` immediately.

### 1.7 Operational patterns and retention
- Use streaming storage for live state: Kafka topic `sbom-events` for ingest events, `vuln-events` for feed updates.
- Persist canonical SBOM inventory in a document store or relational DB with time-series support.
- Keep raw SBOM manifests in object storage for forensic reconstruction.
- Retain alert history and policy decisions for at least 90 days, with longer retention for compliance.

### 1.8 Example flow
1. Build pipeline emits `cyclonedx-4167.json` and pushes to `SBOM Collector`.
2. Collector stores raw file and normalizes 352 components.
3. Vulnerability processor ingests a new NVD modified feed entry for `CVE-XXXX-YYYY` affecting `openssl 1.1.1k`.
4. Exposure Engine finds `openssl@1.1.1k` in two active workloads and computes a P1 exposure score.
5. Guardrail API publishes the finding and triggers a policy action in the production guardian.

## SECTION 2 — OPA Gatekeeper Admission Policies

### 2.1 Goals
- Enforce production security policies at pod scheduling time using OPA Gatekeeper/OPA Admission Webhooks.
- Validate workload SBOM metadata, image provenance, runtime security settings, and network posture before admission.
- Reject or mutate pods based on explicit policy rules and K8s runtime risk posture.

### 2.2 Policy architecture
- `OPA Gatekeeper`: host admission control policies as `ConstraintTemplates` and `Constraints`.
- `Admission Webhook`: intercepts `CREATE` and `UPDATE` on `pods`, `deployments`, `daemonsets`, and `statefulsets`.
- `Policy Library`: rules for SBOM presence, image signing, vulnerability allowances, and runtime layout.
- `Policy Decision Point (PDP)`: Gatekeeper evaluates OPA Rego against live context and returns `allow`/`deny`.
- `Policy Enforcement Point (PEP)`: the Kubernetes API server enforces Gatekeeper decisions.

### 2.3 Core admission policies
#### 2.3.1 SBOM metadata presence
- Require the pod spec to include annotations or image labels pointing to the SBOM artifact or repository.
- Example enforced fields:
  - `security.cbad.io/sbom-url`
  - `security.cbad.io/image-digest`
  - `security.cbad.io/scan-timestamp`
- Reject pods missing SBOM metadata for workloads in protected namespaces (`prod`, `payments`, `identity`).

#### 2.3.2 Signed image provenance
- Enforce `cosign` keyless/signature verification for container images.
- Example policy checks:
  - `image.registry` is in allowed registry list
  - image digest annotation matches actual digest at admission time
  - `security.cbad.io/cosign-verified: "true"`
- Reject if image provenance cannot be validated.

#### 2.3.3 Vulnerability allowance and drift
- Deny deployment if the image has a `security.cbad.io/allowlist` annotation for a CVE older than allowed grace period.
- Allow temporary bypass only with explicit `security.cbad.io/justification` and `security.cbad.io/expiry` annotations.
- Use a separate runtime evaluation to compare admission-time SBOM digest against current CVE exposure state from the SBOM lifecycle monitor.

#### 2.3.4 Runtime layout and security posture
- Require critical pods to opt in to `securityContext` hardened settings:
  - `runAsNonRoot: true`
  - `readOnlyRootFilesystem: true`
  - `allowPrivilegeEscalation: false`
  - `capabilities.drop: ["ALL"]`
- Reject pods without required Pod Security admission profile equivalence in protected namespaces.
- Enforce network policy labels for workloads that serve public-facing APIs.

### 2.4 ConstraintTemplate examples
- `K8sRequiredAnnotations`: enforce required pod/deployment annotations.
- `K8sAllowedRepos`: ensure images are only pulled from approved registries and repos.
- `K8sPodSecurityContext`: validate `securityContext` requirements.
- `K8sSBOMCompliance`: custom template that validates SBOM annotations and external SBOM inventory status.

### 2.5 Policy runtime data and enrichment
- Use Gatekeeper `ConfigMaps` or `external data` to provide:
  - approved registries, allowed namespaces, and exempted workloads
  - vulnerability risk threshold values and policy severity
  - `sbom_watch` live status via periodic refresh from the SBOM lifecycle monitor
- For advanced enforcement, Gatekeeper can call out to `data from` configured external services, e.g. a `sbom-status` endpoint returning current CVE exposure booleans.

### 2.6 Admission-time verification of SBOM freshness
- Policy rule: reject if `security.cbad.io/scan-timestamp` is older than 24h for production workloads.
- In protected namespaces, require the SBOM manifest referenced by the pod is not stale relative to current `SBOM Collector` inventory.
- Use `annotation` or `label` mapping to store `sbom-version` and `build-id` for traceability.

### 2.7 Example Rego snippets
#### SBOM presence rule
```rego
package kubernetes.admission

violation[{
  "msg": msg,
  "details": {"missing": missing}
}] {
  input.request.kind.kind == "Pod"
  required := ["security.cbad.io/sbom-url", "security.cbad.io/image-digest", "security.cbad.io/scan-timestamp"]
  missing := [k | k := required[_]; not input.request.object.metadata.annotations[k]]
  count(missing) > 0
  msg := sprintf("missing required SBOM metadata: %v", [missing])
}
```

#### Image provenance rule
```rego
package kubernetes.admission

violation[{
  "msg": msg
}] {
  image := input.request.object.spec.containers[_].image
  not startswith(image, "ghcr.io/cbad/")
  msg := sprintf("image %v is not from approved registry", [image])
}
```

### 2.8 Enforcement model
- Use `dry-run` mode for initial rollout and tune policies with audit annotations.
- Deploy `PodStatus` and `Audit` reporting to track denied admissions and policy hits.
- Promote policies from `audit` to `enforce` for protected namespaces once stable.
- Combine Gatekeeper with `PodSecurityAdmission` for layered defense.

### 2.9 Integration with Production Guardian
- When admission denies a pod, emit an event to the `Production Guardian` service with context:
  - `cluster`, `namespace`, `resource`, `reason`, `policy_id`, `sbom_status`, `cve_exposure`
- Use denial events as prevention telemetry alongside the continuous SBOM watcher’s alert feed.
- Support a workflow where the guardrail can automatically quarantine or rollback deployments that fail SBOM/CVE admission policies.

### 2.10 Summary
Stage 9 Section 1 defines a live SBOM lifecycle monitor with 5-minute vulnerability feed processing and canonical SBOM inventory. Section 2 specifies OPA Gatekeeper admission policies for SBOM metadata, signed image provenance, vulnerability allowances, and hardened runtime pod layout.

## SECTION 3 — OPA Policy Library

### 3.1 Objectives
- Provide a production-grade OPA policy library that enforces critical runtime safety controls at admission time.
- Enforce image signature validation using Cosign verification metadata, root-less container execution, hostPath volume blocking, and mandatory network isolation labeling.
- Make policies explicit, auditable, and consistent with the Stage 7 production guardian model.

### 3.2 Policy design
- `policy.cbad.image_signature`: verify that images are signed and that the signature metadata matches the admission request.
- `policy.cbad.rootless_execution`: deny any container configured to run as root or with privilege escalation.
- `policy.cbad.hostpath_block`: block hostPath and CSI volume mounts unless explicitly whitelisted.
- `policy.cbad.network_isolation`: require network isolation policy labels and namespace segmentation for sensitive apps.

### 3.3 Production-grade Rego policy blocks
#### 3.3.1 Image signature validation
```rego
package kubernetes.admission.cbad.image_signature

# Validate container image has Cosign verification metadata annotations.
violation[{
  "msg": msg,
  "container": container_name,
  "image": image
}] {
  container := input.request.object.spec.containers[_]
  image := container.image
  not has_cosign_verified_annotation(input.request.object.metadata.annotations, image)
  msg := sprintf("container %v image %v must be Cosign verified", [container.name, image])
}

has_cosign_verified_annotation(annotations, image) {
  annotation_key := sprintf("security.cbad.io/cosign-%v-verified", [image])
  annotations[annotation_key] == "true"
}

# Fallback for image digest annotation validation.
violation[{
  "msg": msg,
  "container": container_name,
  "image": image
}] {
  container := input.request.object.spec.containers[_]
  container_name := container.name
  image := container.image
  digest_annotation := input.request.object.metadata.annotations["security.cbad.io/image-digest"]
  not valid_image_digest(image, digest_annotation)
  msg := sprintf("container %v image digest mismatch or missing for %v", [container_name, image])
}

valid_image_digest(image, digest) {
  digest != ""
  # In production, this function delegates to an external OCI digest resolver or registry metadata cache.
  endswith(digest, ":sha256")
}
```

#### 3.3.2 Root container execution prevention
```rego
package kubernetes.admission.cbad.rootless_execution

violation[{
  "msg": msg,
  "container": container.name
}] {
  container := input.request.object.spec.containers[_]
  not is_rootless(container)
  msg := sprintf("container %v must not run as root", [container.name])
}

is_rootless(container) {
  sc := container.securityContext
  sc.runAsNonRoot == true
  sc.allowPrivilegeEscalation == false
  sc.readOnlyRootFilesystem == true
  sc.capabilities.drop[_] == "ALL"
}

violation[{
  "msg": msg,
  "container": container.name
}] {
  container := input.request.object.spec.initContainers[_]
  not is_rootless(container)
  msg := sprintf("init container %v must not run as root", [container.name])
}
```

#### 3.3.3 hostPath volume blocking
```rego
package kubernetes.admission.cbad.hostpath_block

violation[{
  "msg": msg,
  "volume": vol.name
}] {
  vol := input.request.object.spec.volumes[_]
  vol.hostPath
  not is_whitelisted_hostpath(vol.hostPath.path)
  msg := sprintf("hostPath %v is forbidden unless explicitly whitelisted", [vol.hostPath.path])
}

is_whitelisted_hostpath(path) {
  whitelist := {"/var/log/allowed", "/mnt/readonly"}
  path == whitelist[_]
}
```

#### 3.3.4 Mandatory network isolation policy matching
```rego
package kubernetes.admission.cbad.network_isolation

violation[{
  "msg": msg
}] {
  ns := input.request.object.metadata.namespace
  required := get_network_isolation_requirements(ns)
  not has_network_policy_label(input.request.object.metadata.labels)
  msg := sprintf("namespace %v requires network isolation labels: %v", [ns, required])
}

get_network_isolation_requirements(ns) = required {
  required := {
    "prod": ["network.cbad.io/isolation", "network.cbad.io/mesh"],
    "payments": ["network.cbad.io/isolation"],
    "identity": ["network.cbad.io/isolation", "network.cbad.io/encrypted-svc"],
  }[ns]
}

has_network_policy_label(labels) {
  labels["network.cbad.io/isolation"] == "strict"
}
```

### 3.4 Production hardening notes
- Use `external data` for dynamic whitelists and image provenance caches.
- Keep policy evaluation low-latency; offload heavyweight signature verification to a sidecar or admission cache.
- Audit policy hits with `constrainttemplate` annotations and align with the guardrail event stream.

## SECTION 4 — ML Production Traffic Anomaly Profiler

### 4.1 Objectives
- Track a rolling 7-day baseline of production metrics and detect deviation patterns consistent with zero-day exploitation.
- Focus on request frequencies, error distribution, response sizes, and latency across service/service endpoint dimensions.
- Feed anomalies into the Production Guardian for automated playbook escalation and incident response.

### 4.2 Architecture
- `Metric Ingestor`: collects production telemetry from service mesh (Istio/Linkerd), Kubernetes metrics server, and API gateway logs.
- `Feature Store`: stores time-series aggregates on a rolling 7-day window per service/endpoint.
- `Baseline Profiler`: computes statistical models for each metric dimension and updates them continuously.
- `Anomaly Detector`: compares live metric slices against baseline expectations and emits alerts when divergence exceeds dynamic thresholds.
- `Alert Correlator`: combines anomaly signals with SBOM/CVE exposure and admission denial events to identify probable exploitation.
- `Investigation API`: surfaces anomaly context, root cause candidates, and relevant production telemetry.

### 4.3 Metric model
- Metrics to profile:
  - request frequency by endpoint, method, and client identity
  - error distribution by status code class and endpoint
  - response size percentiles (P50, P95, P99)
  - latency percentiles and service-level latency trends
- Normalize metrics into feature vectors and compute rolling statistics:
  - moving average, standard deviation, median, and interquartile range (IQR)
  - anomaly score = weighted combination of normalized deviation across features
- Use a 7-day sliding window with hourly buckets and decaying weights to preserve recent behavior.

### 4.4 Detection patterns
- Zero-day exploit patterns:
  - sudden spike in 5xx rate for a previously stable endpoint
  - unusual burst of POST/PUT traffic to admin APIs after hours
  - large response size changes for authenticated endpoints
  - low-latency high-volume traffic from a new client or region
- Alert generation rules:
  - score > 3 sigma for critical endpoints
  - abrupt shift in traffic source distribution combined with error spike
  - increase in high-severity anomalies correlated to SBOM/CVE alerts

### 4.5 Implementation blueprint
- Use a time-series database like Prometheus/Thanos plus a feature extraction layer in Kafka Streams or Flink.
- Maintain baseline state in a vector store or specialized anomaly database.
- Add a model training loop to compute thresholds per endpoint and service.
- Provide `baseline drift` metrics so operators can tune sensitivity and reduce false positives.

### 4.6 Guardrail integration
- When the anomaly profiler detects a high-confidence event, forward to `Production Guardian` with:
  - service, namespace, endpoint, client fingerprints, anomaly score, baseline delta, related CVE exposure
- Support automated workflows such as circuit-breaker scaling, WAF rule injection, or emergency Pod rollout.

### 4.7 Reporting and observability
- Dashboards should show:
  - rolling 7-day baseline for each key metric
  - anomaly score heatmaps by service and namespace
  - top anomalous endpoints and correlated security signals
- Retain anomaly context and measurement windows for forensic reconstruction.

### 4.8 Summary
Section 3 defines a production-grade OPA policy library including Cosign image signature enforcement, rootless container prevention, hostPath blocking, and mandatory network isolation. Section 4 defines an ML-driven traffic anomaly profiler that uses a 7-day production baseline to surface zero-day exploit events and integrate with the Production Guardian.

## SECTION 5 — Automated Incident Mitigation Loop

### 5.1 Objectives
- Build an automated event router that receives critical OPA denials and runtime anomaly signals.
- Trigger Canary rollback actions, capture kernel telemetry, and preserve a complete evidence chain in WORM-locked storage.
- Deliver deployment manifests and architecture for production-graded Kubernetes deployment.

### 5.2 Architecture
- `Event Router`: central event processor listening for OPA Gatekeeper block events, anomaly profiler alerts, and runtime security events.
- `Mitigation Orchestrator`: applies immediate actions such as Canary rollback, Pod evacuation, and traffic redirection.
- `Telemetry Collector`: captures kernel-level telemetry, container logs, network flow data, and process snapshots.
- `Evidence Archive`: writes immutable evidence bundles to WORM storage with append-only retention policies.
- `Audit Bridge`: forwards incident summaries to alerting/IR systems and maintains the incident lifecycle state.

### 5.3 Event router flow
1. OPA Gatekeeper denial or anomaly profiler alert is emitted to the `Production Guardian` event bus.
2. `Event Router` evaluates event priority and whether automated mitigation is authorized.
3. If critical, it triggers the `Mitigation Orchestrator` and simultaneously instructs `Telemetry Collector` to snapshot the affected workload.
4. Evidence bundles are sealed and written to the `Evidence Archive` before the rollback completes.
5. A notification is published to on-call channels and ticketing systems.

### 5.4 Canary rollback strategy
- Use Kubernetes `Deployment` canary strategies with progressive rollout and fast rollback via `kubectl rollout undo` or `Argo Rollouts`.
- For a critical policy block, mark the affected deployment as `suspend` or `pause` and create a remediation rollout plan.
- For a runtime anomaly, automatically cut traffic to the canary subset and restore the prior stable revision.
- Keep a rollback guard that only applies to releases older than the last known good revision recorded in the `Production Guardian`.

### 5.5 Kernel telemetry capture
- Use a `telemetry-agent` DaemonSet with privileged access to collect:
  - `eBPF` traces for syscalls and process behavior
  - `ktrace` or `bcc` snapshots of suspicious containers
  - `packet capture` metadata for affected Pod network flows
  - container logs and process file descriptors
- Trigger live capture through an `EventTrigger` CRD that instructs the agent to snapshot the Pod and store results in a local cache.

### 5.6 Evidence preservation
- Evidence bundle contents:
  - event metadata, OPA constraint violation or anomaly score details
  - deployment and Pod spec snapshot
  - kernel telemetry trace
  - container stdout/stderr logs
  - network flow summary and process snapshots
- Persist evidence to a WORM backend such as object storage with object lock (`MinIO/OSS`), or a managed WORM bucket.
- Ensure the archive writes data as immutable objects and logs the retention policy in the bundle manifest.

### 5.7 Deployment architecture
- Namespace: `production-guardian`
- Deployments:
  - `event-router` (webhook consumer + rules engine)
  - `mitigation-orchestrator` (K8s client automation)
  - `telemetry-collector` DaemonSet
  - `evidence-archiver` (WORM storage writer)
- Supporting resources:
  - `ConfigMap` for policy thresholds and action maps
  - `Secret` for WORM storage credentials and alert webhook tokens
  - `ServiceAccount` with RBAC for deploy/rollback and pod log access
  - `EventTrigger` CustomResourceDefinition for incident snapshot requests

### 5.8 Kubernetes manifests
- `event-router-deployment.yaml`
- `mitigation-orchestrator-deployment.yaml`
- `telemetry-collector-daemonset.yaml`
- `evidence-archiver-deployment.yaml`
- `rbac.yaml`
- `event-trigger-crd.yaml`

### 5.9 Example Kubernetes manifest: RBAC
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: production-guardian-sa
  namespace: production-guardian
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: production-guardian-role
rules:
  - apiGroups: [""]
    resources: ["pods", "pods/log", "namespaces", "events"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "rollouts"]
    verbs: ["get", "list", "watch", "patch", "update"]
  - apiGroups: ["guardian.cbad.io"]
    resources: ["eventtriggers"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: production-guardian-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: production-guardian-role
subjects:
  - kind: ServiceAccount
    name: production-guardian-sa
    namespace: production-guardian
```

### 5.10 Example Kubernetes manifest: event-router deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: event-router
  namespace: production-guardian
spec:
  replicas: 2
  selector:
    matchLabels:
      app: event-router
  template:
    metadata:
      labels:
        app: event-router
    spec:
      serviceAccountName: production-guardian-sa
      containers:
        - name: event-router
          image: ghcr.io/cbad/prod-guardian-event-router:latest
          env:
            - name: EVENT_BUS_URL
              value: "https://event-bus.production.svc.cluster.local"
            - name: WORM_ARCHIVE_ENDPOINT
              value: "https://worm-storage.production.svc.cluster.local"
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
```
```

### 5.11 Example Kubernetes manifest: telemetry collector DaemonSet
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: telemetry-collector
  namespace: production-guardian
spec:
  selector:
    matchLabels:
      app: telemetry-collector
  template:
    metadata:
      labels:
        app: telemetry-collector
    spec:
      serviceAccountName: production-guardian-sa
      hostNetwork: true
      hostPID: true
      containers:
        - name: telemetry-agent
          image: ghcr.io/cbad/prod-guardian-telemetry-agent:latest
          securityContext:
            privileged: true
          volumeMounts:
            - name: bpf
              mountPath: /sys/fs/bpf
            - name: var-log
              mountPath: /var/log
      volumes:
        - name: bpf
          hostPath:
            path: /sys/fs/bpf
        - name: var-log
          hostPath:
            path: /var/log
```
```

### 5.12 Example Kubernetes manifest: evidence archiver deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: evidence-archiver
  namespace: production-guardian
spec:
  replicas: 1
  selector:
    matchLabels:
      app: evidence-archiver
  template:
    metadata:
      labels:
        app: evidence-archiver
    spec:
      serviceAccountName: production-guardian-sa
      containers:
        - name: archiver
          image: ghcr.io/cbad/prod-guardian-evidence-archiver:latest
          env:
            - name: WORM_BUCKET
              value: "prod-guardian-evidence"
            - name: WORM_REGION
              value: "us-east-1"
            - name: WORM_MODE
              value: "immutable"
          volumeMounts:
            - name: archive-config
              mountPath: /etc/archiver
      volumes:
        - name: archive-config
          configMap:
            name: evidence-archiver-config
```
```

### 5.13 Example Kubernetes manifest: EventTrigger CRD
```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: eventtriggers.guardian.cbad.io
spec:
  group: guardian.cbad.io
  scope: Namespaced
  names:
    kind: EventTrigger
    plural: eventtriggers
    singular: eventtrigger
  versions:
    - name: v1alpha1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
              properties:
                targetPod:
                  type: string
                targetNamespace:
                  type: string
                eventType:
                  type: string
                priority:
                  type: string
                captureKernelTelemetry:
                  type: boolean
      subresources:
        status: {}
```

### 5.14 Evidence chain and governance
- Evidence bundles are annotated with `incident_id`, `event_type`, and `timestamp`.
- WORM storage uses immutable object upload and retention metadata to prevent tampering.
- Every mitigation action is recorded as an auditable event with action, actor, and result.

### 5.15 Summary
Section 5 defines the automated incident mitigation loop, including a Kubernetes event router, canary rollback orchestration, kernel-level telemetry capture, and WORM evidence preservation. The design includes production-ready manifests for RBAC, event routing, telemetry collection, evidence archiving, and the event trigger CRD.
