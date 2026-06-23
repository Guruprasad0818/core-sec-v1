# CBAD Stage 6 — Sandboxed Runtime Behaviour Whitelisting

## SECTION 1 — gVisor Sandboxing & Kernel Isolation

### 1.1 Overview
Design a hardened runtime layer using Google gVisor to enforce syscall surface minimization, namespace isolation, and deterministic guest process behavior for CI/runner workloads. The architecture uses gVisor Sentry as the in-kernel userspace kernel (in user-space) and Gofer as the userspace proxy that performs controlled access to host resources.

### 1.2 gVisor components and roles
- Sentry: user-space kernel that implements syscall handlers and enforces the sandbox ABI. Runs in the build container's user namespace and mediates all syscalls.
- Gofer: resource proxy running outside the Sentry (but typically in the same container/process namespace) that performs file/metadata/network operations on behalf of the Sentry using a strictly limited protocol over a Unix domain socket.
- Runsc: OCI runtime shim that initializes the Sentry & Gofer for a container and wires up the UDS control plane.

### 1.3 Isolation profile model
Define a JSON/YAML profile describing allowed capabilities and resource operations for each workload class. Profiles are applied at container creation time by the runtime shim.

Profile fields (example):
- `allowed_syscalls`: explicit whitelist (e.g., read, write, openat for /workspace only, execve allowed only from /workspace/bin)
- `capabilities`: minimal POSIX capabilities (drop all except CAP_CHOWN/CAP_DAC_OVERRIDE when necessary)
- `allowed_paths`: list of mounted paths with access modes and file-type filters
- `network_policy`: `none|egress-only|restricted` with explicit DNS allowlist
- `allowed_fds`: maximum allowed open file descriptors and an allowlist of fd numbers for shared sockets
- `resource_limits`: CPU/memory/pid limits enforced via cgroups v2
- `env_whitelist`: allowed environment variables and fixed values
- `runtime_hooks`: permitted helper operations via Gofer protocol (e.g., stat, read, write to /output)

### 1.4 Sentry/Gofer hardened configuration
- Disable direct host namespace operations: Sentry must reject `setns`/`unshare`/`mount` syscalls
- Intercept `execve`: enforce binary provenance check by verifying the executing file's digest against declared manifest before allowing execution
- Openat gating: allow `openat` only when path is within `/workspace` or `/output` and the file checksum matches manifest or is on a per-build allowlist
- Deny `ptrace` and other introspective syscalls unless explicitly allowed for debugging with strong auth
- Time/source determinism: Sentry returns controlled time via `clock_gettime` mapped to `SOURCE_DATE_EPOCH` per build manifest

### 1.5 Gofer protocol hardening
- Use UDS with peer credentials validation to ensure only the authorized Sentry instance may request operations
- Limit Gofer operations to a minimal RPC surface: `stat`, `open_read`, `open_write`, `read_chunk`, `write_chunk`, `list_dir`
- Enforce per-request authorization based on Sentry identity and the build manifest
- Rate-limit and audit every Gofer operation with request IDs and HMAC-signed parameters for non-repudiation

### 1.6 Kernel and cgroups policy
- Use cgroups v2 with explicit delegation for each container to set `memory.max`, `cpu.max`, `pids.max`
- Mount proc/sys as read-only inside Sentry, and present a sanitized `/proc` view via Sentry emulation
- Block loading of kernel modules inside the sandbox and restrict access to `/dev` to only declared devices

### 1.7 Custom container isolation profiles (examples)
- `build-hermetic`: network=none, allowed_syscalls=[read,write,openat,stat,close,lseek,execve], allowed_paths=[/workspace (r), /output (w)], env_whitelist=[SOURCE_DATE_EPOCH]
- `analysis-lite`: network=restricted (https://artifactory.company.com), allowed_syscalls adds `connect` for proxy IPs only
- `debug-ephemeral`: similar to build-hermetic but with `ptrace` allowed and timeboxed, requires elevated RBAC

### 1.8 Attestation and runtime verification
- On container start, `runsc` signs a runtime attestation containing profile ID, image digest, Sentry digest, and start-time; this is stored in the build artifact database
- Continuous runtime attestations: periodical Sentry heartbeats with HMAC proving profile compliance
- Any deviation (syscall outside whitelist, excessive Gofer ops) triggers an incident to the Stage 5/Forensics system

### 1.9 Operational notes
- Maintain a central profile repository and versioned profiles; use admission webhook to reject pods with unapproved profiles
- Test profiles with fuzzing and syscall fuzzers to ensure correct allowance and blocking semantics
- Monitor Sentry/Gofer logs via structured JSON to feed the eBPF/Falco detection matrix

## SECTION 2 — eBPF & Falco Syscall Telemetry Matrix

### 2.1 Goals
- Capture syscall-level telemetry to detect deviations from the allowed behavior enforced by gVisor profiles
- Provide low-latency alerts for suspicious syscalls (`execve`, `socket`, `connect`, `openat`, `ptrace`) and correlate with container identity
- Feed aggregated metrics and raw events to the AI verifier and forensics pipeline

### 2.2 eBPF architecture
- Use a userspace agent (written in Go) that loads eBPF programs via libbpf/CO-RE (or gobpf for rapid prototyping)
- Attach kprobes/tracepoints/uretprobes to syscall entry/exit points for targets: `execve`, `execveat`, `openat`, `open`, `socket`, `connect`, `accept`, `sendto`, `recvfrom`, `ptrace`
- Use cgroup v2 BPF attachment where supported to limit tracing to build runner cgroups to reduce noise
- Emit event records with the following fields:
  - `timestamp`
  - `container_id` (CRI container ID)
  - `pid`, `tid`
  - `comm` (process name)
  - `syscall` name
  - `args`: normalized syscall args (path truncated, IP:port for socket/connect)
  - `return_code`
  - `uid/gid` and namespaces (mnt, pid, net)
  - `stack_trace` (user + kernel stack hashes) when available
  - `event_id` unique

### 2.3 Falco rules schema and examples
- Falco rules ingest k8s metadata via the Falco Kubernetes metadata enrichers and map events to pods and namespaces
- Rules produce alerts with severity and a rule ID that maps to corresponding profile violations

Example Falco rule (openat to outside workspace):

```
- rule: Openat Outside Workspace
  desc: Detect openat syscalls opening files outside /workspace or /output
  condition: evt.type = openat and not fd.name startswith /workspace and not fd.name startswith /output
  output: "Open outside workspace (user=%user.name command=%proc.cmdline file=%fd.name)"
  priority: WARNING
  tags: [container, file-access, policy]
```

Example Falco rule (execve unexpected):

```
- rule: Execve Not Whitelisted
  desc: Detect execve where binary digest not present in build manifest
  condition: evt.type = execve and not proc.name in (whitelist) and container_image.repo = "<build-runner-image>"
  output: "Execve of unapproved binary (container=%container.id image=%container.image)"
  priority: CRITICAL
  tags: [exec, container, policy]
```

Example Falco rule (network connect):

```
- rule: Connect To External IP
  desc: Detect connect to external IPs not in allowlist
  condition: evt.type = connect and not fd.sip in (allowed_ips) and container.name contains "runner"
  output: "Outgoing connect to unexpected IP (pod=%k8s.pod.name ns=%k8s.ns.name ip=%fd.sip port=%fd.sport)"
  priority: CRITICAL
  tags: [network, ssrf, egress]
```

### 2.4 Aggregation and enrichment
- eBPF events stream to a local ring buffer and then to a collector (Fluent Bit/Vector) which enriches events with k8s metadata and container attestations
- Collector writes to:
  - short-term alerting bus (Kafka/NSQ) for real-time SIEM/Falco action
  - long-term event store (ClickHouse/Elasticsearch) for forensics and ML training
- Correlate events with `profile_id` and `sentry` attestation to compute `policy_violation_score`

### 2.5 Event threat scoring matrix
Compute a composite score per event E:

score(E) = w1 * syscall_criticality + w2 * provenance_mismatch + w3 * frequency_factor + w4 * entropy_signal

- `syscall_criticality`: execve/connect/ptrace -> high; openat -> medium
- `provenance_mismatch`: binary digest not in manifest or Gofer denied operation -> high
- `frequency_factor`: rapid repeated syscalls increase score
- `entropy_signal`: integrate entropy engine result if event touches class files or JARs

Thresholds:
- `score >= 0.8` => immediate lockdown/forensic capture
- `0.5 <= score < 0.8` => elevated alert and AI verification
- `< 0.5` => log and continue monitoring

### 2.6 Performance and deployment
- Compile eBPF programs with CO-RE to support multiple kernel versions without recompilation
- Use tail call dispatchers to minimize per-event BPF complexity and keep maps small
- Limit stack captures to high-score events to reduce overhead
- Attach BPF to cgroup v2 to scope tracing to runner workloads and reduce kernel overhead

### 2.7 False positive reduction
- Use allowlists derived from the gVisor profiles to suppress expected syscalls
- Implement per-pod learning windows during which low-severity events are recorded to establish baseline
- Feed aggregated syscall histograms to the AI verifier for triage (Claude wrapper) to reduce noise

### 2.8 Audit and compliance
- Persist signed event batches to immutable storage and reference them in the Incident CRs
- Ensure eBPF collectors sign events with node-local keys and that forwarding to central stores uses mTLS
- Regularly rotate keys and audit collector binaries and eBPF bytecode signatures

### 2.9 Summary
This design leverages gVisor sandboxing to minimize attack surface and couples low-level syscall telemetry via eBPF and Falco rules to detect policy violations early. Together they provide a high-fidelity, low-latency enforcement and observability plane for Stage 6 sandboxes.

## SECTION 3 — Runtime Baseline & Whitelisting Logic

### 3.1 Goals
- Build a stateful evaluation engine that learns normal syscall profiles over a rolling window of 50 clean builds per project/runner profile.
- Provide deterministic baseline comparisons, anomaly scoring, and automatic whitelist updates when variance is benign.

### 3.2 Data model and storage
- Event stream: normalized syscall events (see Section 2 fields) are ingested into a short-term event buffer (Kafka) and persisted to a feature store (ClickHouse/TimescaleDB) for rolling-window analysis.
- Baseline record per `(project_id, profile_id)` contains:
  - `window_size` (default 50 builds)
  - aggregated syscall histogram vectors (per-syscall counts normalized by process lifetime)
  - per-path/file access frequency tables
  - per-binary digest invocation counts
  - timestamped snapshots for drift analysis

### 3.3 Rolling-window baseline algorithm
1. Maintain an ordered list of the last N=50 clean builds validated by dual-build verification and AI verifier.
2. For each build i in the window compute per-build feature vector F_i (syscall frequency vector, open path set, network endpoints touched, entropy touches).
3. Compute baseline B as the element-wise trimmed mean of {F_i} with outlier rejection (drop top/bottom 5% per-feature) and compute baseline covariance matrix Σ for Mahalanobis distance calculations.
4. Store B and Σ as the canonical baseline for the project/profile.

### 3.4 Anomaly scoring and thresholds
- On a new build, compute observation vector O and distance D = sqrt((O - B)^T Σ^{-1} (O - B)) (Mahalanobis distance) and per-feature z-scores.
- Composite anomaly score S = α * normalize(D) + β * provenance_mismatch + γ * entropy_signal + δ * frequency_spike_score.
- Suggested operating thresholds (tunable):
  - `S < 0.4`: normal
  - `0.4 <= S < 0.7`: suspicious — queue for AI verification and extended monitoring
  - `S >= 0.7`: anomalous — trigger containment and forensic capture

### 3.5 Noise filtering and adaptive whitelist logic
- Noise filter components:
  - low-frequency suppression: ignore one-off syscalls below an absolute count threshold unless they touch critical syscalls (execve/connect/ptrace)
  - temporal smoothing: apply exponential moving average on per-syscall counts
  - per-project acceptance window: candidate new behavior must appear in M consecutive builds (M default 3) before being considered for whitelist
- Whitelist update protocol (safe-by-design):
  1. Candidate behavior observed in >= M consecutive clean builds with S < 0.4 for each build
  2. AI verifier verifies that behavior is non-malicious and provenance matches known inputs
  3. Operator approval (optional auto-approve for low-risk changes) updates profile allowlist and annotates profile history

### 3.6 Stateful evaluation engine architecture
- Components:
  - `collector`: receives eBPF/Falco events, normalizes, enriches with k8s metadata
  - `feature-store`: persistent DB holding per-build aggregated vectors and baseline snapshots
  - `baseline-service`: API to compute and expose baselines, covariances, and anomaly scoring
  - `ai-verifier`: Claude wrapper used for human-like triage of borderline cases
  - `policy-engine`: decides actions (monitor, verify, quarantine) based on scores and provenance signals

### 3.7 Explainability & feedback loop
- For each anomaly produce a concise explanation: top contributing syscall features, changed file paths, and entropy signals (SHAP-style feature contributions).
- Feedback loop: human-reviewed incidents mark builds as `clean` or `malicious`; `clean` builds feed back into the rolling window, `malicious` builds are excluded and trigger investigation retention policies.

### 3.8 Operational considerations
- Cold-start: initialize baseline using a bootstrap set of known-clean historical builds (if available) or relax thresholds temporarily while accumulating N builds.
- Multi-tenancy: maintain isolated baselines per project, repo, or team to avoid cross-project noise.

## SECTION 4 — Automated Mitigation & Kill Logic

### 4.1 Goals
- Consume the low-latency anomaly stream and execute real-time mitigations: isolate, pause, or terminate compromised containers; ensure forensic capture precedes or accompanies termination when required.

### 4.2 Mitigation decision flow
1. Receive event E with `score >= critical_threshold` or Falco critical rule match.
2. Policy-engine checks `preserve_forensics` flag: if true, attempt graceful pause + capture; else proceed to hard termination.
3. Execute mitigation playbook: (pause -> capture -> isolate -> terminate -> upload bundle) or (isolate -> terminate -> upload bundle) depending on time sensitivity.

### 4.3 Kubernetes operator kill patterns
- Use the `cbad-controller` (operator) to perform action via CRs. Example `Incident` CR update triggers a `mitigation` subresource reconciliation.

Example operator actions (pseudo-commands):

```bash
# annotate pod for immediate quarantine
kubectl annotate pod -n buildns <pod> cbad/quarantine=true

# apply network deny policy for pod
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-egress-<pod>
  namespace: buildns
spec:
  podSelector:
    matchLabels:
      run: <pod-label>
  policyTypes:
    - Egress
  egress: []
EOF

# pause process
kubectl exec -n buildns <pod> -- kill -STOP <pid>

# fetch forensic bundle via controller job
kubectl create job --from=cronjob/forensic-capture forensic-<incident>
```

### 4.4 eBPF consumer & automatic kill Go snippet
Below is a concise Go consumer skeleton that subscribes to an alert topic and issues Kubernetes API calls to kill pods when a critical policy is matched.

```go
package main

import (
    "context"
    "log"
    "os/exec"
)

func killPod(podNS, podName string) error {
    // attempt graceful SIGTERM first, then SIGKILL after timeout
    exec.Command("kubectl","exec","-n",podNS,podName,"--","kill","-TERM","1").Run()
    // sleep or wait; in production use client-go with context and timeout
    exec.Command("sleep","5").Run()
    return exec.Command("kubectl","exec","-n",podNS,podName,"--","kill","-KILL","1").Run()
}

func main(){
    // subscribe to Kafka/alert bus and process messages
    for msg := range alertChan() {
        if msg.Score >= 0.9 {
            // preserve forensics if requested
            if msg.PreserveForensics {
                // instruct controller to snapshot then kill
                triggerForensicCapture(msg.PodNS, msg.PodName)
            }
            if err := killPod(msg.PodNS, msg.PodName); err != nil {
                log.Printf("kill failed: %v", err)
            }
        }
    }
}
```

### 4.5 Safe kill vs hard kill considerations
- Prefer: `SIGSTOP` -> CRIU checkpoint -> forensic bundle -> `SIGKILL` to prevent process cleanup that may remove evidence.
- If immediate public-safety risk exists (exfiltration in progress), issue immediate hard termination and collect post-mortem artifacts from node-level snapshots.

### 4.6 Audit and non-repudiation
- All mitigation actions produce signed audit events stored in the artifact-store and referenced in the `Incident` CR: who triggered, why, which operator executed, timestamps, and checksums.

### 4.7 Testing and safe deployment
- Blue/green rollout of mitigation logic: start by automating only low-risk quarantines, produce alerts for manual confirmation, then progressively enable auto-kill for Critical policies.
- Simulate attacks during chaos tests to validate forensic capture and ensure minimal false-positive impact.

### 4.8 Summary
Sections 3–4 define a stateful, explainable runtime baseline engine with conservative whitelist evolution and a tightly integrated mitigation layer that consumes eBPF/Falco alerts to quarantine and terminate compromised containers while preserving forensic evidence.

## SECTION 5 — SIEM Data Pipelines & Production Scaling

### 5.1 Goals
- Stream high-throughput, low-latency syscall audit events from node collectors into a multi-tenant Kafka backbone and forward enriched events to a SIEM for detection, hunting, and long-term storage.
- Guarantee durability, ordered delivery per-container, and horizontal scalability to support 10,000+ active containers simultaneously emitting telemetry.

### 5.2 Event schema and serialization
- Use a compact binary schema (Avro or Protobuf) for event payloads to minimize size and allow schema evolution. Key fields:
  - `tenant_id`, `cluster_id`, `node_id`, `pod_ns`, `pod_name`, `container_id`
  - `timestamp`, `event_id`, `seq_no`
  - `syscall`, `args` (normalized and truncated), `return_code`
  - `process`: `{pid, ppid, comm, uid, gid, exec_digest}`
  - `k8s`: labels/annotations, profile_id
  - `attestation`: sentry_heartbeat_id or runtime_attestation_ref
  - `entropy_signals`: optional pointer or small vector

### 5.3 Topic design and multi-tenancy
- Two-layer topic model:
  - `ingest.<region>` (high-throughput partitioned topic for raw events)
  - `tenant.<tenant_id>.alerts` (lower-throughput topic for correlated alerts/notifications)
- Partitioning strategy:
  - Partition `ingest` topics by hash(tenant_id, container_id) to keep ordering per-container
  - Compute number of partitions P = ceil(expected_peak_events_per_sec * safety_margin / per_partition_throughput)
  - Example sizing: assume 10k containers, avg 2 events/sec => 20k eps; with compression and brokers handling 2000 eps/partition, P≈10 partitions per region, add redundancy and headroom => 20–50 partitions

### 5.4 Kafka cluster architecture
- Use a dedicated Kafka cluster per security region (or multi-tenant with strict quotas). Key configurations:
  - Broker count: 9–15 for HA; use replication factor RF=3 for durability
  - KRaft mode preferred (no Zookeeper) for modern deployments
  - Use SSD-backed storage, enable tiered storage if available for retention offload
  - Enable TLS, SASL/OAuth2 with mTLS for broker-to-broker and client auth
  - Configure quotas per tenant (produce/consume) to prevent noisy neighbor issues

### 5.5 Ingestion and backpressure handling
- Node collectors (eBPF agents) batch and compress events, push to local Kafka ingress proxies (or use Kafka REST/HTTP proxy) with client-side buffering and retry.
- Ingress tier enforces rate-limits and drops non-critical fields under overload; critical alert paths (Falco rule hits) must bypass lossy compression and go to a prioritized topic.
- Use Kafka producer acks=all and idempotent producers to ensure at-least-once delivery and avoid duplication.

### 5.6 Stream processing & enrichment
- Use Kafka Streams/Flink for real-time enrichment:
  - join events with lookup stores (SBOM/provenance registry, profile allowlists)
  - compute per-container sliding-window aggregates and anomaly scores
  - emit alerts to `tenant.<id>.alerts` and to SIEM ingestion topics
- Enrichment tasks should be partition-local (keyed by container_id) to preserve ordering and reduce cross-shard joins.

### 5.7 Forwarding to SIEM and long-term storage
- SIEM ingestors subscribe to alert topics and ingest enriched JSON events. Use Avro-to-JSON conversion with schema registry to ensure consistent fields.
- Long-term storage options:
  - Hot index: Elasticsearch/Opensearch for recent N days (e.g., 30d) with fast query
  - Cold store: ClickHouse or Parquet files on S3 for long-term retention and ML training
- Implement nearline indexing: events flow from Kafka -> stream processor -> SIEM indexer and S3 archiver in parallel.

### 5.8 Horizontal scaling metrics & capacity planning
- Expected scale target: 10k active containers sending syscall telemetry.
- Assumptions (example):
  - Avg events per container: 2 events/sec => 20k eps
  - Avg event size (Avro compressed): 400 bytes => ~8 MB/s ingest
  - Peak factor: 5x => 40 MB/s sustained

Broker sizing guidance:
  - With RF=3 and 1MB/s sustained per broker capacity, plan for 6–12 brokers; use 9 as a pragmatic starting point
  - Partition count: scale partitions to provide parallelism for consumers; aim for 50–200 partitions per topic depending on consumer parallelism

Consumer/processing scaling:
  - Deploy multiple consumer groups (stream processors) with autoscaling based on consumer lag and CPU
  - Monitor `BytesInPerSec`, `BytesOutPerSec`, `UnderReplicatedPartitions`, and consumer `lag` metrics

### 5.9 Observability and SLA
- Track these critical metrics:
  - end-to-end latency (agent -> SIEM indexing), target < 5s for alerting
  - event loss rate (producer/consumer errors), target < 0.01%
  - consumer lag percentiles
  - per-tenant throughput and quota adherence
- Implement alerting: broker disk usage > 70%, under-replicated partitions > 0, consumer lag > threshold

### 5.10 Security and compliance
- Encrypt in transit (TLS) and at rest (broker and S3 encryption)
- Implement RBAC and IAM to restrict which services can produce/consume per-topic
- Use Schema Registry with subject-level ACLs to enforce schema evolution and prevent malformed events

### 5.11 High-availability and disaster recovery
- Cross-region replication using MirrorMaker 2 or Tiered Storage replication for critical topics
- Backup critical Kafka topics by archiving to S3 via Kafka Connect sinks
- Plan for broker failover and rolling upgrades with minimal downtime; automate partition reassignment during maintenance

### 5.12 Tenant isolation and noisy-neighbor mitigation
- Per-tenant quotas enforced at the ingress proxy/broker: max produce rate, max partition usage
- Use logical topics per-tenant for alerts and maintain a shared ingest topic with strict quotas
- Implement throttling and circuit-breakers in the collector agent to shed load gracefully

### 5.13 Cost & operational considerations
- Storage sizing: estimate retention days * avg daily ingest * replication factor to compute broker disk needs
- Use compression (snappy/lz4) to reduce network and disk overhead
- Automate scaling policies and add capacity before load spikes (CI night runs)

### 5.14 Example deployment pattern (K8s)
- Deploy Kafka via Strimzi/Confluent operator with:
  - Broker StatefulSet (9 nodes), persistent volumes on SSD
  - Schema Registry and Kafka Connect for SIEM sinks
  - Ingress proxies as DaemonSet or regional ingress services

### 5.15 Summary
This section prescribes a production-grade, Kafka-centric telemetry pipeline designed for multi-tenant, high-throughput syscall audit streaming. Proper partitioning, quotas, encryption, schema management, and stream processing ensure the system scales to 10k+ active containers while preserving order, durability, and real-time alerting to the SIEM.
