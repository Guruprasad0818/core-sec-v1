# CBAD Stage 5 — Build Forensics & Automated Isolation

## SECTION 5 — Build Forensics & Automated Isolation

### 5.1 Objective
Design an immediate forensic lockdown and automated capture pipeline that triggers when the Dual-Build Verification Engine detects non-deterministic or suspicious artifacts. The system must contain the potential compromise, capture forensic evidence (memory, process state, disk snapshots, network state), and preserve immutable audit records for triage and legal forensics.

### 5.2 Triggering events
Lockdown triggers include:
- byte-level divergence beyond calibrated normalization thresholds (dual-build failing equality)
- high entropy classification flagged as `malicious` by entropy ML classifier
- diffoscope report indicating code/section divergence in executable/data payloads
- suspicious runtime behavior observed in CI (outbound network attempt, unexpected child processes, access to host paths)

### 5.3 Immediate containment actions (atomic steps)
When a trigger fires, orchestrate the following automated sequence (aim for sub-60 second response):
1. Mark finding as `incident` and generate a unique incident ID
2. Quarantine artifacts: move output artifacts to an immutable storage area (object store with WORM or object-lock)
3. Pause the build job: send SIGSTOP to build PID(s) inside container namespace
4. Isolate network: apply egress/ingress deny using container network policy (CNI) and disable container network interface
5. Snapshot process list and namespaces: capture `/proc` tree for the build PID and child processes
6. Acquire memory dumps:
   - prefer `CRIU` or container-aware checkpoint to capture process memory and namespaces
   - fallback to `gcore` for single process memory dump
   - for Java processes capture `jmap -dump:format=b,file=heap.bin` and `jstack` for threads
7. Capture file descriptors and open files: `ls -l /proc/<pid>/fd`, copy referenced files
8. Capture filesystem state:
   - compute and store checksums for `/workspace`, `/output`, and any mounted volumes
   - perform an overlay diff of container filesystem vs base image
   - snapshot lowerdir/upperdir if overlayfs present or use filesystem-level snapshot (LVM/ZFS/BTRFS)
9. Capture network state: `ss -tunap`, `netstat -an`, active connections, recent firewall rules, loaded eBPF programs
10. Capture kernel and system logs: `dmesg --ctime`, `journalctl -u container-runtime.service --no-pager -n 1000`
11. Collect container runtime metadata: `docker inspect` / `crictl inspect` output, image digest, container command line, environment variables
12. Generate a signed forensic bundle and push to immutable store; register the bundle in the audit log (Rekor or enterprise transparency log)

### 5.4 Forensic capture implementation details
- Use privileged helper pods (K8s DaemonSet) with restricted capabilities to perform host-level snapshots; these run only on-demand via the operator and are RBAC-locked
- Memory capture:
  - CRIU: checkpoint running container into a tarball capturing process memory, fd table, and namespaces
  - gcore: produce core dump for PID when CRIU unavailable; then run `eu-readelf`, `strings` for quick inspection
  - For higher-fidelity Java artifacts: `jmap`, `jstack`, `jcmd VM.system_properties` and heap histogram via `jmap -histo`
- Filesystem snapshot:
  - use underlying storage snapshot (LVM/BTRFS/ZFS) by coordinating with storage provisioner
  - if snapshot not possible, archive `/workspace` and `/output` with `tar --numeric-owner --sort=name --mtime='UTC 1970-01-01'` to canonicalize metadata
- Network capture: use `tcpdump -w` inside the container namespace or attach to host interface for brief capture window; limit capture size and hash packet capture for integrity
- Process and env capture: dump `/proc/<pid>/environ`, `/proc/<pid>/cmdline`, `/proc/<pid>/mountinfo`

### 5.5 Automated evidence bundling and immutability
- Compose a forensic bundle with the following structure:
  - `incident.json` (metadata, incident ID, trigger reason, timestamps, worker/node)
  - `container-inspect.json` (runtime metadata)
  - `process-tree.tar.gz` (proc copies and fd targets)
  - `memory-dump/` (CRIU tarball or core dumps)
  - `fs-snapshot.tar.gz` (workspace/output snapshot)
  - `network.pcap` (if captured)
  - `diffoscope-report.html` (from dual-build step)
  - `entropy-features.json`
- Compute SHA-256 of bundle and sign with builder/key management service (KMS) key
- Upload bundle to immutable object storage with object-lock or to the Rekor transparency log with an attached payload (or pointer to object) and record returned UUID

### 5.6 Automated triage and prioritization
- Run a fast triage pipeline on the forensic bundle:
  - virus scanning of extracted binaries (YARA + ClamAV)
  - automated static heuristics: check for inserted class files, expanded resource sections, suspicious strings (C2 domains, obfuscated payload markers)
  - re-run entropy classifier on extracted class/method payloads
  - correlate with external threat intelligence (hash lookups, YARA repo)
- Triage scoring components:
  - `severity`: impact of modified artifact (executable vs docs)
  - `confidence`: entropy classifier + diffoscope classification + AI verification vote
  - `reproducibility`: whether discrepancy reproduces across re-runs or different builders
- Automatically escalate incidents above threshold to on-call security and optionally pause related pipeline queues and dependent releases

### 5.7 Forensics retention and chain-of-custody
- All artifacts and bundles must be write-once and retain an audit trail (who requested, who accessed, hashes, Rekor UUID)
- Provide role-based access to forensic bundles; require multi-party approval for release of raw captures
- Use signed attestations and timestamped Rekor entries to maintain chain-of-custody

### 5.8 Kubernetes enterprise deployment map
Provide a resilient K8s operator-driven architecture to enforce detection, containment, and forensic capture.

Core components:
- `cbad-controller` (operator): watches dual-build verification events, creates `Incident` CRs, orchestrates lockdown and forensic capture by issuing jobs/requests
- `runner-fleet` (CI runners): namespaced runner pods that perform hermetic builds; annotated with runner metadata and signed image digests
- `forensic-daemonset`: privileged pods on each node capable of CRIU, filesystem snapshotting, and host-level instrumentation; RBAC-restricted and admission-controlled
- `lockdown-webhook`: admission webhook to enforce PodSecurityPolicies for build pods (network disabled, no host mounts) and to reject non-conformant runner requests
- `artifact-store`: immutable object storage (S3 with Object Lock or Ceph with RBD snapshots) for forensic bundles and artifacts
- `transparency-log-adapter`: service that writes attestations to Rekor and records returned UUIDs in the `Incident` CR
- `ai-verifier-service`: Claude wrapper and verification API used for triage enrichment
- `alerting & incident-management`: integration with PagerDuty, SIEM, and ticketing systems

Deployment topology:
- Control Plane Services (HA): `cbad-controller`, `transparency-log-adapter`, `ai-verifier-service`, `results-aggregator`
- Node Agents: `forensic-daemonset` (privileged), `runner-fleet` pods (unprivileged inside separate namespaces)
- Storage: `artifact-store` (S3-compatible) with lifecycle and retention policies
- Network: isolate `runner-fleet` namespaces with NetworkPolicies; forensic agents require separate egress policies for upload to `artifact-store` only after signing

### 5.9 Kubernetes automated lockdown flow (CR-driven)
1. `cbad-controller` observes a failing verification result and creates `Incident` CR with status `open`
2. controller patches runner Pod: add annotation `cbad/quarantine=true`
3. `lockdown-webhook` or controller enforces immediate `kubectl exec` run to: 
   - `kubectl exec --namespace buildns <pod> -- pkill -STOP -f <build>` (SIGSTOP)
   - apply networkpolicy denying all traffic for the pod
4. controller schedules a `forensic-job` targeted at the node where Pod runs; the job uses `forensic-daemonset` to capture memory and filesystem
5. controller uploads signed forensic bundle via `transparency-log-adapter` and updates `Incident` CR with Rekor UUID and bundle checksums
6. controller sets `Incident` status = `triaged` after automated triage completes; if severity high, `Incident` -> `escalated`

### 5.10 Secure operational considerations
- Forensic capture tools must be audited, signed, and run from read-only images to avoid tampering
- Minimize privileged surface: forensic agents run only on-demand and under controller-driven RBAC
- Use ephemeral keys for signing with rotation and enforce HSM/KMS-backed key storage
- All network egress from the cluster to artifact-store/re crowd must be limited by allowlists and use mutual TLS

### 5.11 Forensic playbook snippets (automation commands)
Example CRIU-based capture run via helper pod (illustrative):

```bash
# pause container process (inside helper pod namespace)
kubectl exec -n buildns <build-pod> -- kill -STOP <pid>

# run CRIU via privileged forensic agent to checkpoint PID
kubectl exec -n forensic <agent-pod> -- criu dump -t <pid> --images-dir /tmp/criu-images --shell-job --leave-running

# copy criu image to artifact store
kubectl cp forensic/<agent-pod>:/tmp/criu-images ./incident-123-criu
aws s3 cp incident-123-criu s3://cbad-forensics/incident-123/ --acl private

# create signed bundle and upload to Rekor (pseudo)
tar -czf incident-123-bundle.tar.gz incident-123-metadata.json criu-images fs-snapshot.tar.gz network.pcap
sha256sum incident-123-bundle.tar.gz > incident-123-bundle.sha256
cosign sign --key <kms://...> incident-123-bundle.tar.gz
rekor-cli upload --file incident-123-bundle.tar.gz --signing-key <path>
```

### 5.12 Summary
This Section defines a rapid containment and high-fidelity forensic capture pipeline triggered by non-deterministic build verification failures. It prescribes atomic containment actions, CR-driven Kubernetes orchestration, forensic capture methods (CRIU/gcore/jmap), immutable evidence bundling, and an enterprise deployment map ensuring the platform scales and remains secure.
