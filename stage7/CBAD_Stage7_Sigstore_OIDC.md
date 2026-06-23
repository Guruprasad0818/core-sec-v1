# CBAD Stage 7 — Multi-Party Keyless Signing and Validation

## SECTION 1 — Sigstore Cryptographic Architecture

### 1.1 Overview
This section documents the keyless signing loop using Sigstore components: `cosign` (client), `Fulcio` (OIDC-backed Certificate Authority), `Rekor` (transparency log), and optional `Trust Roots`/fulcio CT-like verification. The design focuses on strong non-repudiation without long-lived signing keys by minting short-lived X.509 leaf certificates bound to OIDC identities, recording attestations in Rekor, and verifying via certificate chain + inclusion proofs.

### 1.2 High-level keyless signing sequence
1. Developer/CI requests an OIDC identity token from an OIDC provider (GitHub/GitLab/Azure/other) for the running job.
2. `cosign` (or client) calls Fulcio's ``/signedcertificate`` endpoint, presenting the OIDC token and a public key (generated ephemeral on the client).
3. Fulcio validates the token (issuer, audience, expiry, signature) and issues a short-lived X.509 certificate binding the public key to the identity claims (sub, email, kid, or custom claims).
4. `cosign` uses the generated certificate to sign the artifact (or signs the artifact’s digest using the ephemeral private key and attaches the certificate).
5. `cosign` uploads the signature, certificate, and optionally an attestation (e.g., SLSA provenance) to Rekor as a transparency log entry.
6. Verification: `cosign verify` fetches the certificate, confirms Fulcio-signed chain, queries Rekor for the log entry, validates inclusion proof and signed tree head (STH), and checks the certificate was issued to an accepted identity and not revoked.

### 1.3 Fulcio interactions and validation
- Fulcio is configured to accept OIDC tokens from a set of trusted OIDC issuers. Each issuer configuration contains accepted audiences and claim mappings.
- Upon receiving a certificate request, Fulcio:
  - verifies the OIDC token signature and `iss` claim against configured issuers;
  - verifies `aud` is acceptable for the Fulcio instance (or for the specific root);
  - extracts identity claims (e.g., `email`, `sub`, `repository_claims` like `repository` and `sha` for GitHub) and encodes them into certificate subject/subjectAltName;
  - issues a short-lived X.509 leaf certificate with a validity window (e.g., 60 seconds to 15 minutes) signed by Fulcio's CA or an intermediate CA.
- Logging: Fulcio emits an attestation or records certificate metadata (serial, public key, subject) to Rekor to create an auditable trail.

### 1.4 Rekor append validation and transparency guarantees
- When `cosign` writes a signature/attestation to Rekor, Rekor returns an entry UUID and the log index. Rekor stores:
  - payload (the assertion, e.g., signature blob)
  - metadata: certificate, public key id, requestor, timestamp
  - signed entry structure with a canonical serialized representation
- Verification uses Rekor features:
  - inclusion proof: Rekor can provide a Merkle inclusion proof that the entry exists in the log at a given tree head
  - signed tree head (STH): Rekor publishes STHs signed with its key; clients verify STH signatures to ensure log integrity
  - auditors/verifiers perform consistency checks between STHs to detect log equivocation
- For full non-repudiation, verification checks both certificate chain (Fulcio->root) and Rekor inclusion proof for the signature blob; absence of Rekor entry or mismatch indicates potential foul play or signature omission.

### 1.5 Cosign execution patterns (sign and verify)
- Keyless sign flow (example):
  - `cosign generate-key-pair` (optional for key-based signing)
  - `cosign sign --key <key> <image>` or keyless: `cosign sign --oidc-issuer https://token.actions.githubusercontent.com <image>`
  - cosign generates ephemeral keypair (if keyless) and calls Fulcio to receive a certificate, then signs and records to Rekor.
- Verify flow (example):
  - `cosign verify --cert-oidc-issuer https://fulcio.example.com --rekor-url https://rekor.example.com <image>`
  - `cosign` will verify the signature matches the artifact, validate the certificate chain (Fulcio root or trusted root), and query Rekor for the corresponding entry; it will validate inclusion proof and STH.
- Offline verification:
  - fetch Rekor entry JSON and inclusion proof; fetch Fulcio CA certificates and certificate chain; use `cosign verify-blob` with `--certificate` and `--rekor` flags to validate without contacting online services (provided you have STH+inclusion proofs).

### 1.6 Multi-party and threshold considerations
- For higher assurance, require multiple independent signatures/attestations (multi-signer) and record each to Rekor. Verification requires N-of-M criteria.
- Support for threshold signing can be achieved at higher layers by requiring multiple cosign signatures or by using a separate threshold signing service; Rekor will hold all entries and the verifier checks presence of required signers and their attestations.

### 1.7 Revocation and root rotation
- Fulcio issues short-lived certificates so conventional revocation is less critical; however, Fulcio and Rekor must support root/intermediate rotation with continuity:
  - publish new root certificates and sign future certificates with new intermediates
  - Rekor STHs allow auditors to validate continuity across root rotations
- For emergency revocation, add a revocation list in Rekor or integrate OCSP-like checks backed by transparency logs.

### 1.8 Audit and governance
- Store full attestations: SLSA provenance, CycloneDX SBOM, and cosign signature in Rekor entries for auditability.
- Record mapping from CI build ID -> Rekor UUID(s) for each artifact signed; use this mapping during verification and incident response.

---

## SECTION 2 — OIDC Identity Integration Mapping

### 2.1 Overview
This section maps OIDC federated identity flows for common CI providers and cloud IAM. For keyless signing, CI jobs obtain OIDC tokens scoped to the job, which are then presented to Fulcio to mint certificates. The mapping covers GitHub Actions, GitLab CI, Azure DevOps, and AWS IAM (OIDC role federation).

### 2.2 Common OIDC token requirements
Fulcio expects tokens with:
- `iss`: issuer URL (trusted OIDC provider)
- `sub`: subject (string representing identity, e.g., repo/workflow/actor)
- `aud`: audience (must include Fulcio client ID or configured audience)
- `exp`/`iat`: bounded lifetime
- provider-specific claims (e.g., `repository`, `ref`, `workflow` for GitHub) useful for binding certificate to a specific build

Tokens should be minted with minimal privileges and short lifetimes.

### 2.3 GitHub Actions
Flow:
1. Configure GitHub Actions job with `permissions: id-token: write` and `id-token: write` for steps that need OIDC.
2. `actions/checkout` + `uses: sigstore/cosign` or `cosign` CLI may request the OIDC token via the local metadata service endpoint: `ACTIONS_ID_TOKEN_REQUEST_URL` with `ACTIONS_ID_TOKEN_REQUEST_TOKEN`.
3. Token audience: cosign requests a token for Fulcio by specifying `audience` (Fulcio must be configured to accept that audience). Typical audience is the Fulcio endpoint or a configured string.
4. Fulcio validates `iss=https://token.actions.githubusercontent.com`, checks `repository`, `ref`, `sha`, and issues certificate only if claims meet policy (e.g., repo allowlist, branch protect rules).

Configuration steps:
- In Fulcio config, add `https://token.actions.githubusercontent.com` as trusted issuer and configure allowed `aud` values.
- CI pipeline: enable `id-token: write` and call `cosign sign --oidc-issuer https://token.actions.githubusercontent.com --oidc-client-id <fulcio-audience>`

Security notes:
- Bind issuance to `repository` and `sha` claims to avoid token replay across repositories.
- Use short token lifetimes and verify `aud` on Fulcio.

### 2.4 GitLab CI
Flow:
1. GitLab exposes a JWT via `CI_JOB_JWT` or via `gitlab-jwt` endpoint when configured. GitLab's OIDC token includes claims like `project_path` and `ref`.
2. Configure Fulcio to trust `https://gitlab.com` (or self-hosted GitLab issuer URL) and accept tokens with configured `aud` values.
3. `cosign` or a custom signer fetches `CI_JOB_JWT` and presents it to Fulcio for a certificate.

Configuration steps:
- Enable GitLab OIDC token generation for the project or group.
- Add GitLab issuer and allowed audiences to Fulcio config.
- Validate `project_path` and `ref` claims against policy before certificate issuance.

### 2.5 Azure DevOps
Flow:
1. Azure DevOps supports OIDC federation for pipelines using `system.accessToken` or the OIDC token endpoint when configured.
2. The pipeline requests an OIDC token scoped to the pipeline; token includes `aud` and claims like `repo`, `project`.
3. Fulcio must be configured to accept Azure DevOps issuer `https://vstoken.azure.net` (or tenant-specific issuer for enterprise) and audiences.

Configuration steps:
- Setup OIDC in Azure DevOps Service Connections and configure pipeline to request OIDC token.
- Add Azure DevOps issuer/audience to Fulcio and configure claim validation for project/repo.

### 2.6 AWS IAM OIDC provider
Flow options:
A. CI -> Fulcio directly using provider JWT
- Some systems can obtain an OIDC token from AWS IAM OIDC provider; however AWS commonly uses OIDC to allow external entities to assume IAM roles.
- For GitHub Actions -> AWS, GitHub can request a token for `sts:AssumeRoleWithWebIdentity` to assume a role; the resulting credentials are AWS temporary keys, not a raw OIDC token suitable for Fulcio.

B. Recommended pattern: use federated identity from CI provider directly with Fulcio
- Configure Fulcio to trust GitHub/GitLab/Azure issuers; these tokens present identity directly to Fulcio.
- For AWS workloads, use AWS IAM roles with OIDC identity provider to bind AWS IAM principals to Fulcio-validated identities if signing happens within AWS.

AWS-specific mapping for signing inside AWS environment:
1. An AWS CodeBuild job may assume a role via OIDC; inside the job, a short-lived token or identity can be presented to Fulcio if configured to accept AWS issuer (e.g., `https://oidc.eks.<region>.amazonaws.com/id/...`).
2. Configure Fulcio to trust the appropriate AWS OIDC issuer and map claims such as `sub` and `aud` to allowed principals.

### 2.7 Audience and claim mapping best practices
- Use strict `aud` values: Fulcio should accept only configured audiences; cosign should request tokens targeting Fulcio's audience.
- Map identity claims to certificate subjectAltName entries (email, repository, project, sha); keep required claims minimal but sufficient for traceability.
- Enforce short token lifetime and one-time-use semantics when possible.

### 2.8 Example Fulcio issuer configuration snippet (conceptual)

```yaml
trusted_issuers:
  - issuer: https://token.actions.githubusercontent.com
    audiences: ["sigstore", "https://fulcio.example.com"]
    claim_mapping:
      repo: repository
      sha: commit
  - issuer: https://gitlab.com
    audiences: ["sigstore"]
  - issuer: https://sts.windows.net/<tenant>
    audiences: ["sigstore"]
```

### 2.9 Security controls and policy enforcement
- Enforce repository and ref allowlists; require branch protection or PR checks before allowing signing in CI flows.
- Require multi-signer policy for release artifacts: e.g., require both CI signature and maintainer signature from a trusted device.
- Monitor Rekor entries for unexpected issuers or anomalous signing patterns.

### 2.10 Summary
This mapping provides direct OIDC integration strategies for major CI providers and AWS IAM. Configure Fulcio with strict issuer/audience mappings and claim validations, require minimal claims for binding, and use Rekor for append-only provenance guaranteed by transparency proofs.

## SECTION 3 — Multi-Party Human Approval Workflow

### 3.1 Goals
- Provide an out-of-band human approval gate requiring an independent security signature for production-bound containers.
- Enforce that the security signature is submitted within a strict 24-hour expiration window; otherwise the artifact is ineligible for deployment.

### 3.2 High-level flow
1. Build pipeline produces artifacts (images, SBOM, provenance) and performs initial keyless signing via CI (cosign keyless). A Rekor entry is created for the CI signature.
2. The pipeline publishes an approval request to the `approval-service` with artifact digest, SBOM link, provenance link, and Rekor UUID(s).
3. `approval-service` notifies an independent human approver group (security on-call) via configured channels (Slack, email, or internal UI).
4. Approver inspects SBOM, provenance, diffoscope reports, entropy/ML signals, and either `approve` or `reject` within 24 hours.
5. On `approve`, approver uses their own signing principal (hardware-backed key or OIDC-bound ephemeral cert) to cosign the artifact; cosign writes a second Rekor entry containing the approver's signature and attestation.
6. The `approval-service` verifies both Rekor entries (CI signer + approver), validates certificate chains and inclusion proofs, and emits a signed `release-attestation` recorded to Rekor that includes both signatures and a timestamp.
7. The deployment system only promotes artifacts with a valid `release-attestation` containing an approver signature within the 24-hour window.

### 3.3 Approver identity and signing options
- Hardware-backed signing: approvers use `cosign` with `--key` pointing to a YubiKey or TPM-protected key; keys may be wrapped by KMS and require operator presence.
- Keyless approval: approver obtains OIDC token from an enterprise IdP and requests Fulcio issuance for an ephemeral certificate bound to their identity; cosign uses the certificate to sign and Rekor to log the approval.
- Multi-party policy: allow require N-of-M approvers by demanding multiple Rekor entries with expected approver identities.

### 3.4 24-hour expiration semantics
- Enforce start_time as the time the initial CI signature Rekor entry was created.
- Approval must be recorded (approver Rekor entry) within start_time + 24 hours; the `release-attestation` contains timestamps and Rekor indexes for validation.
- If approval occurs after 24 hours, the `approval-service` rejects automatic promotion and requires re-build and re-sign to ensure freshness.

### 3.5 Automating the approval UI & API
- `approval-service` API endpoints:
  - `POST /request-approval` -> create approval ticket, return ticket ID and Rekor links
  - `GET /ticket/{id}` -> fetch artifact details, SBOM, provenance, diffoscope, ML signals
  - `POST /ticket/{id}/approve` -> approver calls cosign (or service triggers cosign with approver's delegated OIDC) to create approval signature
  - `POST /ticket/{id}/reject` -> rejection reason stored
- UI: interactive display with SBOM viewer, provenance timeline, and quick actions `approve/reject`; include `one-click cosign` for hardware-key users via browser extension bridging to local cosign agent

### 3.6 Security controls
- Enforce MFA and device attestation for approvers when signing: require hardware key presence or enterprise-provisioned device attestation.
- Audit: every approval action writes an auditable Rekor entry and stores operator identity, ip address, and proof-of-presence.
- Least-privilege: approver service only obtains ephemeral signing capability, no long-lived access to private keys.

### 3.7 Failure modes and recovery
- If approver key compromise suspected, revoke approval by creating a revocation attestation in Rekor and invalidate any `release-attestation` referencing that approver.
- Reprovisioning: if approval window expires, require rebuild and new CI signature to avoid replay.

### 3.8 Example policy rules
- `production-release` rule: requires CI signature + at least one approver signature with `role: security` and `email` in `security@company.com` within 24h.

## SECTION 4 — Kubernetes Admission Controller Webhook (Validation/OPA)

### 4.1 Goals
- Implement an admission validation layer that rejects pod/image creation unless the image has valid Sigstore attestations: CI signature, approver signature, SBOM attestation, and Rekor inclusion proofs.
- Support both a custom validating webhook (service) and an OPA/Gatekeeper constraint template.

### 4.2 Admission validation checks
For each Pod creation or Image admission event, the controller must:
1. Extract the image digest from the Pod spec (`image: name@sha256:...`) and fail if image uses a mutable tag only (recommend digest-only policy).
2. Query the local cache / Rekor for signature entries matching the artifact digest.
3. Validate signature certificates: Fulcio chain, issuer trusted, and certificate subject matches expected claim mapping (repo, sha, approver identity).
4. Verify inclusion proofs and STH consistency for Rekor entries used by CI and approver signatures.
5. Verify SBOM attestation exists, is co-signed, and components match image contents.
6. Check `release-attestation` presence and timestamp (approval within 24h of CI signature creation).
7. If any check fails, deny admission with a clear rejection message including missing item(s) and Rekor UUIDs.

### 4.3 Webhook service blueprint
- Service responsibilities:
  - TLS-terminated HTTPS server with a serving cert stored in Kubernetes secret
  - Authenticate caller metadata and enrich with k8s Pod info
  - Caching layer for Rekor lookups and certificate chains to reduce external calls
  - Offline verification mode using locally cached STHs and inclusion proofs for high-availability
  - Audit logging to artifact-store and SIEM

### 4.4 OPA/Gatekeeper alternative
- Implement a `ConstraintTemplate` and `Constraint` that uses an external data source (the webhook or an OPA data client) to perform Rekor and cosign checks.
- Rego policy pseudo-signature check snippet:

```rego
package cbad.signverify

deny[msg] {
  input.request.kind.kind == "Pod"
  img := input.request.object.spec.containers[_].image
  not image_has_valid_release_attestation(img)
  msg = sprintf("Image %v is missing valid release attestation", [img])
}

image_has_valid_release_attestation(img) {
  digest := extract_digest(img)
  att := data.rekor.lookup[digest]
  att.ci_signature_present
  att.approver_signature_present
  att.sbom_attached
  within_24h(att.ci_timestamp, att.approver_timestamp)
}
```

### 4.5 Deployment and RBAC
- Webhook deployment:
  - ServiceAccount with minimal permissions: read-only access to Pods, Secrets (for signing policy), and ConfigMaps
  - ClusterRoleBinding to allow webhook to list/get images and secrets required for verification
  - MutatingWebhookConfiguration/ValidatingWebhookConfiguration registered with appropriate `failurePolicy: Fail` to enforce deny-by-default

### 4.6 Performance & caching
- Cache Rekor lookups keyed by artifact digest with TTL aligned to STH rotation window (e.g., 10 minutes)
- Pre-warm cache for approved images synced from CI `approval-service` to reduce lookup latency
- Use parallel verification: validate certificate chain and fetch Rekor inclusion proofs concurrently

### 4.7 Offline verification mode and STH anchoring
- Support verifying signatures offline using pre-fetched STHs and inclusion proofs stored in the cluster; run periodic STH refreshes via the `transparency-log-adapter` service
- In cases where live Rekor is unavailable, admission controller can either `Fail` (secure-by-default) or `Defer` (allow with alert) based on policy

### 4.8 Sample rejection message
"Admission denied: image sha256:abcd... missing approver signature (expected Rekor entry not found). CI signature: rekor://<uuid-ci>, approver: rekor://<uuid-approver>; approval window expired."

### 4.9 Testing and verification
- Provide an integration test suite that:
  - signs test images in a staging Rekor instance
  - exercises happy-path and failure scenarios (missing approver, stale approvals, malformed SBOM)
  - validates webhook behavior under load (concurrent pod creations)

### 4.10 Summary
This Admission Controller and OPA/Gatekeeper blueprint enforces that only artifacts with full keyless sigstore provenance and multi-party approvals may run in production. It prioritizes secure-by-default `Fail` semantics and provides caching/backoff for availability.

## SECTION 5 — Enterprise Governance & Compliance Framework

### 5.1 Goals
- Provide an auditable, verifiable trail for all signing, approval, and admission events that meets SOC 2 and ISO 27001 controls.
- Implement robust backup, verification, and recovery procedures for Rekor in both public and private deployment modes.

### 5.2 Audit trail architecture
- Ingest points: CI (cosign sign), approver signatures, admission controller decisions, and Rekor append events are all forwarded to the audit pipeline.
- Immutable storage: store signed bundles (attestations, SBOMs, provenance, Rekor UUIDs) in WORM-enabled object storage (S3 Object Lock / Azure Immutable Blob) with retention policies.
- Indexing: metadata (artifact digest, Rekor UUIDs, signers, timestamps, STHs) stored in an append-only database (e.g., PostgreSQL with WAL archiving and controlled write access) and cross-referenced to object-store blobs.
- Transparency: Rekor remains the canonical append-only index for signatures; mirror Rekor entries to an internal transparency index to support offline verification.

### 5.3 Log verification scripting
- Provide reusable verification scripts for operators to verify Rekor-backed attestations and STH continuity.

Operator verification script (bash, illustrative):

```bash
# verify-entry.sh: verify Rekor entry and STH
REKOR_URL=${1:-https://rekor.example.com}
UUID=$2

# fetch entry
curl -s "$REKOR_URL/api/v1/log/entries/$UUID" -o entry.json

# extract body and compute digest
PAYLOAD=$(jq -r '.["'"$UUID"'"].body' entry.json)
echo "$PAYLOAD" | base64 -d > entry.payload

# verify inclusion (requires pre-fetched STH and inclusion proof)
curl -s "$REKOR_URL/api/v1/log/publicKey" -o publickey.pem
# fetch STH
curl -s "$REKOR_URL/api/v1/log/records" -o sth.json
# (use Rekor client libraries for inclusion proof verification)
echo "Entry $UUID downloaded; verify using Rekor client or SDK"
```

### 5.4 Backup and replication patterns (public vs private Rekor)
- Public Rekor usage:
  - rely on upstream Rekor service for append-only guarantees
  - mirror entries to internal object store via periodic jobs (`rekor-cli` or SDK) to maintain local copies and enable offline verification
  - maintain STH snapshots signed by the Rekor STH keychain for future audits

- Private Rekor deployment:
  - run a privately-managed Rekor cluster with replication across multiple availability zones
  - enforce RBAC and mTLS on Rekor API access
  - configure automated backups: periodic export of log shards, STHs, and private keys to HSM-managed KMS and encrypted object storage
  - implement multi-site replication (async mirror) to reduce single-site failure risk

### 5.5 Backup verification and recovery drills
- Periodic verification job that:
  - replays a sample of Rekor entries and confirms inclusion proofs against stored STHs
  - verifies that archived attestation bundles can be retrieved, signature-verified, and mapped to Rekor UUIDs
- Recovery drill runbook:
  1. Promote mirror cluster to primary if Rekor cluster degraded
  2. Recompute STHs and re-sign with a threshold of operator keys (HSM)
  3. Re-run verification script against whole archive and produce audit report

### 5.6 Compliance mapping (SOC 2 / ISO 27001)
- Control families mapped:
  - Access Control (ISO A.9 / SOC 2 CC6): enforce RBAC for signing, Rekor writes, and approval operations; MFA and hardware-backed signing for approvers
  - Change Management (ISO A.12 / SOC 2 CC4): record all changes to signing policy and profile repository in signed manifests and Rekor entries
  - Logging and Monitoring (ISO A.12.4 / SOC 2 CC7): centralize logs, retain immutable audit trails, alert on anomalous signing or Rekor inconsistencies
  - Cryptographic Controls (ISO A.10 / SOC 2 CC6): short-lived certificates, HSM/KMS-backed root keys, and key rotation policies
  - Business Continuity (ISO A.17 / SOC 2 CC8): backup/replication for Rekor and artifact-store; documented DR procedures and recovery SLAs

### 5.7 Implementation roadmap (milestones)
1. Phase 1 — Foundations (1 month):
   - Deploy Rekor (private) or integrate with public Rekor; configure Fulcio trust and cosign in CI; enable basic logging to object store
2. Phase 2 — Audit & Mirroring (1 month):
   - Implement mirroring job, STH snapshotting, and basic verification scripts; wire audit index and retention policies
3. Phase 3 — Governance & Approval (1 month):
   - Build `approval-service`, integrate approver signing flows, and require approver Rekor entries for production promotion
4. Phase 4 — DR & Compliance (2 months):
   - Implement Rekor backups, multi-AZ replication, recovery drills, and SOC 2/ISO-ready documentation and evidence collection
5. Phase 5 — Certification (3 months):
   - Engage external auditors, produce control evidence, remediate findings, and obtain SOC 2 Type II / ISO 27001 certification as required

### 5.8 Evidence collection & audit artifacts
- Automate collection of evidence artifacts for auditors:
  - list of Rekor entries per release (with UUIDs and STH snapshots)
  - key rotation logs and KMS/HSM audit events
  - approval-service logs showing approver identities and timestamps (with access controls)
  - backup/restore test reports and recovery exercise logs

### 5.9 Operational recommendations
- Enforce immutable retention and separation of duties: operators who can modify profiles cannot approve production releases alone
- Regularly rotate Fulcio/Rekor keys and document rotation in Rekor with signed attestations
- Provide read-only auditor access to STH snapshots, audit indexes, and WORM object-store buckets

### 5.10 Summary
Section 5 outlines a complete governance and compliance framework that leverages Rekor as the transparency backbone, WORM storage for archival evidence, and scripted verification/recovery procedures to satisfy SOC 2 and ISO 27001 requirements. Follow the phased roadmap to reach production-grade compliance and continuous auditability.
