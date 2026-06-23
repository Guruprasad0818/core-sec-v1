# CBAD Stage 5 — Bytecode Entropy & SLSA Attestation

## SECTION 3 — Bytecode Shannon Entropy Analysis Engine

### 3.1 Goals
- Compute Shannon entropy per-class-file and per-class-section (constant pool, method bytecode, attributes) to detect obfuscation and injected payloads.
- Provide deterministic normalization and section extraction for Java `.class` files.
- Feed entropy and auxiliary features into an ML classifier to distinguish benign variability from maliciously obfuscated artifacts.

### 3.2 Mathematical basis
Shannon entropy H for a byte stream X with alphabet of 256 byte values is:

H(X) = - \sum_{b=0}^{255} p_b log2(p_b)

where p_b is the empirical probability of byte value b in X. H is measured in bits per byte and ranges from 0 (all bytes identical) to 8 (uniform distribution).

### 3.3 Class-file section model
Parse `.class` into canonical sections:
- Magic + Version (header)
- Constant Pool (CP)
- Access flags, this_class, super_class, interfaces
- Fields
- Methods (for each method: attributes incl. Code attribute)
- Class attributes (SourceFile, InnerClasses, Signature, RuntimeVisibleAnnotations, etc.)

For each `.class` file compute entropy for these byte ranges separately:
- H_total: entropy of the entire class file
- H_cp: entropy of the constant pool block
- H_code_sum: entropy of concatenated method bytecode sequences
- H_max_method: maximum entropy among individual method Code attributes
- H_attributes: entropy of remaining attributes block

Also compute normalized measures:
- H_norm = H_section * (section_size / class_size)
- entropy density vector E = [H_cp, H_code_sum, H_attributes]

### 3.4 Normalization & canonicalization
To avoid false positives from metadata differences, canonicalize binary blobs before entropy calculation:
- strip or normalize timestamp-like attributes (SourceFile can be dropped or canonicalized)
- remove debug info if present or compute entropy both with and without debug sections
- canonicalize constant pool ordering where possible (for deterministic compilers) by reordering non-essential entries when semantics permit (only for baseline canonical model)
- for method Code attributes, strip out LineNumberTable and LocalVariableTable before measuring code entropy

### 3.5 Trigger thresholds (suggested)
Based on empirical characterization across large Java corpora (typical library and application classes):
- Normal / benign range: 4.5–5.5 bits/byte (whole-file H_total)
- Elevated suspicion range: 6.0–7.0 bits/byte (requires further classifier evidence)
- High-confidence malicious range: 7.5–8.0 bits/byte (strong indicator of compressed/packed/obfuscated data)

Section-level thresholds:
- H_code_sum > 6.5 and H_max_method > 7.2 => strong signal for method-level obfuscation
- H_cp > 6.8 => constant-pool obfuscation or embedded encrypted payloads

These thresholds should be tuned per corpus; use a labeled validation set to calibrate.

### 3.6 Auxiliary features for ML classifier
Construct a feature vector per `.class` file or per-artifact containing:
- Entropy features: H_total, H_cp, H_code_sum, H_max_method, H_attributes
- Size features: class_size, cp_size, code_size, num_methods, avg_method_size
- Opcode distribution vector: relative frequency of JVM opcodes (normalized)
- Byte n-gram statistics (e.g., top-256 bigrams frequencies)
- Section-level compression ratio: compressed_size(section)/section_size using zlib
- Symbol table sparsity: ratio of symbolic constant pool entries to binary payloads
- Control-flow density: avg(opcode_count / instruction_count) or estimated cyclomatic complexity per method (from bytecode analysis)
- Entropy delta to project baseline: H_total - baseline_H_for_same_package
- Diffoscope tags: structural anomalies (if dual-build data available)

### 3.7 ML model design
- Model: gradient-boosted decision trees (XGBoost/LightGBM) for tabular features, or a small feed-forward neural network for combined features; ensemble models recommended (tree + calibrated logistic regressor)
- Labels: `benign`, `suspicious`, `malicious` from curated corpora (open-source libraries, known obfuscators, packed malware samples)
- Loss: cross-entropy with class weighting (malicious samples are rare)
- Evaluation metrics: PR-AUC, ROC-AUC, precision@k, and false positive rate at fixed recall

Training procedure:
1. Gather datasets: large benign corpus (Maven Central, standard library) and malicious/obfuscated samples (known malware, class file packers, obfuscators)
2. Precompute entropy and auxiliary features for every sample
3. Split into train/val/test with stratification by package and project to avoid leakage
4. Use k-fold CV (k=5) and hyperparameter tuning (Bayesian or grid) on learning rate, tree depth, and regularization
5. Calibrate probabilities with isotonic regression or Platt scaling for production thresholds
6. Set production decision thresholds based on desired precision/recall tradeoffs and operational capacity for manual triage

### 3.8 Explainability & triage signals
- Report top contributing features per prediction using SHAP for XGBoost
- Produce per-method entropy heatmaps to guide code review (method name + entropy + bytes)
- Attach diffoscope outputs (when available) linking entropy anomalies to binary payload differences

### 3.9 Operational pipeline integration
- Run entropy engine during dual-build verification aggregation step and store features in artifact metadata store
- Flag any artifact exceeding calibrated thresholds for immediate quarantine and deeper static/dynamic analysis
- Maintain rolling baseline profiles per project and update baselines with human-reviewed benign variance

---

## SECTION 4 — SLSA Supply Chain Attestation (CycloneDX SBOM, SLSA v3/4, Rekor)

### 4.1 Goals
- Produce machine-readable SBOMs (CycloneDX) for all build artifacts
- Generate SLSA-compliant provenance attestations at Level 3/4
- Submit signed provenance and SBOMs to an immutable transparency log (Rekor) for public/non-repudiable audit trails

### 4.2 CycloneDX SBOM generation pattern
- Use `syft` or `cyclonedx-bom` to generate SBOMs for source trees, container images, and packages

Example: generate a CycloneDX SBOM for a built artifact:

```bash
# for image
syft <image>:<digest> -o cyclonedx-json > sbom-image.json

# for filesystem/source
syft dir:/workspace/output -o cyclonedx-json > sbom-artifact.json

# optional: convert to SBOM formats
cyclonedx-cli convert --input-format json --output-format xml sbom-artifact.json > sbom-artifact.xml
```

SBOM content must include component checksums, origin/source repository, supplied materials, and relationships between components.

### 4.3 SLSA provenance generation (Level 3/4)
SLSA provenance requires a signed attestation containing builder identity, materials, invocation details, and metadata that prove the build process.

Provenance fields (recommended):
- `builder`: identifier for the build system and key ID
- `buildType`: e.g., `https://example.com/ci/builds/gradle` or SLSA standard types
- `invocation`: command-line, environment, and entrypoint
- `metadata`: startTime, endTime, buildToolVersions, buildConfig
- `materials`: list of digests for source tarball, toolchain images, and consumed artifacts
- `byproducts`: generated SBOM file digests, attestation digests

Use in-toto/v1 or the SLSA Provenance JSON schema (e.g., `provenance.json`).

Example minimal provenance JSON (schema-illustrative):

```json
{
  "builder": {"id": "oci-pinned://registry.company.com/compiler:v1@sha256:..."},
  "buildType": "https://slsa.dev/buildType/github.com/example/project/build",
  "invocation": {"command": ["./build.sh"], "environment": {"SOURCE_DATE_EPOCH": "1600000000"}},
  "metadata": {"startedOn": "2026-06-23T12:00:00Z", "finishedOn": "2026-06-23T12:10:00Z"},
  "materials": [
    {"uri": "git+https://github.com/example/repo@refs/heads/main", "digest": {"sha1": "...", "sha256": "..."}},
    {"uri": "oci://registry.company.com/compiler:v1", "digest": {"sha256": "..."}}
  ]
}
```

### 4.4 Signing provenance and SBOMs
- use Sigstore/cosign for signing container images and opaque artifacts
- generate a keypair per builder or use ephemeral keys provisioned by a secure KMS and rotate regularly

Example: sign provenance and SBOM with `cosign`:

```bash
# sign an SBOM JSON
cosign sign --key <kms://...> --output-signature sbom-artifact.json.sig sbom-artifact.json

# or use OIDC identity for ephemeral keys
cosign sign --oidc-issuer https://token.issuer --output-signature provenance.json.sig provenance.json
```

Attach signature(s) and public key identity info to the attestation bundle.

### 4.5 Rekor transparency log write pattern
Rekor (part of Sigstore) accepts signed artifacts and stores immutable entries.

High-level flow:
1. create an attestation bundle containing `provenance.json`, `sbom-artifact.json`, and signatures
2. upload the bundle to Rekor using its API or client libraries

Example Rekor CLI flow (illustrative):

```bash
# create entry JSON
cat <<EOF > rekor-entry.json
{
  "apiVersion": "0.0.1",
  "kind": "hashedrekord",
  "spec": {
    "data": {"hash": {"algorithm": "sha256", "sum": "<sha256-of-bundle>"}},
    "signature": {"content": "$(base64 -w0 < provenance.json.sig > /dev/stdout)", "publicKey": "..." }
  }
}
EOF

# post to Rekor
curl -X POST --data-binary @rekor-entry.json https://rekor.example.com/api/v1/log/entries
```

Or use `rekor-cli` / Sigstore SDK for typed submission which returns an index and UUID for audit.

### 4.6 SLSA Level mapping and enforcement
- Level 3: authenticated build with provenance and materials recorded; ensure builder identity is verified and materials are recorded
- Level 4: reproducible builds and hermetic verification plus two-party attestation, e.g., independent builder verification and threshold signatures or multi-signer attestations

Implementation notes:
- Level 3: sign provenance with builder key; write provenance + SBOM to Rekor
- Level 4: require two independent builders to each produce signed provenance, and write both attestations to Rekor under the same artifact digest; consider requiring multi-sig via threshold keys

### 4.7 Rekor entry design recommendations
- store digest of the artifact and a pointer to the provenance/SBOM artifacts
- include the certificate chain or OIDC issuer identity that links the build invocation to a principal
- mark entries with `slsa_level` metadata and include the verification status from the dual-build engine

### 4.8 Example automation workflow (commands)

```bash
# generate SBOM
syft dir:/workspace/output -o cyclonedx-json > sbom-artifact.json

# create provenance (tooling or custom generator)
python generate_provenance.py --manifest build-manifest.json --out provenance.json

# sign provenance with cosign
cosign sign --key <kms://...> provenance.json

# make provenance bundle
tar -czf attestation-bundle.tar.gz provenance.json provenance.json.sig sbom-artifact.json sbom-artifact.json.sig

# calculate bundle digest
sha256sum attestation-bundle.tar.gz

# push to Rekor (example using API)
rekor-cli upload --file attestation-bundle.tar.gz --signing-key <path-to-key>
```

### 4.9 Auditing and verification
- when verifying an artifact, fetch Rekor entries by artifact digest and verify signatures and signer identities
- ensure materials in provenance match the artifact digest and compiled output
- cross-check SBOM component checksums against the artifact contents

### 4.10 Summary
Section 4 provides a practical implementation pattern for generating CycloneDX SBOMs, creating signed SLSA v3/4 provenance, and writing attestations to an immutable Rekor transparency log. Use Sigstore/cosign, Rekor, and strict builder key policies to achieve non-repudiable supply chain attestations.
