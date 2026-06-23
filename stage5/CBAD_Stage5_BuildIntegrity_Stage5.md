# CBAD Stage 5 — Build Integrity Platform

## SECTION 1 — SolarWinds Threat Model & Hermetic Build Architecture

### 1.1 Threat model overview

This stage targets SolarWinds-style supply chain attacks that inject malicious behavior during build-time via compromised build tooling, dependency tampering, or non-hermetic environments. The objective is to eliminate all sources of nondeterminism, isolate the compiler toolchain, and enforce reproducible binary output across independent builds.

Threats addressed:
- build host compromise injecting malicious compiler flags, pre/post build hooks, or runtime payloads
- compromised network dependencies or package downloads during build execution
- nondeterministic compiler outputs caused by environment variables, timestamp leakage, or random seeds
- hidden build-time data exfiltration through network access or external tool invocation
- untrusted host filesystem artifacts affecting link order, file metadata, or tool search paths

### 1.2 Hermetic build architecture

The architecture enforces a strictly hermetic lifecycle from source checkout to final artifact generation.

Key components:
- `trusted source artifact`: signed source tarballs/checkouts from the repository with provenance metadata
- `hermetic build container`: OCI containers instantiated from signed base images containing only pinned compiler toolchains and deterministic build utilities
- `build inputs manifest`: explicit listing of compiler version, linker version, build flags, environment variables, and all input file checksums
- `isolated execution environment`: no outbound network, no mounted host binaries, and no non-declared volumes
- `reproducibility policy engine`: validates the build environment and enforces deterministic compiler/linker settings
- `audit logging`: immutable record of container image digest, build manifest, and build result checksums

### 1.3 OCI container isolation

Achieving absolute hermeticity requires container-based sandboxing with strict OCI runtime configuration.

Isolation requirements:
- network disabled: `--network=none`, no DNS or host namespace access
- no host mount propagation: only mount the source tree and an explicit scratch volume containing declared inputs
- user namespace enforcement: build runs as an unprivileged user inside the container
- read-only system image: `/usr`, `/lib`, `/bin`, and toolchain directories are read-only
- explicit writable paths: `/workspace`, `/tmp`, and `/output` only
- no shell fallback to host binaries: container must contain all required build tools and script interpreters

### 1.4 Dependency and toolchain pinning

The build must only use explicit, pinned versions of compiler toolchain components.

- compiler binaries pinned by digest and cryptographic signature
- linker, assembler, archive, and debugger utilities pinned likewise
- language runtimes, build helpers, and static analysis utilities included in the signed image or provided as declared input artifacts
- no dynamic dependency fetching during the build; all dependencies are available locally in the container or via the declared input manifest
- manifest includes exact checksums for every header, library, source file, and build script

### 1.5 Build manifest and provenance

A hermetic build manifest captures every build input and environment property.

Manifest sections:
- `source checksum`: SHA-256 digest of source tree and git metadata (commit ID, patch set)
- `compiler digest`: OCI image digest and compiler binary checksums
- `build_toolchain`: versions and checksums for `gcc/clang`, `ld/ld.lld`, `as`, `ar`, `strip`, `cmake`, `ninja`, `cargo`, `maven`, `gradle`
- `build_flags`: exact compiler/linker flags, sanitizer flags, optimization level, debug info controls, and preprocessor defines
- `env_vars`: explicit environment variables allowed in the build, with fixed values
- `inputs`: list of all source files, generated sources, and prebuilt artifacts with checksums
- `outputs`: declared output artifact paths and expected checksum algorithm
- `build_date_policy`: prohibition on embedding build-time timestamps or a canonical timestamp replacement strategy

### 1.6 Deterministic compilation mechanics

The platform must enforce compiler and linker determinism at the code-level.

Determinism controls:
- use deterministic compiler flags: `-fno-ident`, `-fdebug-prefix-map=OLD=NEW`, `-frandom-seed=0`, `-Wno-date-time`, `-Wno-missing-prototypes` where applicable
- canonicalize file paths inside debug sections using build-prefix and source-prefix mappings
- suppress build timestamps by replacing them with fixed epoch values or using deterministic time stamping options like `SOURCE_DATE_EPOCH`
- force stable object file order in archives and link commands by sorting input lists lexicographically
- enforce reproducible archive creation with `ar --sort=filename` and deterministic mode where available
- sanitize and normalize metadata fields in compiler-generated debug information, symbol tables, and DWARF sections

### 1.7 Compiler mechanics for isolation

The build process must bind compiler execution to fixed, declared inputs only.

Compiler isolation mechanics:
- toolchain in a sealed directory within the container, mounted read-only
- disable dynamic linker search paths beyond the declared toolchain directories
- use `-nostdinc`, `-nostdlib`, and explicit include/library paths for C/C++ builds
- for Java builds, use a pinned JDK/JRE inside the container and disable system classpath lookup
- for Go/Rust builds, use module vendoring with exact `go.sum` / `Cargo.lock` checksums and no network fetch
- enforce deterministic language-specific flags such as `-X` replacement values in Go, `SOURCE_DATE_EPOCH` in Python packaging, and `-Dpython=...` equivalents when building extension modules
- disallow custom compiler wrappers or host-provided toolchains unless they are in the declared image and checksummed

### 1.8 Host and build environment hardening

- the build host only runs container execution requests; it cannot influence container internals
- use a minimal build controller with hardened runtime policies and allowlist enforcement
- disallow mounting host SSH keys, credentials, or external sockets into build containers
- ensure container runtime does not expose host filesystem metadata beyond product artifacts
- require attestation of container runtime configuration before build start

---

## SECTION 2 — Dual-Build Verification Engine

### 2.1 Engine overview

The dual-build verification engine performs two independent builds from the same declared inputs and compares artifacts at the byte level to detect tampering or nondeterministic divergence.

Engine components:
- `build orchestrator`: schedules two independent build runs in parallel on isolated workers
- `input verifier`: validates the source artifact and toolchain manifest against trusted checksums
- `build environment resolver`: provisions two separate OCI containers from distinct signed base images
- `artifact collector`: gathers final binaries, archives, containers, and package artifacts from each build
- `binary diff engine`: executes byte-level comparison using `diffoscope`, `cmp`, and deterministic section normalization
- `result analyzer`: classifies divergence as expected (deterministic variability) or suspicious tampering

### 2.2 Parallel independent builds

The pipeline runs two fully-isolated builds in parallel to ensure independence.

Step-by-step orchestration:
1. `checkout`: retrieve the trusted source bundle and verify manifest checksums
2. `prepare-build-inputs`: unpack sources and declared inputs into two isolated build workspaces
3. `provision-containers`: launch two separate OCI containers with distinct, signed compiler toolchain digests
4. `load-manifest`: inject the same build manifest and environment variable set into both containers
5. `execute-builds`: concurrently run `build.sh` or equivalent deterministic build script in both containers
6. `monitor`: track build logs, enforce container-level resource limits, and abort on any network or undeclared tool invocation
7. `collect-artifacts`: copy artifacts from `/output` directories in both containers to the verification host

### 2.3 Binary diff analysis

The verification engine compares build outputs using advanced diffing tools.

Binary diffing steps:
- normalize artifacts by stripping or canonicalizing known nondeterministic sections, such as build IDs, UUIDs, and timestamps
- compare raw bytes with `cmp` for exact equality checks on deterministic artifact classes
- use `diffoscope` to compare complex archives, containers, and metadata-rich binaries
- analyze ELF/PE/Mach-O sections, debug info, symbol tables, and resource sections for discrepancies
- compare checksums for each declared artifact and for content-level equivalence of archives and package payloads

### 2.4 Diffoscope integration

`diffoscope` is the core advanced diff engine for non-text artifacts.

Integration design:
- run `diffoscope --progress --text` on artifact pairs to generate structured reports
- configure `diffoscope` with custom comparators for ELF, JAR, WAR, Docker image layers, ZIP/JAR archives, and metadata
- supply pre-normalization hooks to remove known reproducible metadata from results
- use `diffoscope --json` and `--html` output for downstream analysis and audit reports
- classify differences into categories: metadata-only, debug-only, section order, or true code/data divergence

### 2.5 Bytecode Mutation Entropy Scoring foundation

While this stage focuses on dual-build verification, the engine must collect entropy signals for later Bytecode Mutation Entropy Scoring.

Collected signals:
- hash collision distances between independent artifact pairs
- normalized section-level variance metrics across ELF/PE/DWARF output
- build-to-build compile-time metadata entropy measures
- diffoscope divergence classification tags

### 2.6 Decision logic

- if artifacts are byte-identical after canonical normalization, mark the build as verified
- if differences are limited to accepted nondeterministic metadata and the diffoscope report confirms structural equivalence, mark the build as reproducible
- if differences appear in code, symbol, or section payloads, flag as tampering and quarantine the build artifacts
- retain the full diffoscope report and container manifests for forensic review

### 2.7 Pipeline hardening

- require two independent container images from separate build clusters or separate signing authorities to eliminate single-image compromise
- use different physical workers or execution policies for the two builds when possible
- require the build manifest to include exact checksums for both build inputs and the declared toolchain
- log each build’s container digest, start/end timestamps, and environment hash into the audit record
- enforce a post-build verification gate that rejects any artifact pair without deterministic or approved structural equivalence
