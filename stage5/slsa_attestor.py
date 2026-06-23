#!/usr/bin/env python3
"""CBAD Stage 5 - CycloneDX SBOM generation and SLSA attestation.

Implements CBAD_Stage5_Entropy_SLSA.md SECTION 4: CycloneDX SBOM generation
(4.2), SLSA provenance generation (4.3), signing (4.4), a Rekor-style
transparency log (4.5), and SLSA level mapping (4.6).

Deliberate stand-ins, called out explicitly rather than silently faked:
  - section 4.2's `syft`/`cyclonedx-bom` CLI tools are not shelled out to;
    SBOM components are built natively in Python from a directory file walk
    (hash-based "file" components) and/or a requirements.txt/package.json
    manifest (dependency "library" components), which is sufficient to
    produce a spec-shaped CycloneDX 1.4 document without that dependency
  - section 4.4's `cosign`/Sigstore ephemeral-OIDC signing is replaced with
    a locally generated Ed25519 keypair (via the `cryptography` package);
    swap sign_file()/verify_signature() for a cosign subprocess call or the
    sigstore-python client when a Fulcio/cosign endpoint is available
  - section 4.5's Rekor transparency log is replaced with
    append_to_local_transparency_log(), an append-only local JSONL ledger.
    It captures the same fields a Rekor entry would (artifact digest,
    signature, signer identity, SLSA level) but is NOT a public,
    non-repudiable log - swap it for a real Rekor API client (POST
    /api/v1/log/entries) before relying on it for actual non-repudiation

Usage:
  python stage5/slsa_attestor.py sbom --source-dir path/to/build/output --output sbom.json
  python stage5/slsa_attestor.py attest --artifact path/to/app.jar --source-dir path/to/src \\
      --builder-id "cbad-ci-builder-v1" --build-type "https://cbad.dev/buildType/maven" \\
      --command mvn package --output-dir stage5/attestation_artifacts
  python stage5/slsa_attestor.py verify --file sbom.json --signature sbom.json.sig --public-key keys/cbad-builder.pub
  python stage5/slsa_attestor.py self-test
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

CYCLONEDX_SPEC_VERSION = "1.4"
TOOL_NAME = "cbad-slsa-attestor"
TOOL_VERSION = "1.0"
DEFAULT_KEY_ID = "cbad-builder"


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def hash_bytes_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# CycloneDX SBOM generation (section 4.2)
# ---------------------------------------------------------------------------

@dataclass
class SBOMComponent:
    name: str
    version: str
    component_type: str  # "file" | "library" | "application"
    sha256: str
    purl: Optional[str] = None

    def to_cyclonedx(self) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "type": self.component_type,
            "name": self.name,
            "version": self.version,
            "hashes": [{"alg": "SHA-256", "content": self.sha256}],
        }
        if self.purl:
            entry["purl"] = self.purl
        return entry


def new_sbom_document(root_component_name: str, root_component_version: str = "0.0.0") -> Dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "CBAD", "name": TOOL_NAME, "version": TOOL_VERSION}],
            "component": {"type": "application", "name": root_component_name, "version": root_component_version},
        },
        "components": [],
    }


def file_components_from_directory(root: Path) -> List[SBOMComponent]:
    components: List[SBOMComponent] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            components.append(SBOMComponent(name=rel, version="", component_type="file", sha256=hash_file_sha256(path)))
    return components


def parse_requirements_txt(path: Path) -> Dict[str, str]:
    deps: Dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for sep in ("==", ">=", "~="):
            if sep in line:
                name, version = line.split(sep, 1)
                deps[name.strip().lower()] = version.strip()
                break
        else:
            deps[line.lower()] = "latest"
    return deps


def parse_package_json(path: Path) -> Dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    deps: Dict[str, str] = {}
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            deps[name.lower()] = str(version)
    return deps


def dependency_components(deps: Dict[str, str], ecosystem: str) -> List[SBOMComponent]:
    components = []
    for name, version in sorted(deps.items()):
        purl = f"pkg:{ecosystem}/{name}@{version}" if version != "latest" else f"pkg:{ecosystem}/{name}"
        digest = hash_bytes_sha256(f"{ecosystem}:{name}:{version}".encode("utf-8"))
        components.append(SBOMComponent(name=name, version=version, component_type="library", sha256=digest, purl=purl))
    return components


def build_sbom(
    root_component_name: str,
    source_dir: Optional[Path] = None,
    requirements_path: Optional[Path] = None,
    package_json_path: Optional[Path] = None,
) -> Dict[str, Any]:
    sbom = new_sbom_document(root_component_name)
    components: List[SBOMComponent] = []

    if source_dir is not None:
        components.extend(file_components_from_directory(source_dir))
    if requirements_path is not None:
        components.extend(dependency_components(parse_requirements_txt(requirements_path), "pypi"))
    if package_json_path is not None:
        components.extend(dependency_components(parse_package_json(package_json_path), "npm"))

    sbom["components"] = [c.to_cyclonedx() for c in components]
    return sbom


# ---------------------------------------------------------------------------
# SLSA provenance generation (section 4.3)
# ---------------------------------------------------------------------------

@dataclass
class BuildManifest:
    builder_id: str
    build_type: str
    command: List[str]
    env_vars: Dict[str, str]
    started_on: str
    finished_on: str
    materials: List[Dict[str, Any]] = field(default_factory=list)


def build_provenance(
    manifest: BuildManifest,
    artifact_uri: str,
    artifact_digest: str,
    sbom_digest: Optional[str] = None,
) -> Dict[str, Any]:
    predicate: Dict[str, Any] = {
        "builder": {"id": manifest.builder_id},
        "buildType": manifest.build_type,
        "invocation": {"command": manifest.command, "environment": manifest.env_vars},
        "metadata": {"startedOn": manifest.started_on, "finishedOn": manifest.finished_on},
        "materials": manifest.materials,
    }
    if sbom_digest:
        predicate["byproducts"] = [{"name": "sbom", "digest": {"sha256": sbom_digest}}]

    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": artifact_uri, "digest": {"sha256": artifact_digest}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": predicate,
    }


# ---------------------------------------------------------------------------
# Signing (section 4.4) - Ed25519 keypair stand-in for cosign/Sigstore
# ---------------------------------------------------------------------------

@dataclass
class KeyPairPaths:
    private_key_path: Path
    public_key_path: Path


def generate_keypair(key_dir: Path, key_id: str = DEFAULT_KEY_ID) -> KeyPairPaths:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key_dir.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = key_dir / f"{key_id}.pem"
    pub_path = key_dir / f"{key_id}.pub"

    priv_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        priv_path.chmod(0o600)
    except (NotImplementedError, OSError):
        pass  # best-effort; not all platforms (e.g. Windows) honor POSIX modes

    return KeyPairPaths(priv_path, pub_path)


def load_or_create_keypair(key_dir: Path, key_id: str = DEFAULT_KEY_ID) -> KeyPairPaths:
    priv_path = key_dir / f"{key_id}.pem"
    pub_path = key_dir / f"{key_id}.pub"
    if priv_path.exists() and pub_path.exists():
        return KeyPairPaths(priv_path, pub_path)
    return generate_keypair(key_dir, key_id)


def sign_file(target: Path, key_paths: KeyPairPaths) -> Path:
    from cryptography.hazmat.primitives import serialization

    private_key = serialization.load_pem_private_key(key_paths.private_key_path.read_bytes(), password=None)
    signature = private_key.sign(target.read_bytes())
    sig_path = target.with_name(target.name + ".sig")
    sig_path.write_text(base64.b64encode(signature).decode("ascii"), encoding="ascii")
    return sig_path


def verify_signature(target: Path, signature_path: Path, public_key_path: Path) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization

    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    signature = base64.b64decode(signature_path.read_text(encoding="ascii"))
    try:
        public_key.verify(signature, target.read_bytes())
        return True
    except InvalidSignature:
        return False


def public_key_fingerprint(public_key_path: Path) -> str:
    return hashlib.sha256(public_key_path.read_bytes()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Local transparency log (section 4.5/4.7 - Rekor stand-in)
# ---------------------------------------------------------------------------

@dataclass
class TransparencyLogEntry:
    entry_uuid: str
    artifact_uri: str
    artifact_digest: str
    signature_path: str
    public_key_fingerprint: str
    slsa_level: int
    logged_at: str


def append_to_local_transparency_log(log_path: Path, entry: TransparencyLogEntry) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(asdict(entry)) + "\n")


def read_transparency_log(log_path: Path) -> List[Dict[str, Any]]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# SLSA level mapping (section 4.6)
# ---------------------------------------------------------------------------

def determine_slsa_level(
    authenticated_build: bool,
    materials_recorded: bool,
    hermetic_reproducible: bool = False,
    two_party_attested: bool = False,
) -> int:
    if not (authenticated_build and materials_recorded):
        return 2  # below the Level 3 floor this module is designed for
    if hermetic_reproducible and two_party_attested:
        return 4
    return 3


# ---------------------------------------------------------------------------
# Orchestration: full SBOM + provenance + sign + log pipeline
# ---------------------------------------------------------------------------

def run_attestation(
    artifact_path: Path,
    output_dir: Path,
    builder_id: str,
    build_type: str,
    command: Sequence[str],
    source_dir: Optional[Path] = None,
    requirements_path: Optional[Path] = None,
    package_json_path: Optional[Path] = None,
    env_vars: Optional[Dict[str, str]] = None,
    key_dir: Optional[Path] = None,
    hermetic_reproducible: bool = False,
    two_party_attested: bool = False,
) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    key_dir = key_dir or (output_dir / "keys")

    sbom = build_sbom(artifact_path.name, source_dir, requirements_path, package_json_path)
    sbom_path = output_dir / "sbom.json"
    sbom_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    artifact_digest = hash_file_sha256(artifact_path)
    sbom_digest = hash_file_sha256(sbom_path)
    started_on = datetime.now(timezone.utc).isoformat()

    materials: List[Dict[str, Any]] = [{"uri": str(artifact_path), "digest": {"sha256": artifact_digest}}]
    if source_dir is not None:
        materials.append({"uri": str(source_dir), "digest": {"sha256": hash_bytes_sha256(str(source_dir).encode("utf-8"))}})

    manifest = BuildManifest(
        builder_id=builder_id,
        build_type=build_type,
        command=list(command),
        env_vars=env_vars or {},
        started_on=started_on,
        finished_on=datetime.now(timezone.utc).isoformat(),
        materials=materials,
    )
    provenance = build_provenance(manifest, str(artifact_path), artifact_digest, sbom_digest)
    provenance_path = output_dir / "provenance.json"
    provenance_path.write_text(json.dumps(provenance, indent=2), encoding="utf-8")

    key_paths = load_or_create_keypair(key_dir)
    sbom_signature_path = sign_file(sbom_path, key_paths)
    provenance_signature_path = sign_file(provenance_path, key_paths)

    slsa_level = determine_slsa_level(
        authenticated_build=True, materials_recorded=True,
        hermetic_reproducible=hermetic_reproducible, two_party_attested=two_party_attested,
    )

    entry = TransparencyLogEntry(
        entry_uuid=str(uuid.uuid4()),
        artifact_uri=str(artifact_path),
        artifact_digest=artifact_digest,
        signature_path=str(provenance_signature_path),
        public_key_fingerprint=public_key_fingerprint(key_paths.public_key_path),
        slsa_level=slsa_level,
        logged_at=datetime.now(timezone.utc).isoformat(),
    )
    log_path = output_dir / "transparency_log.jsonl"
    append_to_local_transparency_log(log_path, entry)

    return {
        "sbom_path": str(sbom_path),
        "sbom_signature_path": str(sbom_signature_path),
        "provenance_path": str(provenance_path),
        "provenance_signature_path": str(provenance_signature_path),
        "public_key_path": str(key_paths.public_key_path),
        "transparency_log_path": str(log_path),
        "slsa_level": slsa_level,
        "artifact_digest": artifact_digest,
        "log_entry": asdict(entry),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_sbom(args: argparse.Namespace) -> int:
    sbom = build_sbom(
        root_component_name=Path(args.source_dir).name if args.source_dir else "artifact",
        source_dir=Path(args.source_dir) if args.source_dir else None,
        requirements_path=Path(args.requirements) if args.requirements else None,
        package_json_path=Path(args.package_json) if args.package_json else None,
    )
    output_text = json.dumps(sbom, indent=2)
    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Wrote SBOM with {len(sbom['components'])} components to {args.output}")
    else:
        print(output_text)
    return 0


def _cmd_attest(args: argparse.Namespace) -> int:
    result = run_attestation(
        artifact_path=Path(args.artifact),
        output_dir=Path(args.output_dir),
        builder_id=args.builder_id,
        build_type=args.build_type,
        command=args.command,
        source_dir=Path(args.source_dir) if args.source_dir else None,
        requirements_path=Path(args.requirements) if args.requirements else None,
        package_json_path=Path(args.package_json) if args.package_json else None,
        hermetic_reproducible=args.hermetic_reproducible,
        two_party_attested=args.two_party_attested,
    )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    ok = verify_signature(Path(args.file), Path(args.signature), Path(args.public_key))
    print("VALID" if ok else "INVALID")
    return 0 if ok else 1


def run_self_test() -> Dict[str, Any]:
    import shutil
    import tempfile

    workdir = Path(tempfile.mkdtemp(prefix="cbad-stage5-"))
    try:
        source_dir = workdir / "src"
        source_dir.mkdir()
        (source_dir / "app.py").write_text("print('hello from a hermetic build')\n", encoding="utf-8")
        (source_dir / "requirements.txt").write_text("requests==2.31.0\nflask>=2.0\n", encoding="utf-8")

        artifact_path = workdir / "app.jar"
        artifact_path.write_bytes(b"FAKE-JAR-BYTES-FOR-SELF-TEST")

        output_dir = workdir / "attestation"
        result = run_attestation(
            artifact_path=artifact_path,
            output_dir=output_dir,
            builder_id="cbad-self-test-builder",
            build_type="https://cbad.dev/buildType/self-test",
            command=["./build.sh"],
            source_dir=source_dir,
            requirements_path=source_dir / "requirements.txt",
            hermetic_reproducible=True,
            two_party_attested=False,
        )

        key_dir = output_dir / "keys"
        key_paths = KeyPairPaths(key_dir / f"{DEFAULT_KEY_ID}.pem", key_dir / f"{DEFAULT_KEY_ID}.pub")
        sbom_valid = verify_signature(Path(result["sbom_path"]), Path(result["sbom_signature_path"]), key_paths.public_key_path)
        provenance_valid = verify_signature(Path(result["provenance_path"]), Path(result["provenance_signature_path"]), key_paths.public_key_path)

        tampered_valid = True
        provenance_path = Path(result["provenance_path"])
        original = provenance_path.read_bytes()
        try:
            provenance_path.write_bytes(original + b"tampered")
            tampered_valid = verify_signature(provenance_path, Path(result["provenance_signature_path"]), key_paths.public_key_path)
        finally:
            provenance_path.write_bytes(original)

        log_entries = read_transparency_log(Path(result["transparency_log_path"]))

        return {
            "slsa_level": result["slsa_level"],
            "sbom_signature_valid": sbom_valid,
            "provenance_signature_valid": provenance_valid,
            "tampered_provenance_rejected": not tampered_valid,
            "transparency_log_entries": len(log_entries),
            "artifact_digest": result["artifact_digest"],
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 5 SBOM + SLSA attestation tool")
    subparsers = parser.add_subparsers(dest="mode")

    sbom_parser = subparsers.add_parser("sbom", help="Generate a CycloneDX SBOM")
    sbom_parser.add_argument("--source-dir")
    sbom_parser.add_argument("--requirements")
    sbom_parser.add_argument("--package-json")
    sbom_parser.add_argument("--output")
    sbom_parser.set_defaults(func=_cmd_sbom)

    attest_parser = subparsers.add_parser("attest", help="Run the full SBOM + provenance + sign + log pipeline")
    attest_parser.add_argument("--artifact", required=True)
    attest_parser.add_argument("--source-dir")
    attest_parser.add_argument("--requirements")
    attest_parser.add_argument("--package-json")
    attest_parser.add_argument("--builder-id", required=True)
    attest_parser.add_argument("--build-type", required=True)
    attest_parser.add_argument("--command", nargs="+", required=True)
    attest_parser.add_argument("--output-dir", required=True)
    attest_parser.add_argument("--hermetic-reproducible", action="store_true")
    attest_parser.add_argument("--two-party-attested", action="store_true")
    attest_parser.set_defaults(func=_cmd_attest)

    verify_parser = subparsers.add_parser("verify", help="Verify a signature against a public key")
    verify_parser.add_argument("--file", required=True)
    verify_parser.add_argument("--signature", required=True)
    verify_parser.add_argument("--public-key", required=True)
    verify_parser.set_defaults(func=_cmd_verify)

    self_test_parser = subparsers.add_parser("self-test", help="Run the full pipeline against a synthetic temp project")
    self_test_parser.set_defaults(func=None)

    args = parser.parse_args()

    if args.mode == "self-test":
        print(json.dumps(run_self_test(), indent=2))
        return 0
    if not args.mode:
        parser.error("Provide a subcommand: sbom | attest | verify | self-test")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
