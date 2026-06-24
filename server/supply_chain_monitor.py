"""Stage 8 - Supply Chain Security & SLSA Provenance.

Reuses two existing, fully-functional engines unmodified rather than
reinventing them:
  - stage5/slsa_attestor.py: real CycloneDX SBOM generation from the live
    server/requirements.txt + frontend/package.json manifests, SLSA
    provenance predicate construction, and SLSA level determination.
  - stage7/cosign_wrapper.py: the genuine keyless-signing flow this app
    built for Stage 7 before that slot became compliance tracking - real
    Ed25519 signing, a real in-process X.509 CA minting short-lived leaf
    certificates (Fulcio stand-in), and a hash-chained local transparency
    log (Rekor stand-in). Signing/verifying here is real cryptography, just
    against a locally-run CA instead of the public Sigstore root of trust.

Honest scope: there is no compiled container image in this dev repo to scan
layer-by-layer, so the "artifact" being attested is the SBOM document itself
(its own SHA-256 digest) - the same pipeline (SBOM -> provenance -> sign ->
transparency log -> verify) a real image build would go through, just
pointed at the one real build artifact this repo actually produces.

The dependency "tree" is two levels (root -> ecosystem -> direct
dependencies from requirements.txt/package.json), not a fully resolved
transitive graph - requirements.txt has no transitive-resolution data
without shelling out to a real resolver, so this doesn't pretend to have
deeper data than it does.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from bootstrap import REPO_ROOT
from core.stage_loader import load_module

_slsa = load_module("slsa_attestor")
_cosign = load_module("cosign_wrapper")

ARTIFACTS_DIR = REPO_ROOT / "server" / "logs" / "supply_chain"
SLSA_LEVEL_TARGET = 3

# Both LocalRekorSimulator.upload_entry() (cosign_wrapper.py) and the SLSA
# transparency log append (slsa_attestor.py) do a non-atomic read-then-write
# against a shared file with no locking of their own. Two requests racing
# through a cache-cold run_supply_chain_check() at once (observed directly
# in testing - FastAPI's threadpool runs stage loaders concurrently) corrupts
# the hash chain: both read the same "previous entry," both append with the
# same previous_hash and log_index, and Rekor chain verification then fails
# for everyone. Serializing the whole check is simpler and safer than trying
# to make every underlying log append atomic individually.
_check_lock = threading.Lock()


def _build_dependencies() -> List[Dict[str, Any]]:
    """Real declared dependencies from the two manifests this app actually
    ships with - the same files server/requirements.txt and
    frontend/package.json that were pinned and verified earlier this
    session, not a synthetic fixture."""
    dependencies: List[Dict[str, Any]] = []

    requirements_path = REPO_ROOT / "server" / "requirements.txt"
    if requirements_path.exists():
        deps = _slsa.parse_requirements_txt(requirements_path)
        for component in _slsa.dependency_components(deps, "pypi"):
            dependencies.append({**component.to_cyclonedx(), "ecosystem": "pypi"})

    package_json_path = REPO_ROOT / "frontend" / "package.json"
    if package_json_path.exists():
        deps = _slsa.parse_package_json(package_json_path)
        for component in _slsa.dependency_components(deps, "npm"):
            dependencies.append({**component.to_cyclonedx(), "ecosystem": "npm"})

    return dependencies


def _flatten_dependency(raw: Dict[str, Any]) -> Dict[str, Any]:
    sha256 = next((h["content"] for h in raw.get("hashes", []) if h.get("alg") == "SHA-256"), "")
    version = raw.get("version", "")
    purl = raw.get("purl")
    return {
        "name": raw["name"],
        "version": version,
        "ecosystem": raw["ecosystem"],
        "purl": purl,
        "sha256": sha256,
        # "verified" = this dependency has a pinned version and a resolvable
        # package URL, i.e. enough metadata to actually look it up/audit -
        # not a cryptographic verification of the package contents itself.
        "verified": bool(purl) and version not in ("", "latest"),
    }


def _dependency_tree(dependencies: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_ecosystem: Dict[str, List[Dict[str, Any]]] = {}
    for dep in dependencies:
        by_ecosystem.setdefault(dep["ecosystem"], []).append({"name": dep["name"], "version": dep["version"], "verified": dep["verified"]})
    return {
        "name": "cbad-pipeline",
        "children": [
            {"name": ecosystem, "children": sorted(pkgs, key=lambda p: p["name"])}
            for ecosystem, pkgs in sorted(by_ecosystem.items())
        ],
    }


def _run_attestation(sbom: Dict[str, Any], git_commit: str) -> Dict[str, Any]:
    """Runs the real SBOM -> provenance -> sign -> transparency-log pipeline
    (stage5/slsa_attestor.py) over the SBOM document itself, since this repo
    has no compiled artifact to point it at instead."""
    output_dir = ARTIFACTS_DIR / "attestation"
    output_dir.mkdir(parents=True, exist_ok=True)

    artifact_path = output_dir / "sbom_artifact.json"
    artifact_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")

    result = _slsa.run_attestation(
        artifact_path=artifact_path,
        output_dir=output_dir,
        builder_id="cbad-supply-chain-monitor",
        build_type="https://cbad.dev/buildType/sbom-attestation",
        command=["server/supply_chain_monitor.py"],
        env_vars={"GIT_COMMIT": git_commit},
        hermetic_reproducible=True,
        two_party_attested=False,
    )
    return result


def _verify_attestation(result: Dict[str, Any]) -> Dict[str, Any]:
    """Real signature verification (stage5/slsa_attestor.verify_signature) -
    recomputes the artifact's hash and checks the Ed25519 signature against
    the public key written alongside it, exactly as cosign verify would."""
    artifact_path = Path(result["sbom_path"])
    signature_path = Path(result["sbom_signature_path"])
    key_dir = Path(result["public_key_path"]).parent
    public_key_path = Path(result["public_key_path"])
    valid = _slsa.verify_signature(artifact_path, signature_path, public_key_path)
    return {
        "valid": valid,
        "key_fingerprint": _slsa.public_key_fingerprint(public_key_path),
    }


def _cosign_style_signature_log(artifact_digest: str) -> Dict[str, Any]:
    """Drives the actual Stage 7 CosignWrapper (Fulcio+Rekor simulators) end
    to end over a fresh ephemeral keypair/OIDC identity, independent of
    stage5's own signing above - this is the "modeled after Cosign
    verification flows" half of the brief specifically, kept separate from
    the SLSA attestation signing since cosign and in-toto/SLSA signing are
    different mechanisms in real supply-chain tooling too."""
    workdir = ARTIFACTS_DIR / "cosign"
    workdir.mkdir(parents=True, exist_ok=True)
    artifact_path = workdir / "artifact.digest"
    artifact_path.write_text(artifact_digest, encoding="utf-8")

    fulcio = _cosign.LocalFulcioSimulator(workdir / "fulcio-ca")
    rekor = _cosign.LocalRekorSimulator(workdir / "rekor-log.jsonl")
    wrapper = _cosign.CosignWrapper(fulcio, rekor)
    provider = _cosign.SimulatedOIDCProvider(repository="cbad/core-sec-v1")

    bundle = wrapper.sign_blob(artifact_path, provider)
    verification = wrapper.verify_blob(artifact_path, bundle, fulcio.trusted_root_pem)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "artifact_digest": bundle.artifact_digest,
        "verified": verification.verified,
        "reason": verification.reason,
        "subject_identity": verification.subject_identity,
        "rekor_uuid": bundle.rekor_uuid,
        "rekor_log_index": bundle.rekor_log_index,
        "rekor_chain_intact": rekor.verify_chain(),
    }


def run_supply_chain_check(git_commit: str = "unknown") -> Dict[str, Any]:
    with _check_lock:
        return _run_supply_chain_check_locked(git_commit)


def _run_supply_chain_check_locked(git_commit: str) -> Dict[str, Any]:
    dependencies = [_flatten_dependency(d) for d in _build_dependencies()]
    verified_count = sum(1 for d in dependencies if d["verified"])
    sbom_completeness_pct = round(100 * verified_count / len(dependencies), 1) if dependencies else 0.0

    sbom = _slsa.build_sbom(
        root_component_name="cbad-pipeline",
        requirements_path=REPO_ROOT / "server" / "requirements.txt",
        package_json_path=REPO_ROOT / "frontend" / "package.json",
    )

    attestation = _run_attestation(sbom, git_commit)
    signature_check = _verify_attestation(attestation)
    cosign_entry = _cosign_style_signature_log(attestation["artifact_digest"])

    slsa_level = attestation["slsa_level"]
    transparency_log = _slsa.read_transparency_log(Path(attestation["transparency_log_path"]))

    attestation_status = (
        "PASSED"
        if signature_check["valid"] and cosign_entry["verified"] and cosign_entry["rekor_chain_intact"] and slsa_level >= SLSA_LEVEL_TARGET
        else "FAILED"
    )

    return {
        "source": "live_supply_chain_monitor",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "attestation_status": attestation_status,
        "slsa_level": slsa_level,
        "slsa_level_target": SLSA_LEVEL_TARGET,
        "artifact_digest": attestation["artifact_digest"],
        "sbom_completeness_pct": sbom_completeness_pct,
        "dependency_count": len(dependencies),
        "dependencies": dependencies,
        "dependency_tree": _dependency_tree(dependencies),
        "signature_log": [
            {
                "timestamp": attestation["log_entry"]["logged_at"],
                "method": "slsa_attestor (Ed25519, local transparency log)",
                "artifact_digest": attestation["artifact_digest"],
                "verified": signature_check["valid"],
                "reason": "signature matches the recomputed artifact digest" if signature_check["valid"] else "signature verification failed",
                "subject_identity": {"key_fingerprint": signature_check["key_fingerprint"]},
                "rekor_uuid": None,
                "rekor_log_index": None,
            },
            {
                "timestamp": cosign_entry["timestamp"],
                "method": "cosign_wrapper (keyless OIDC, Fulcio + Rekor simulators)",
                "artifact_digest": cosign_entry["artifact_digest"],
                "verified": cosign_entry["verified"],
                "reason": cosign_entry["reason"],
                "subject_identity": cosign_entry["subject_identity"],
                "rekor_uuid": cosign_entry["rekor_uuid"],
                "rekor_log_index": cosign_entry["rekor_log_index"],
            },
        ],
        "transparency_log_entries": len(transparency_log),
        "rekor_chain_intact": cosign_entry["rekor_chain_intact"],
    }
