#!/usr/bin/env python3
"""CBAD Stage 7 - keyless signing wrapper over OIDC federation, Fulcio, and Rekor.

Implements the keyless signing sequence (CBAD_Stage7_Sigstore_OIDC.md
section 1.2), the OIDC token requirements and per-provider claim mapping
(section 2.2-2.6), and offline verification (section 1.5).

Honest scope and stand-ins, called out explicitly:
  - OIDC providers: GitHubActionsOIDCProvider and GitLabCIOIDCProvider are
    real implementations of the documented mechanisms (GitHub's
    ACTIONS_ID_TOKEN_REQUEST_URL metadata call, GitLab's CI_JOB_JWT_V2 env
    var) and will work unmodified inside an actual CI job with the right
    permissions configured - they just can't be exercised from this
    standalone dev environment, which has neither env var set.
    AzureDevOpsOIDCProvider/AWSOIDCProvider follow the doc's own "conceptual"
    framing (section 2.5/2.6 - AWS explicitly notes raw OIDC tokens aren't
    normally available to Fulcio) and are best-effort sketches, not
    verified integrations.
  - SimulatedOIDCProvider fabricates a structurally valid, *unsigned*
    GitHub-Actions-shaped token for local development/self-test, standing
    in for a real IdP signature Fulcio would normally verify.
  - RemoteFulcioClient/RemoteRekorClient are real HTTP implementations of
    section 1.2 steps 2 and 5, written per spec but never invoked by this
    module's own tests (no live Fulcio/Rekor endpoint to call from here).
  - LocalFulcioSimulator/LocalRekorSimulator are the offline stand-ins that
    make sign/verify actually runnable end-to-end: a real, in-process X.509
    CA (via `cryptography`) mints genuine short-lived leaf certificates
    bound to OIDC claims, exactly as Fulcio does, and a hash-chained local
    JSONL ledger stands in for Rekor's Merkle transparency log (a hash
    chain proves "nothing was edited after the fact" but is not a Merkle
    inclusion proof - swap for a real Rekor client for actual non-repudiation).

Usage:
  python stage7/cosign_wrapper.py self-test
  python stage7/cosign_wrapper.py sign --artifact app.jar --provider simulated --output bundle.json
  python stage7/cosign_wrapper.py verify --artifact app.jar --bundle bundle.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import urllib.request
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple

DEFAULT_AUDIENCE = "sigstore"
FULCIO_CERT_VALIDITY = timedelta(minutes=10)  # section 1.3: "60 seconds to 15 minutes"


# ---------------------------------------------------------------------------
# OIDC identity tokens (section 2.2)
# ---------------------------------------------------------------------------

@dataclass
class OIDCIdentityToken:
    raw_jwt: str
    issuer: str
    subject: str
    audience: str
    claims: Dict[str, str]
    issued_at: str
    expires_at: str


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def decode_jwt_claims(raw_jwt: str) -> Dict[str, Any]:
    """Decodes (without verifying) a JWT's payload segment. Verifying the
    issuer's signature is Fulcio's job (section 1.3), not the requester's -
    this is only used here to surface claims for local bookkeeping/audit.
    """
    parts = raw_jwt.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT: expected three dot-separated segments")
    return json.loads(_b64url_decode(parts[1]))


class OIDCProvider(ABC):
    @abstractmethod
    def fetch_token(self, audience: str = DEFAULT_AUDIENCE) -> OIDCIdentityToken:
        """Obtain an OIDC identity token scoped to `audience` (section 2.2)."""


class GitHubActionsOIDCProvider(OIDCProvider):
    """Section 2.3: calls the GitHub Actions runner's local metadata
    endpoint named by ACTIONS_ID_TOKEN_REQUEST_URL, authenticated with
    ACTIONS_ID_TOKEN_REQUEST_TOKEN. Only works inside a job with
    `permissions: id-token: write`.
    """

    def fetch_token(self, audience: str = DEFAULT_AUDIENCE) -> OIDCIdentityToken:
        request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
        request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
        if not request_url or not request_token:
            raise RuntimeError(
                "ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN not set - this provider only works inside a "
                "GitHub Actions job with 'permissions: id-token: write'. Use --provider simulated for local testing."
            )
        url = f"{request_url}&audience={audience}" if "?" in request_url else f"{request_url}?audience={audience}"
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {request_token}"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        raw_jwt = payload["value"]
        return _token_from_jwt(raw_jwt)


class GitLabCIOIDCProvider(OIDCProvider):
    """Section 2.4: GitLab exposes the OIDC token directly as the
    CI_JOB_JWT_V2 environment variable for jobs with `id_tokens` configured.
    """

    def fetch_token(self, audience: str = DEFAULT_AUDIENCE) -> OIDCIdentityToken:
        raw_jwt = os.environ.get("CI_JOB_JWT_V2")
        if not raw_jwt:
            raise RuntimeError(
                "CI_JOB_JWT_V2 not set - this provider only works inside a GitLab CI job with an "
                "`id_tokens` block configured. Use --provider simulated for local testing."
            )
        return _token_from_jwt(raw_jwt)


class AzureDevOpsOIDCProvider(OIDCProvider):
    """Section 2.5 - best-effort sketch: Azure DevOps OIDC federation is
    pipeline/service-connection specific; this reads a token from an env
    var a pipeline step would need to populate itself (e.g. via the Azure
    DevOps REST API for service connection federation), since there is no
    single universal metadata endpoint analogous to GitHub's.
    """

    ENV_VAR = "AZURE_DEVOPS_OIDC_TOKEN"

    def fetch_token(self, audience: str = DEFAULT_AUDIENCE) -> OIDCIdentityToken:
        raw_jwt = os.environ.get(self.ENV_VAR)
        if not raw_jwt:
            raise RuntimeError(
                f"{self.ENV_VAR} not set - populate it from your pipeline's OIDC federation step. "
                "Use --provider simulated for local testing."
            )
        return _token_from_jwt(raw_jwt)


class AWSOIDCProvider(OIDCProvider):
    """Section 2.6 - best-effort sketch. The doc itself notes AWS commonly
    yields temporary AWS credentials (via AssumeRoleWithWebIdentity) rather
    than a raw OIDC token suitable for Fulcio; this reads a token from an
    env var under the assumption the caller has already obtained one from
    an AWS-hosted OIDC issuer (e.g. an EKS service account projected token).
    """

    ENV_VAR = "AWS_WEB_IDENTITY_OIDC_TOKEN"

    def fetch_token(self, audience: str = DEFAULT_AUDIENCE) -> OIDCIdentityToken:
        token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
        raw_jwt = os.environ.get(self.ENV_VAR)
        if token_file and Path(token_file).exists():
            raw_jwt = Path(token_file).read_text(encoding="utf-8").strip()
        if not raw_jwt:
            raise RuntimeError(
                f"Neither AWS_WEB_IDENTITY_TOKEN_FILE nor {self.ENV_VAR} is set/available. "
                "Use --provider simulated for local testing."
            )
        return _token_from_jwt(raw_jwt)


class SimulatedOIDCProvider(OIDCProvider):
    """Fabricates a structurally valid, unsigned GitHub-Actions-shaped
    token for local development. Stands in for a real IdP signature that
    Fulcio would verify in production.
    """

    def __init__(self, repository: str = "example-org/example-repo", ref: str = "refs/heads/main", sha: Optional[str] = None):
        self.repository = repository
        self.ref = ref
        self.sha = sha or hashlib.sha1(repository.encode("utf-8")).hexdigest()

    def fetch_token(self, audience: str = DEFAULT_AUDIENCE) -> OIDCIdentityToken:
        now = datetime.now(timezone.utc)
        claims = {
            "iss": "https://token.actions.githubusercontent.com",
            "sub": f"repo:{self.repository}:ref:{self.ref}",
            "aud": audience,
            "repository": self.repository,
            "ref": self.ref,
            "sha": self.sha,
            "iat": str(int(now.timestamp())),
            "exp": str(int((now + timedelta(minutes=5)).timestamp())),
        }
        header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        raw_jwt = f"{header_b64}.{payload_b64}."  # unsigned - simulated only
        return _token_from_jwt(raw_jwt, claims_override=claims)


def _token_from_jwt(raw_jwt: str, claims_override: Optional[Dict[str, str]] = None) -> OIDCIdentityToken:
    claims = claims_override or decode_jwt_claims(raw_jwt)
    issued_at = datetime.fromtimestamp(int(claims.get("iat", 0)), tz=timezone.utc) if claims.get("iat") else datetime.now(timezone.utc)
    expires_at = datetime.fromtimestamp(int(claims.get("exp", 0)), tz=timezone.utc) if claims.get("exp") else issued_at + timedelta(minutes=5)
    return OIDCIdentityToken(
        raw_jwt=raw_jwt,
        issuer=str(claims.get("iss", "")),
        subject=str(claims.get("sub", "")),
        audience=str(claims.get("aud", "")),
        claims={k: str(v) for k, v in claims.items()},
        issued_at=issued_at.isoformat(),
        expires_at=expires_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Fulcio client (section 1.3)
# ---------------------------------------------------------------------------

@dataclass
class FulcioCertificate:
    certificate_pem: str
    chain_pem: List[str]
    not_before: str
    not_after: str
    subject_identity: Dict[str, str]


class FulcioClient(ABC):
    @abstractmethod
    def request_certificate(self, oidc_token: OIDCIdentityToken, public_key_pem: str) -> FulcioCertificate: ...


@dataclass(frozen=True)
class TrustedIssuerPolicy:
    trusted_issuers: Tuple[str, ...] = ("https://token.actions.githubusercontent.com", "https://gitlab.com")
    accepted_audiences: Tuple[str, ...] = (DEFAULT_AUDIENCE,)


class LocalFulcioSimulator(FulcioClient):
    """Mints real short-lived X.509 leaf certificates, signed by a locally
    generated self-signed CA, binding the caller's ephemeral public key to
    OIDC identity claims - the same shape as a real Fulcio certificate
    (section 1.3), minus the production root of trust.
    """

    def __init__(self, ca_dir: Path, policy: TrustedIssuerPolicy = TrustedIssuerPolicy()):
        self.ca_dir = ca_dir
        self.policy = policy
        self._ca_cert, self._ca_key = self._load_or_create_ca()

    def _load_or_create_ca(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.x509.oid import NameOID

        self.ca_dir.mkdir(parents=True, exist_ok=True)
        cert_path = self.ca_dir / "fulcio-sim-ca.pem"
        key_path = self.ca_dir / "fulcio-sim-ca.key"

        if cert_path.exists() and key_path.exists():
            ca_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            return ca_cert, ca_key

        ca_key = ed25519.Ed25519PrivateKey.generate()
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "CBAD Local Fulcio Simulator CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CBAD"),
        ])
        now = datetime.now(timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, None)
        )
        key_path.write_bytes(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        return ca_cert, ca_key

    def request_certificate(self, oidc_token: OIDCIdentityToken, public_key_pem: str) -> FulcioCertificate:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import NameOID

        if oidc_token.issuer not in self.policy.trusted_issuers:
            raise PermissionError(f"issuer not trusted by this Fulcio policy: {oidc_token.issuer}")
        if oidc_token.audience not in self.policy.accepted_audiences:
            raise PermissionError(f"audience not accepted by this Fulcio policy: {oidc_token.audience}")

        now = datetime.now(timezone.utc)
        expires = now + FULCIO_CERT_VALIDITY
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

        san_entries = [x509.RFC822Name(oidc_token.subject[:255])] if "@" in oidc_token.subject else []
        repo_claim = oidc_token.claims.get("repository")
        san_uris = [x509.UniformResourceIdentifier(f"https://github.com/{repo_claim}")] if repo_claim else []

        leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, oidc_token.subject)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(leaf_subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(expires)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        if san_entries or san_uris:
            builder = builder.add_extension(x509.SubjectAlternativeName(san_entries + san_uris), critical=False)

        leaf_cert = builder.sign(self._ca_key, None)

        return FulcioCertificate(
            certificate_pem=leaf_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            chain_pem=[self._ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")],
            not_before=now.isoformat(),
            not_after=expires.isoformat(),
            subject_identity={"sub": oidc_token.subject, "iss": oidc_token.issuer, **oidc_token.claims},
        )

    @property
    def trusted_root_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


class RemoteFulcioClient(FulcioClient):
    """Real HTTP implementation of section 1.2 step 2/1.3, written per spec.
    Never invoked by this module's tests - no live Fulcio endpoint to call here.
    """

    def __init__(self, fulcio_url: str = "https://fulcio.sigstore.dev"):
        self.fulcio_url = fulcio_url.rstrip("/")

    def request_certificate(self, oidc_token: OIDCIdentityToken, public_key_pem: str) -> FulcioCertificate:
        body = json.dumps({
            "publicKey": {"content": base64.b64encode(public_key_pem.encode("utf-8")).decode("ascii"), "algorithm": "ed25519"},
            "credentials": {"oidcIdentityToken": oidc_token.raw_jwt},
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.fulcio_url}/api/v2/signingCert", data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        chain = payload["signedCertificateEmbeddedSct"]["chain"]["certificates"]
        return FulcioCertificate(
            certificate_pem=chain[0], chain_pem=chain[1:],
            not_before=datetime.now(timezone.utc).isoformat(),
            not_after=(datetime.now(timezone.utc) + FULCIO_CERT_VALIDITY).isoformat(),
            subject_identity={"sub": oidc_token.subject, "iss": oidc_token.issuer},
        )


# ---------------------------------------------------------------------------
# Rekor client (section 1.4) - local hash-chained stand-in + real HTTP client
# ---------------------------------------------------------------------------

@dataclass
class RekorEntry:
    uuid: str
    log_index: int
    artifact_digest: str
    certificate_pem: str
    signature_b64: str
    entry_hash: str
    previous_entry_hash: str
    logged_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RekorClientProtocol(Protocol):
    def upload_entry(self, artifact_digest: str, certificate_pem: str, signature_b64: str) -> RekorEntry: ...
    def get_entry(self, entry_uuid: str) -> Optional[RekorEntry]: ...
    def find_by_digest(self, artifact_digest: str) -> List[RekorEntry]: ...


class LocalRekorSimulator:
    """Append-only local JSONL ledger with a SHA-256 hash chain linking each
    entry to the previous one. A hash chain proves the log was not edited
    after the fact once you have the latest hash out-of-band; it is not a
    Merkle inclusion proof / signed tree head (section 1.4) - swap for a
    real Rekor client before relying on this for actual non-repudiation.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, log_path: Path):
        self.log_path = log_path

    def _read_all(self) -> List[RekorEntry]:
        if not self.log_path.exists():
            return []
        return [RekorEntry(**json.loads(line)) for line in self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def upload_entry(self, artifact_digest: str, certificate_pem: str, signature_b64: str) -> RekorEntry:
        entries = self._read_all()
        previous_hash = entries[-1].entry_hash if entries else self.GENESIS_HASH
        partial = {
            "uuid": str(uuid.uuid4()),
            "log_index": len(entries),
            "artifact_digest": artifact_digest,
            "certificate_pem": certificate_pem,
            "signature_b64": signature_b64,
            "previous_entry_hash": previous_hash,
            "logged_at": datetime.now(timezone.utc).isoformat(),
        }
        entry_hash = hashlib.sha256(json.dumps(partial, sort_keys=True).encode("utf-8")).hexdigest()
        entry = RekorEntry(entry_hash=entry_hash, **partial)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict()) + "\n")
        return entry

    def get_entry(self, entry_uuid: str) -> Optional[RekorEntry]:
        for entry in self._read_all():
            if entry.uuid == entry_uuid:
                return entry
        return None

    def find_by_digest(self, artifact_digest: str) -> List[RekorEntry]:
        return [e for e in self._read_all() if e.artifact_digest == artifact_digest]

    def verify_chain(self) -> bool:
        previous_hash = self.GENESIS_HASH
        for entry in self._read_all():
            if entry.previous_entry_hash != previous_hash:
                return False
            partial = {k: v for k, v in entry.to_dict().items() if k != "entry_hash"}
            recomputed = hashlib.sha256(json.dumps(partial, sort_keys=True).encode("utf-8")).hexdigest()
            if recomputed != entry.entry_hash:
                return False
            previous_hash = entry.entry_hash
        return True


class RemoteRekorClient:
    """Real HTTP implementation of section 1.4's append flow, written per
    spec. Never invoked by this module's tests - no live Rekor endpoint here.
    """

    def __init__(self, rekor_url: str = "https://rekor.sigstore.dev"):
        self.rekor_url = rekor_url.rstrip("/")

    def upload_entry(self, artifact_digest: str, certificate_pem: str, signature_b64: str) -> RekorEntry:
        body = json.dumps({
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": artifact_digest}},
                "signature": {"content": signature_b64, "publicKey": {"content": base64.b64encode(certificate_pem.encode()).decode()}},
            },
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.rekor_url}/api/v1/log/entries", data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        entry_uuid = next(iter(payload))
        body_data = payload[entry_uuid]
        return RekorEntry(
            uuid=entry_uuid, log_index=body_data.get("logIndex", -1), artifact_digest=artifact_digest,
            certificate_pem=certificate_pem, signature_b64=signature_b64,
            entry_hash="", previous_entry_hash="", logged_at=datetime.now(timezone.utc).isoformat(),
        )

    def get_entry(self, entry_uuid: str) -> Optional[RekorEntry]:
        req = urllib.request.Request(f"{self.rekor_url}/api/v1/log/entries/{entry_uuid}")
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        if entry_uuid not in payload:
            return None
        body_data = payload[entry_uuid]
        return RekorEntry(
            uuid=entry_uuid, log_index=body_data.get("logIndex", -1), artifact_digest="",
            certificate_pem="", signature_b64="", entry_hash="", previous_entry_hash="",
            logged_at=datetime.now(timezone.utc).isoformat(),
        )

    def find_by_digest(self, artifact_digest: str) -> List[RekorEntry]:
        raise NotImplementedError("Use the Rekor search API (POST /api/v1/index/retrieve) for digest lookups.")


# ---------------------------------------------------------------------------
# Cosign wrapper orchestration (section 1.2 / 1.5)
# ---------------------------------------------------------------------------

@dataclass
class SigningBundle:
    artifact_digest: str
    certificate_pem: str
    chain_pem: List[str]
    signature_b64: str
    rekor_uuid: str
    rekor_log_index: int
    subject_identity: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    verified: bool
    reason: str
    subject_identity: Dict[str, str] = field(default_factory=dict)


def hash_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CosignWrapper:
    def __init__(self, fulcio_client: FulcioClient, rekor_client: LocalRekorSimulator, allowed_subjects: Optional[Tuple[str, ...]] = None):
        self.fulcio_client = fulcio_client
        self.rekor_client = rekor_client
        self.allowed_subjects = allowed_subjects

    def sign_blob(self, artifact_path: Path, oidc_provider: OIDCProvider, audience: str = DEFAULT_AUDIENCE) -> SigningBundle:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        # step 1-2: ephemeral keypair + OIDC token (section 1.2)
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        oidc_token = oidc_provider.fetch_token(audience)

        # step 3: Fulcio issues a short-lived certificate bound to the identity
        certificate = self.fulcio_client.request_certificate(oidc_token, public_key_pem)

        # step 4: sign the artifact digest with the ephemeral private key
        artifact_digest = hash_file_sha256(artifact_path)
        signature = private_key.sign(bytes.fromhex(artifact_digest))
        signature_b64 = base64.b64encode(signature).decode("ascii")

        # step 5: upload signature + certificate to Rekor
        rekor_entry = self.rekor_client.upload_entry(artifact_digest, certificate.certificate_pem, signature_b64)

        return SigningBundle(
            artifact_digest=artifact_digest,
            certificate_pem=certificate.certificate_pem,
            chain_pem=certificate.chain_pem,
            signature_b64=signature_b64,
            rekor_uuid=rekor_entry.uuid,
            rekor_log_index=rekor_entry.log_index,
            subject_identity=certificate.subject_identity,
        )

    def verify_blob(self, artifact_path: Path, bundle: SigningBundle, trusted_root_pem: str) -> VerificationResult:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature

        # 1. recompute and compare the artifact digest
        actual_digest = hash_file_sha256(artifact_path)
        if actual_digest != bundle.artifact_digest:
            return VerificationResult(False, "artifact digest does not match the signed digest in the bundle")

        # 2. verify the certificate was issued by the trusted root
        leaf_cert = x509.load_pem_x509_certificate(bundle.certificate_pem.encode("utf-8"))
        root_cert = x509.load_pem_x509_certificate(trusted_root_pem.encode("utf-8"))
        try:
            root_cert.public_key().verify(leaf_cert.signature, leaf_cert.tbs_certificate_bytes)
        except InvalidSignature:
            return VerificationResult(False, "certificate was not signed by the trusted root")

        # 3. verify the certificate validity window covers now
        now = datetime.now(timezone.utc)
        not_before = leaf_cert.not_valid_before_utc
        not_after = leaf_cert.not_valid_after_utc
        if not (not_before <= now <= not_after):
            return VerificationResult(False, f"certificate is outside its validity window ({not_before} - {not_after})")

        # 4. verify the signature over the artifact digest using the cert's public key
        try:
            leaf_cert.public_key().verify(base64.b64decode(bundle.signature_b64), bytes.fromhex(actual_digest))
        except InvalidSignature:
            return VerificationResult(False, "signature does not verify against the certificate's public key")

        # 5. verify the Rekor entry exists, matches, and the local hash chain is intact
        rekor_entry = self.rekor_client.get_entry(bundle.rekor_uuid)
        if rekor_entry is None:
            return VerificationResult(False, f"no Rekor entry found for uuid {bundle.rekor_uuid}")
        if rekor_entry.artifact_digest != bundle.artifact_digest:
            return VerificationResult(False, "Rekor entry digest does not match the bundle")
        if not self.rekor_client.verify_chain():
            return VerificationResult(False, "local Rekor hash chain failed integrity verification")

        # 6. policy: identity allowlist (section 2.9)
        if self.allowed_subjects is not None and bundle.subject_identity.get("sub") not in self.allowed_subjects:
            return VerificationResult(False, f"signer identity not in allowlist: {bundle.subject_identity.get('sub')}")

        return VerificationResult(True, "signature, certificate chain, and Rekor entry all verified", bundle.subject_identity)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

PROVIDERS: Dict[str, type] = {
    "github": GitHubActionsOIDCProvider,
    "gitlab": GitLabCIOIDCProvider,
    "azure": AzureDevOpsOIDCProvider,
    "aws": AWSOIDCProvider,
    "simulated": SimulatedOIDCProvider,
}


def run_self_test() -> Dict[str, Any]:
    import shutil
    import tempfile

    workdir = Path(tempfile.mkdtemp(prefix="cbad-stage7-"))
    try:
        artifact_path = workdir / "app.jar"
        artifact_path.write_bytes(b"FAKE-ARTIFACT-BYTES-FOR-SELF-TEST")

        fulcio = LocalFulcioSimulator(workdir / "fulcio-ca")
        rekor = LocalRekorSimulator(workdir / "rekor-log.jsonl")
        wrapper = CosignWrapper(fulcio, rekor, allowed_subjects=("repo:example-org/example-repo:ref:refs/heads/main",))

        provider = SimulatedOIDCProvider(repository="example-org/example-repo")
        bundle = wrapper.sign_blob(artifact_path, provider)

        valid = wrapper.verify_blob(artifact_path, bundle, fulcio.trusted_root_pem)

        # tamper test: mutate the artifact after signing, verification must fail
        original = artifact_path.read_bytes()
        artifact_path.write_bytes(original + b"tampered")
        tampered = wrapper.verify_blob(artifact_path, bundle, fulcio.trusted_root_pem)
        artifact_path.write_bytes(original)

        # untrusted issuer test: Fulcio must reject an unrecognized issuer
        rogue_provider = SimulatedOIDCProvider(repository="attacker/repo")
        rogue_provider.fetch_token = lambda audience=DEFAULT_AUDIENCE: OIDCIdentityToken(  # type: ignore[method-assign]
            raw_jwt="x.y.z", issuer="https://evil.example.com", subject="attacker",
            audience=audience, claims={}, issued_at=datetime.now(timezone.utc).isoformat(),
            expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        )
        untrusted_issuer_rejected = False
        try:
            wrapper.sign_blob(artifact_path, rogue_provider)
        except PermissionError:
            untrusted_issuer_rejected = True

        return {
            "sign_succeeded": bool(bundle.rekor_uuid),
            "verify_valid_artifact": asdict(valid),
            "verify_tampered_artifact_rejected": not tampered.verified,
            "untrusted_issuer_rejected": untrusted_issuer_rejected,
            "rekor_chain_intact": rekor.verify_chain(),
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _cmd_sign(args: argparse.Namespace) -> int:
    provider_cls = PROVIDERS[args.provider]
    provider = provider_cls() if args.provider != "simulated" else SimulatedOIDCProvider(repository=args.repository)
    fulcio = LocalFulcioSimulator(Path(args.ca_dir))
    rekor = LocalRekorSimulator(Path(args.rekor_log))
    wrapper = CosignWrapper(fulcio, rekor)

    bundle = wrapper.sign_blob(Path(args.artifact), provider, audience=args.audience)
    output_text = json.dumps(bundle.to_dict(), indent=2)
    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Wrote signing bundle to {args.output}")
    else:
        print(output_text)
    print(f"trusted_root_pem path (needed for verify): {Path(args.ca_dir) / 'fulcio-sim-ca.pem'}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    bundle_payload = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    bundle = SigningBundle(**bundle_payload)
    fulcio = LocalFulcioSimulator(Path(args.ca_dir))
    rekor = LocalRekorSimulator(Path(args.rekor_log))
    wrapper = CosignWrapper(fulcio, rekor)
    result = wrapper.verify_blob(Path(args.artifact), bundle, fulcio.trusted_root_pem)
    print(json.dumps(asdict(result), indent=2))
    return 0 if result.verified else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 7 keyless signing wrapper")
    subparsers = parser.add_subparsers(dest="mode")

    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("--artifact", required=True)
    sign_parser.add_argument("--provider", choices=list(PROVIDERS), default="simulated")
    sign_parser.add_argument("--repository", default="example-org/example-repo")
    sign_parser.add_argument("--audience", default=DEFAULT_AUDIENCE)
    sign_parser.add_argument("--ca-dir", default=str(Path(__file__).resolve().parent / "fulcio_sim_artifacts"))
    sign_parser.add_argument("--rekor-log", default=str(Path(__file__).resolve().parent / "rekor_sim_artifacts" / "log.jsonl"))
    sign_parser.add_argument("--output")
    sign_parser.set_defaults(func=_cmd_sign)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--artifact", required=True)
    verify_parser.add_argument("--bundle", required=True)
    verify_parser.add_argument("--ca-dir", default=str(Path(__file__).resolve().parent / "fulcio_sim_artifacts"))
    verify_parser.add_argument("--rekor-log", default=str(Path(__file__).resolve().parent / "rekor_sim_artifacts" / "log.jsonl"))
    verify_parser.set_defaults(func=_cmd_verify)

    subparsers.add_parser("self-test")

    args = parser.parse_args()
    if args.mode == "self-test":
        print(json.dumps(run_self_test(), indent=2))
        return 0
    if not args.mode:
        parser.error("Provide a subcommand: sign | verify | self-test")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
