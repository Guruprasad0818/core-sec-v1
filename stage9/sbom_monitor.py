#!/usr/bin/env python3
"""CBAD Stage 9 - continuous SBOM lifecycle monitor and vulnerability watcher.

Implements CBAD_Stage9_SBOM_CVE_Watcher.md SECTION 1: SBOM normalization
(1.4) for CycloneDX (compatible with stage5/slsa_attestor.py's output) and
SPDX 2.x, live vulnerability feed polling against the real public OSV and
GHSA APIs (1.5), and the exposure scoring engine (1.6).

This module makes genuine outbound HTTPS calls to https://api.osv.dev and
https://api.github.com/advisories - both public, unauthenticated-by-default
APIs - rather than simulating them, because they were reachable and
verified to return real vulnerability data while building this module.
GHSA's REST search (`?affects=<name>`) matches by package name only across
all ecosystems, so this module filters results client-side by ecosystem and
evaluates GHSA's `vulnerable_version_range` with `packaging.specifiers`
(works for PEP 440-shaped ranges - npm/pypi-style; Maven/Go pseudo-versions
that don't parse as PEP 440 are flagged `needs_review` rather than silently
dropped, since a false negative is worse than a false positive here). OSV's
`/v1/query` does its own server-side version matching, so no client-side
range evaluation is needed for that feed.

If neither feed is reachable (offline dev, restrictive network egress),
LocalFeedSimulator provides a deterministic canned result for self-testing.

Usage:
  python stage9/sbom_monitor.py scan --sbom sbom.json --output findings.jsonl
  python stage9/sbom_monitor.py self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

OSV_API_URL = "https://api.osv.dev/v1/query"
GHSA_API_URL = "https://api.github.com/advisories"

# canonical ecosystem (section 1.4) -> OSV ecosystem name
OSV_ECOSYSTEM_MAP: Dict[str, str] = {
    "npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go",
    "apk": "Alpine", "deb": "Debian", "rpm": "Rpm",
}
# canonical ecosystem -> GHSA ecosystem name
GHSA_ECOSYSTEM_MAP: Dict[str, str] = {
    "npm": "npm", "pypi": "pip", "maven": "maven", "golang": "go",
    "rubygems": "rubygems", "nuget": "nuget",
}

SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 1.0, "high": 0.8, "moderate": 0.5, "medium": 0.5, "low": 0.25, "unknown": 0.3,
}


# ---------------------------------------------------------------------------
# Canonical SBOM material model (section 1.4)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Material:
    material_id: str
    ecosystem: str
    name: str
    version: str
    purl: Optional[str] = None
    sha256: Optional[str] = None
    source_workflow: Optional[str] = None
    cluster: Optional[str] = None
    namespace: Optional[str] = None
    pod: Optional[str] = None
    container_name: Optional[str] = None
    image_digest: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _material_id(purl: Optional[str], ecosystem: str, name: str, version: str) -> str:
    seed = purl or f"{ecosystem}:{name}:{version}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


PURL_ECOSYSTEM_MAP: Dict[str, str] = {
    "npm": "npm", "pypi": "pypi", "maven": "maven", "golang": "golang",
    "apk": "apk", "deb": "deb", "rpm": "rpm", "oci": "oci-image",
}


def _ecosystem_from_purl(purl: str) -> str:
    # purl shape: pkg:<type>/<namespace>/<name>@<version>
    scheme = purl.split(":", 1)[-1].split("/", 1)[0] if purl.startswith("pkg:") else ""
    return PURL_ECOSYSTEM_MAP.get(scheme, scheme or "unknown")


def parse_cyclonedx(sbom: Dict[str, Any], provenance: Optional[Dict[str, str]] = None) -> List[Material]:
    provenance = provenance or {}
    materials: List[Material] = []
    for component in sbom.get("components", []):
        purl = component.get("purl")
        ecosystem = _ecosystem_from_purl(purl) if purl else "unknown"
        sha256 = next((h.get("content") for h in component.get("hashes", []) if h.get("alg") == "SHA-256"), None)
        materials.append(Material(
            material_id=_material_id(purl, ecosystem, component.get("name", ""), component.get("version", "")),
            ecosystem=ecosystem, name=component.get("name", ""), version=component.get("version", ""),
            purl=purl, sha256=sha256, **provenance,
        ))
    return materials


def parse_spdx(sbom: Dict[str, Any], provenance: Optional[Dict[str, str]] = None) -> List[Material]:
    provenance = provenance or {}
    materials: List[Material] = []
    for package in sbom.get("packages", []):
        purl = next(
            (ref.get("referenceLocator") for ref in package.get("externalRefs", []) if ref.get("referenceType") == "purl"),
            None,
        )
        ecosystem = _ecosystem_from_purl(purl) if purl else "unknown"
        sha256 = next((c.get("checksumValue") for c in package.get("checksums", []) if c.get("algorithm") == "SHA256"), None)
        name = package.get("name", "")
        version = package.get("versionInfo", "")
        materials.append(Material(
            material_id=_material_id(purl, ecosystem, name, version),
            ecosystem=ecosystem, name=name, version=version, purl=purl, sha256=sha256, **provenance,
        ))
    return materials


def parse_sbom(sbom: Dict[str, Any], provenance: Optional[Dict[str, str]] = None) -> List[Material]:
    if sbom.get("bomFormat") == "CycloneDX" or "components" in sbom:
        return parse_cyclonedx(sbom, provenance)
    if "spdxVersion" in sbom or "packages" in sbom:
        return parse_spdx(sbom, provenance)
    raise ValueError("unrecognized SBOM format: expected CycloneDX ('components') or SPDX ('packages')")


# ---------------------------------------------------------------------------
# Vulnerability record model (section 1.5)
# ---------------------------------------------------------------------------

@dataclass
class VulnerabilityRecord:
    vuln_id: str
    source: str  # osv | ghsa | local
    ecosystem: str
    package_name: str
    severity: str  # critical | high | moderate | low | unknown
    summary: str
    published_at: Optional[str] = None
    references: List[str] = field(default_factory=list)
    needs_review: bool = False  # set when a version range could not be evaluated with confidence

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VulnerabilityFeedClient(ABC):
    name: str

    @abstractmethod
    def query(self, ecosystem: str, package_name: str, version: str) -> List[VulnerabilityRecord]: ...


class OSVFeedClient(VulnerabilityFeedClient):
    name = "osv"

    def __init__(self, api_url: str = OSV_API_URL, timeout: float = 10.0):
        self.api_url = api_url
        self.timeout = timeout

    def query(self, ecosystem: str, package_name: str, version: str) -> List[VulnerabilityRecord]:
        osv_ecosystem = OSV_ECOSYSTEM_MAP.get(ecosystem)
        if osv_ecosystem is None or not package_name or not version:
            return []
        body = json.dumps({"package": {"name": package_name, "ecosystem": osv_ecosystem}, "version": version}).encode("utf-8")
        req = urllib.request.Request(self.api_url, data=body, method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return [self._to_record(v, ecosystem, package_name) for v in payload.get("vulns", [])]

    @staticmethod
    def _to_record(vuln: Dict[str, Any], ecosystem: str, package_name: str) -> VulnerabilityRecord:
        severity = str(vuln.get("database_specific", {}).get("severity", "unknown")).lower()
        return VulnerabilityRecord(
            vuln_id=vuln.get("id", ""), source="osv", ecosystem=ecosystem, package_name=package_name,
            severity=severity if severity in SEVERITY_WEIGHTS else "unknown",
            summary=vuln.get("summary", ""), published_at=vuln.get("published"),
            references=[ref.get("url", "") for ref in vuln.get("references", [])],
        )


class GHSAFeedClient(VulnerabilityFeedClient):
    name = "ghsa"

    def __init__(self, api_url: str = GHSA_API_URL, github_token: Optional[str] = None, timeout: float = 10.0):
        self.api_url = api_url
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self.timeout = timeout

    def query(self, ecosystem: str, package_name: str, version: str) -> List[VulnerabilityRecord]:
        ghsa_ecosystem = GHSA_ECOSYSTEM_MAP.get(ecosystem)
        if ghsa_ecosystem is None or not package_name:
            return []
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        url = f"{self.api_url}?affects={urllib.parse.quote(package_name)}&per_page=20"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            advisories = json.loads(resp.read().decode("utf-8"))

        records: List[VulnerabilityRecord] = []
        for advisory in advisories:
            for vuln in advisory.get("vulnerabilities", []):
                package = vuln.get("package", {})
                if package.get("ecosystem", "").lower() != ghsa_ecosystem or package.get("name") != package_name:
                    continue
                affected, needs_review = _version_in_ghsa_range(version, vuln.get("vulnerable_version_range", ""))
                if not affected and not needs_review:
                    continue
                records.append(VulnerabilityRecord(
                    vuln_id=advisory.get("ghsa_id", ""), source="ghsa", ecosystem=ecosystem, package_name=package_name,
                    severity=str(advisory.get("severity", "unknown")).lower(),
                    summary=advisory.get("summary", ""), published_at=advisory.get("published_at"),
                    references=[advisory.get("html_url", "")], needs_review=needs_review,
                ))
        return records


def _version_in_ghsa_range(version: str, range_text: str) -> Tuple[bool, bool]:
    """Returns (affected, needs_review). needs_review=True means the range
    could not be parsed with confidence (e.g. non-PEP-440 version strings
    common in Maven/Go) and should be treated as a possible match pending
    manual confirmation, rather than silently excluded.
    """
    if not range_text:
        return False, True
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version

        return Version(version) in SpecifierSet(range_text), False
    except Exception:
        return False, True


class LocalFeedSimulator(VulnerabilityFeedClient):
    """Deterministic offline stand-in, used as a fallback when neither real
    feed is reachable. Returns a canned finding only for the well-known
    lodash@4.17.15 ReDoS test case (GHSA-29mw-wpgm-hmr9 / CVE-2020-28500),
    so self-test stays meaningful without a network call.
    """

    name = "local"

    def query(self, ecosystem: str, package_name: str, version: str) -> List[VulnerabilityRecord]:
        if ecosystem == "npm" and package_name == "lodash" and version == "4.17.15":
            return [VulnerabilityRecord(
                vuln_id="GHSA-29mw-wpgm-hmr9", source="local", ecosystem=ecosystem, package_name=package_name,
                severity="moderate", summary="Regular Expression Denial of Service (ReDoS) in lodash",
                published_at="2022-01-06T20:30:46Z", references=["https://github.com/advisories/GHSA-29mw-wpgm-hmr9"],
            )]
        return []


# ---------------------------------------------------------------------------
# Exposure scoring engine (section 1.6)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExposureContext:
    deployment_criticality: float = 0.5  # 0-1: namespace sensitivity / service priority
    live_state_factor: float = 0.5       # 0-1: restart count, replica count, runtime exposure
    compensating_controls: float = 0.0   # 0-1: network policy / mTLS / EDR presence reduces score


def compute_exposure_score(severity: str, context: ExposureContext) -> float:
    base_severity = SEVERITY_WEIGHTS.get(severity.lower(), 0.3)
    raw = (
        0.45 * base_severity
        + 0.25 * context.deployment_criticality
        + 0.20 * context.live_state_factor
        - 0.20 * context.compensating_controls
    )
    return round(max(0.0, min(1.0, raw)), 4)


def classify_exposure(score: float) -> str:
    if score >= 0.8:
        return "P0"
    if score >= 0.6:
        return "P1"
    if score >= 0.4:
        return "P2"
    return "P3"


@dataclass
class ExposureFinding:
    finding_id: str
    material: Material
    vulnerability: VulnerabilityRecord
    exposure_score: float
    severity_band: str  # P0 | P1 | P2 | P3
    detected_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "material": self.material.to_dict(),
            "vulnerability": self.vulnerability.to_dict(),
            "exposure_score": self.exposure_score,
            "severity_band": self.severity_band,
            "detected_at": self.detected_at,
        }


def finding_from_dict(payload: Dict[str, Any]) -> ExposureFinding:
    return ExposureFinding(
        finding_id=payload["finding_id"],
        material=Material(**payload["material"]),
        vulnerability=VulnerabilityRecord(**payload["vulnerability"]),
        exposure_score=payload["exposure_score"],
        severity_band=payload["severity_band"],
        detected_at=payload["detected_at"],
    )


# ---------------------------------------------------------------------------
# SBOM monitor orchestration
# ---------------------------------------------------------------------------

class SBOMMonitor:
    def __init__(self, feed_clients: Sequence[VulnerabilityFeedClient], default_context: ExposureContext = ExposureContext()):
        self.feed_clients = feed_clients
        self.default_context = default_context

    def scan_materials(
        self, materials: Sequence[Material], context_overrides: Optional[Dict[str, ExposureContext]] = None,
    ) -> List[ExposureFinding]:
        context_overrides = context_overrides or {}
        findings: List[ExposureFinding] = []
        now = datetime.now(timezone.utc).isoformat()

        for material in materials:
            context = context_overrides.get(material.material_id, self.default_context)
            for client in self.feed_clients:
                try:
                    vulns = client.query(material.ecosystem, material.name, material.version)
                except (urllib.error.URLError, urllib.error.HTTPError):
                    continue  # one unreachable feed should not abort the scan
                for vuln in vulns:
                    score = compute_exposure_score(vuln.severity, context)
                    findings.append(ExposureFinding(
                        finding_id=hashlib.sha256(f"{material.material_id}:{vuln.vuln_id}".encode()).hexdigest()[:16],
                        material=material, vulnerability=vuln, exposure_score=score,
                        severity_band=classify_exposure(score), detected_at=now,
                    ))
        return findings


def build_default_feed_chain(github_token: Optional[str] = None) -> List[VulnerabilityFeedClient]:
    return [OSVFeedClient(), GHSAFeedClient(github_token=github_token)]


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

SELF_TEST_SBOM: Dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [
        {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15",
         "hashes": [{"alg": "SHA-256", "content": "0" * 64}]},
        {"type": "library", "name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0",
         "hashes": [{"alg": "SHA-256", "content": "1" * 64}]},
    ],
}


def run_self_test() -> Dict[str, Any]:
    materials = parse_sbom(SELF_TEST_SBOM, provenance={"cluster": "staging", "namespace": "orders"})
    assert len(materials) == 2

    feed_used = "live (osv+ghsa)"
    monitor = SBOMMonitor(build_default_feed_chain())
    try:
        findings = monitor.scan_materials(materials)
        if not findings:
            raise RuntimeError("live feeds reachable but returned no findings - falling back to local simulator")
    except Exception:
        feed_used = "local (offline fallback)"
        monitor = SBOMMonitor([LocalFeedSimulator()])
        findings = monitor.scan_materials(materials)

    lodash_findings = [f for f in findings if f.material.name == "lodash"]

    return {
        "feed_used": feed_used,
        "materials_scanned": len(materials),
        "total_findings": len(findings),
        "lodash_finding_found": len(lodash_findings) > 0,
        "sample_finding": lodash_findings[0].to_dict() if lodash_findings else None,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_scan(args: argparse.Namespace) -> int:
    sbom = json.loads(Path(args.sbom).read_text(encoding="utf-8"))
    provenance = {"cluster": args.cluster, "namespace": args.namespace} if args.cluster or args.namespace else None
    materials = parse_sbom(sbom, provenance)

    feeds: List[VulnerabilityFeedClient] = []
    for name in args.feeds.split(","):
        name = name.strip()
        if name == "osv":
            feeds.append(OSVFeedClient())
        elif name == "ghsa":
            feeds.append(GHSAFeedClient(github_token=args.github_token))
        elif name == "local":
            feeds.append(LocalFeedSimulator())

    monitor = SBOMMonitor(feeds)
    findings = monitor.scan_materials(materials)
    lines = [json.dumps(f.to_dict()) for f in findings]

    if args.output:
        Path(args.output).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        print(f"Wrote {len(findings)} findings to {args.output}")
    else:
        print("\n".join(lines))
    print(f"\nscanned {len(materials)} materials, {len(findings)} findings")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 9 SBOM lifecycle monitor and CVE watcher")
    subparsers = parser.add_subparsers(dest="mode")

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--sbom", required=True)
    scan_parser.add_argument("--feeds", default="osv,ghsa", help="comma-separated: osv,ghsa,local")
    scan_parser.add_argument("--github-token", default=None)
    scan_parser.add_argument("--cluster", default=None)
    scan_parser.add_argument("--namespace", default=None)
    scan_parser.add_argument("--output")
    scan_parser.set_defaults(func=_cmd_scan)

    subparsers.add_parser("self-test")

    args = parser.parse_args()
    if args.mode == "self-test":
        print(json.dumps(run_self_test(), indent=2, default=str))
        return 0
    if not args.mode:
        parser.error("Provide a subcommand: scan | self-test")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
