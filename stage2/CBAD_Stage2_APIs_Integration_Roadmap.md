# CBAD Stage 2 — REST APIs, Nexus/Artifactory Integration, and Enterprise Roadmap

## SECTION 6 — REST APIs

### 6.1 API design principles

CBAD Stage 2 exposes secure, versioned REST APIs for artifact admission, quarantine, risk scoring, and graph queries. APIs are designed to support:
- low-latency proxy validation for Nexus and Artifactory
- asynchronous review workflows
- event-driven cache synchronization
- enterprise RBAC and tenant isolation

Security requirements:
- TLS-only transport
- OAuth 2.0 / mTLS for service-to-service authentication
- per-tenant API keys for build agents
- request signing for artifact admission events
- rate limiting and audit logging

### 6.2 API surface

#### 6.2.1 `POST /api/v2/artifacts/validate`

Validates an incoming artifact or package request against the DGT, typosquat, and quarantine policies.

Request payload:
```json
{
  "request_id": "string",
  "tenant_id": "string",
  "artifact": {
    "ecosystem": "npm|pypi|maven|nuget|go|rubygems|docker",
    "namespace": "string",
    "name": "string",
    "version": "string",
    "source_registry": "string",
    "source_url": "string",
    "checksum": "sha256:...",
    "signature": {
      "algorithm": "string",
      "signature_value": "string",
      "signer": "string"
    },
    "metadata": {
      "description": "string",
      "keywords": ["string"],
      "repository_url": "string",
      "homepage": "string"
    }
  },
  "request_context": {
    "requester_id": "string",
    "requester_type": "build_agent|human|sync_service",
    "source_ip": "string",
    "user_agent": "string",
    "timestamp": "2026-06-23T12:00:00Z"
  }
}
```

Response payload:
```json
{
  "request_id": "string",
  "artifact_id": "string",
  "decision": "allow|quarantine|block|review",
  "dgt_score": 0.0,
  "typosquat_score": 0.0,
  "risk_category": "trusted|caution|risk|high_risk",
  "policy_reasons": ["string"],
  "recommended_action": "string",
  "quarantine_id": "string|null",
  "details": {
    "scores": {
      "cve": 0.0,
      "maintainers": 0.0,
      "bus_factor": 0.0,
      "release_frequency": 0.0,
      "code_review": 0.0,
      "community": 0.0,
      "corporate": 0.0,
      "dependency_depth": 0.0,
      "test_coverage": 0.0,
      "documentation": 0.0,
      "name_similarity": 0.0,
      "keyboard_similarity": 0.0,
      "visual_similarity": 0.0,
      "transformer_similarity": 0.0
    },
    "matched_rules": ["string"]
  }
}
```

#### 6.2.2 `POST /api/v2/artifacts/quarantine`

Creates or updates a quarantine record for a suspicious artifact.

Request payload:
```json
{
  "request_id": "string",
  "tenant_id": "string",
  "artifact_id": "string",
  "artifact": {
    "ecosystem": "string",
    "namespace": "string",
    "name": "string",
    "version": "string",
    "checksum": "sha256:...",
    "source_registry": "string",
    "source_url": "string"
  },
  "quarantine_reason": "typosquat|dependency_confusion|cve_risk|maintainer_risk|release_anomaly|signature_failure",
  "risk_details": {
    "dgt_score": 0.0,
    "typosquat_score": 0.0,
    "policy_triggered": ["string"]
  },
  "storage_location": "string",
  "assigned_team": "string",
  "requested_by": "string",
  "timestamp": "2026-06-23T12:00:00Z"
}
```

Response payload:
```json
{
  "request_id": "string",
  "quarantine_id": "string",
  "status": "created|updated",
  "review_status": "pending|approved|rejected|escalated",
  "review_url": "string"
}
```

#### 6.2.3 `GET /api/v2/artifacts/{artifact_id}`

Retrieves artifact trust and quarantine state.

Response payload:
```json
{
  "artifact_id": "string",
  "tenant_id": "string",
  "package": {
    "ecosystem": "string",
    "namespace": "string",
    "name": "string",
    "version": "string"
  },
  "trust_profile": {
    "dgt_score": 0.0,
    "typosquat_score": 0.0,
    "trust_category": "string",
    "decision": "allow|quarantine|block|review"
  },
  "quarantine": {
    "quarantine_id": "string|null",
    "status": "pending|approved|rejected|escalated|null",
    "created_at": "string|null",
    "updated_at": "string|null"
  },
  "audit": {
    "last_reviewed_at": "string|null",
    "last_reviewed_by": "string|null",
    "review_notes": "string|null"
  }
}
```

#### 6.2.4 `POST /api/v2/graph/query`

Executes a graph risk query for dependency lineage and attack surface.

Request payload:
```json
{
  "request_id": "string",
  "tenant_id": "string",
  "query_type": "package_risk|maintainer_surface|dependent_branches|typosquat_cluster",
  "query_params": {
    "package_name": "string",
    "namespace": "string",
    "ecosystem": "string",
    "depth": 4,
    "threshold": 60
  }
}
```

Response payload:
```json
{
  "request_id": "string",
  "results": [
    {
      "node_type": "Package|Release|Maintainer|Vulnerability",
      "id": "string",
      "properties": {"string": "any"},
      "relationships": [
        {"type": "string", "target_id": "string", "properties": {"string": "any"}}
      ]
    }
  ],
  "metrics": {
    "node_count": 0,
    "edge_count": 0,
    "query_time_ms": 0
  }
}
```

#### 6.2.5 `POST /api/v2/reviews/{quarantine_id}/decision`

Records review decisions and triggers promotion or remediation.

Request payload:
```json
{
  "request_id": "string",
  "tenant_id": "string",
  "quarantine_id": "string",
  "reviewer_id": "string",
  "decision": "approve|reject|escalate",
  "comments": "string",
  "artifact_action": "promote|blacklist|hold"
}
```

Response payload:
```json
{
  "request_id": "string",
  "quarantine_id": "string",
  "status": "approved|rejected|escalated",
  "artifacts_promoted": ["string"],
  "blacklist_entries": ["string"]
}
```

#### 6.2.6 `GET /api/v2/healthz`

Health check endpoint for load balancers and proxies.

Response payload:
```json
{
  "status": "ok",
  "uptime_seconds": 0,
  "dependencies": {
    "neo4j": "ok|degraded|down",
    "postgres": "ok|degraded|down",
    "s3": "ok|degraded|down"
  }
}
```

### 6.3 API behavior and versioning

- support `Accept: application/json; version=2` header
- respond with `429` for rate-limited traffic
- respond with `403` for unauthorized requests
- use `400` for malformed payloads, `409` for conflicting artifact states
- log request/response audit trails including `request_id`, `tenant_id`, and `artifact_id`
- return `X-RateLimit-Remaining` and `X-Request-ID`

### 6.4 API implementation notes

- implement idempotency on artifact validation and quarantine creation using `request_id`
- store API payload versions in PostgreSQL for audit and replay
- expose metrics via Prometheus endpoints for request rates, latency, and error counts
- support GraphQL later for exploration, but REST is primary for artifact proxies

## SECTION 7 — Nexus/Artifactory Integration

### 7.1 Integration architecture

CBAD integrates with Sonatype Nexus and JFrog Artifactory using a proxy plugin / interceptor architecture. The design supports:
- transparent request interception for artifact fetch and publish
- policy enforcement for artifact admission and proxy caching
- cache synchronization with existing repository groups
- minimal disruption to existing developer workflows

### 7.2 Proxy plugin architecture

The proxy plugin sits between the package manager and the repository cluster and performs these functions:
1. intercept artifact metadata and binary requests
2. call `POST /api/v2/artifacts/validate`
3. allow, quarantine, or block artifact fetches based on the response
4. forward artifact uploads to the artifact cache only after validation
5. enrich repository metadata with DGT and typosquat scores
6. synchronize blacklists and trusted caches from CBAD

#### 7.2.1 Deployment modes

- `Sidecar mode` for Kubernetes-hosted Nexus/Artifactory deployments
- `Plugin mode` using native extension points (Nexus IQ, Artifactory Add-ons)
- `Reverse proxy mode` with Envoy or NGINX in front of repository clusters

### 7.3 Sonatype Nexus integration

#### 7.3.1 Recommended architecture

- deploy CBAD proxy plugin as a custom Nexus `RepositoryRouter` or security plugin
- intercept proxy repository requests and hosted repository uploads
- validate artifacts before caching or serving
- tag packages in Nexus metadata with CBAD risk scores
- enforce repository routing rules such as internal registry precedence

#### 7.3.2 Nexus extension endpoints

- `RepositoryContentHandler` intercepts `GET /repository/{repo}/...`
- `RepositoryUploadHandler` intercepts `PUT /repository/{repo}/...` and `POST /service/rest/v1/components`
- `RepositoryRouting` uses `CBAD` callout to decide whether to proxy or block

#### 7.3.3 Nexus plugin behavior

- for `proxy` repositories:
  - if artifact not cached, call CBAD validate API
  - if `allow`, fetch upstream artifact and cache it
  - if `quarantine`, do not cache and add artifact metadata to quarantine index
  - if `block`, return HTTP `403` to client
- for `hosted` repositories:
  - validate published artifacts before acceptance
  - reject packages that fail signature or namespace conflict checks
- for `group` repositories:
  - preserve group ordering while ensuring CBAD-managed repositories are consulted first

### 7.4 JFrog Artifactory integration

#### 7.4.1 Recommended architecture

- integrate via Artifactory `User Plugins` or `Smart Remote` proxy hooks
- use `beforeDownload`, `beforeUpload`, and `remoteDownload` plugin entry points
- implement policy decisions based on CBAD validation responses

#### 7.4.2 Artifactory plugin flow

- `beforeDownload`: check cache for artifact metadata, call CBAD if needed
- `beforeUpload`: validate artifact on hosted/release repositories
- `remoteDownload`: inspect artifacts fetched from smart remotes and apply quarantine rules

#### 7.4.3 Example plugin pseudocode

```groovy
import org.artifactory.repo.RepoPath
import org.artifactory.fs.FileInfo

storage { 
  beforeDownload { item ->
    def artifact = extractArtifactMetadata(item)
    def response = callCBADValidate(artifact)
    if (response.decision == 'block') {
      status = 403
      message = 'Artifact blocked by CBAD policy.'
    } else if (response.decision == 'quarantine') {
      quarantineArtifact(item, response.quarantine_id)
      status = 403
      message = 'Artifact quarantined.'
    }
  }

  beforeUpload { item ->
    def artifact = extractArtifactMetadata(item)
    def response = callCBADValidate(artifact)
    if (response.decision != 'allow') {
      status = 403
      message = 'Upload blocked by CBAD.'
    }
  }
}
```

### 7.5 Seamless cache behavior

- maintain existing Nexus/Artifactory repository IDs and access patterns
- integrate CBAD as a validation layer, not a replacement path where possible
- use metadata enrichment to surface trust scores in repository UIs
- synchronize blacklist and allowlist policies from CBAD to repo clusters
- support `proxy rejection` and `fail-open vs fail-closed` modes per repository policy

### 7.6 Enterprise plugin governance

- sign plugin binaries and validate plugin integrity on deployment
- support plugin configuration via central CBAD policy service
- log plugin decisions to both CBAD and local repo audit logs
- provide rollback path if plugin or validation service is unavailable

## SECTION 8 — Enterprise Scale & Roadmap

### 8.1 High-availability design

For enterprise deployment, CBAD must be designed for 99.95% availability and regional resilience.

#### 8.1.1 Service architecture

- stateless API pods behind a load balancer
- separate stateful services:
  - PostgreSQL or Aurora for transactional metadata
  - Neo4j cluster for graph storage
  - Elasticsearch/OpenSearch for search and incident queries
  - S3-compatible object storage for audit and quarantine payloads
- asynchronous worker pools for quarantine processing, graph ingestion, and policy propagation
- message bus such as Kafka or AWS SNS/SQS for event-driven coordination

#### 8.1.2 Resilience patterns

- multi-AZ deployments for databases and graph stores
- read replicas for Neo4j and PostgreSQL query scaling
- circuit breaker and retry policies for external registry integration
- health checks and Kubernetes pod disruption budgets
- canary and blue-green deployments for plugin and API updates

### 8.2 Cache synchronization patterns

#### 8.2.1 Multi-region artifact sync

- use geo-replicated repository groups in Nexus/Artifactory
- synchronize only vetted artifacts across regions
- use CBAD risk metadata to determine replication eligibility
- maintain a region-local trusted cache for low-latency local builds

#### 8.2.2 Policy synchronization

- central CBAD policy service publishes policies to regional proxies
- use incremental delta updates for allowlists, blacklists, and namespace rules
- version policy bundles with a checksum and `policy_version`
- ensure eventual consistency with strong local enforcement for critical rules

#### 8.2.3 Graph sync and lineage propagation

- ingest dependency graph events from each region into a central Neo4j or federated graph
- replicate critical provenance and quarantine state to regional caches for local evaluation
- use publish/subscribe channels to update DGT and typosquat scoring in real time

### 8.3 Implementation roadmap

#### Phase 1 — Pilot deployment

- deploy CBAD core services in a single region
- implement REST APIs and internal admission controller
- integrate with one Nexus or Artifactory cluster using sidecar/proxy mode
- validate `POST /api/v2/artifacts/validate` and quarantine workflow
- enable basic DGT and typosquat scoring for package admission
- certify developer and CI workflows against the proxy

##### Code example: artifact validation client

```python
import requests

CBAD_API = 'https://cbad.example.com/api/v2/artifacts/validate'

payload = {
  'request_id': 'req-123',
  'tenant_id': 'tenant-acme',
  'artifact': {
    'ecosystem': 'npm',
    'namespace': 'acme',
    'name': 'acmecore',
    'version': '1.2.3',
    'source_registry': 'https://registry.npmjs.org',
    'checksum': 'sha256:abcd...',
    'metadata': {
      'description': 'Acme core library',
      'repository_url': 'https://github.com/acme/acmecore'
    }
  },
  'request_context': {
    'requester_id': 'ci-runner-1',
    'requester_type': 'build_agent',
    'source_ip': '10.0.0.1',
    'user_agent': 'npm/9.0.0'
  }
}

resp = requests.post(CBAD_API, json=payload, timeout=5)
print(resp.json())
```

#### Phase 2 — Production readiness

- expand to multi-region deployment and HA database clusters
- integrate with both Nexus and Artifactory
- deploy quarantine workflows and review automation
- implement Neo4j lineage ingestion and graph-based risk queries
- support 10-1000 developers and concurrent build agents
- add RBAC, multi-tenant isolation, and audit logging

#### Phase 3 — Enterprise scale

- enable global artifact cache synchronization across regions
- support 10,000+ developers and 500k artifact validations/day
- deploy regional CBAD proxies and local trust caches
- implement advanced rate limiting, SLA-based quarantine review, and incident response playbooks
- integrate with enterprise security platforms and IAM

#### Phase 4 — Optimization and compliance

- add adaptive policy tuning based on false positive feedback
- support offline/air-gapped artifact pipelines
- certify architecture for regulatory compliance (SOC 2, FedRAMP, ISO 27001)
- optimize for massive repositories and long-term provenance retention

### 8.4 Code examples for enterprise integration

#### Proxy plugin health check route

```python
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/healthz', methods=['GET'])
def healthz():
    return jsonify({
        'status': 'ok',
        'service': 'cbad-proxy',
        'version': '2.0.0'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

#### Policy bundle sync example

```bash
curl -X GET \
  https://cbad.example.com/api/v2/policies/latest \
  -H 'Authorization: Bearer <token>' \
  -o /etc/cbad/policy-bundle.json

systemctl restart cbad-proxy
```

#### Cache sync event structure

```json
{
  "event_id": "evt-123",
  "tenant_id": "tenant-acme",
  "artifact_id": "pkg-npm-acme-core-1.2.3",
  "source_region": "us-east-1",
  "target_region": "eu-west-1",
  "sync_action": "replicate|evict|refresh",
  "timestamp": "2026-06-23T12:00:00Z"
}
```

### 8.5 Operations and observability

- instrument request latency and decision distributions per endpoint
- monitor quarantine queue depth and review SLA compliance
- track cache hit/miss ratios and artifact denial rates
- alert on high-risk artifact admission spikes and failed proxy health checks
- use distributed tracing for request flow across CBAD, Nexus/Artifactory, and CI systems

### 8.6 Enterprise governance

- define policy categories: `strict`, `standard`, `developer` per tenant or repository group
- use policy versioning and change approval workflows
- audit all API decisions, review outcomes, and artifact promotions
- integrate with enterprise SIEM and ticketing systems for suspicious artifact cases

---

This Stage 2 deliverable completes the enterprise-ready REST API and integration architecture, plus a detailed roadmap for high-availability and multi-region scale.
