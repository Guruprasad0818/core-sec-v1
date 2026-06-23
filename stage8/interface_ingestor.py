#!/usr/bin/env python3
"""CBAD Stage 8 - OpenAPI/Swagger interface ingestor.

Implements the "Spec Ingestor" component and a lightweight slice of the
"State Machine Constructor" and "Constraint Solver/Parameter Suggester"
from CBAD_Stage8_DAST_InterfaceDiscovery.md SECTION 1: it parses OpenAPI
v2 (Swagger) and v3 documents into canonical Operation objects (1.3),
detects authentication schemes (1.4), groups operations into resource
nodes (1.5/1.6), and generates sample parameter values (1.7).

Honest scope: section 1.2 names eight components (Spec Ingestor, Live Recon
Collector, Auth Context Analyzer, Schema Resolver, State Machine
Constructor, Constraint Solver, Planner/Orchestrator, Telemetry Store).
This module implements only the spec-driven slice - static parsing of a
provided OpenAPI document. It does not crawl live traffic (no Playwright/
headless browser, section 1.9), does not probe the live service to observe
real response codes (section 1.6's "issue dry-run probes"), and does not
run a full SMT solver (section 1.7's optional Z3 integration) - sample
generation is type-driven only. $ref resolution and request-body schema
flattening are one level deep; deeply nested object schemas degrade to a
generic "object" placeholder rather than full recursive expansion.

Usage:
  python stage8/interface_ingestor.py --spec openapi.json --output graph.json
  python stage8/interface_ingestor.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PATH_PARAM_PATTERN = re.compile(r"\{([^}]+)\}")
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


# ---------------------------------------------------------------------------
# Canonical data model (section 1.13)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Parameter:
    name: str
    location: str  # path | query | header | cookie | body
    required: bool
    schema_type: str  # string | integer | number | boolean | array | object
    example: Optional[Any] = None
    enum: Tuple[Any, ...] = ()
    format: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuthScheme:
    name: str
    scheme_type: str  # apiKey | http | oauth2 | openIdConnect | basic
    location: Optional[str] = None       # header | query | cookie, for apiKey
    param_name: Optional[str] = None     # e.g. "Authorization" or "X-API-Key"
    bearer_format: Optional[str] = None  # e.g. "JWT"
    oauth2_flows: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Operation:
    operation_id: str
    method: str
    path_template: str
    parameters: Tuple[Parameter, ...]
    request_body_fields: Tuple[Parameter, ...]
    response_status_codes: Tuple[str, ...]
    security_requirements: Tuple[str, ...]
    tags: Tuple[str, ...]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            **{k: v for k, v in asdict(self).items() if k not in ("parameters", "request_body_fields")},
            "parameters": [p.to_dict() for p in self.parameters],
            "request_body_fields": [p.to_dict() for p in self.request_body_fields],
        }


@dataclass
class ResourceNode:
    name: str
    operations: List[str] = field(default_factory=list)  # operation_ids

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class APIGraph:
    title: str
    version: str
    base_url: str
    auth_schemes: Dict[str, AuthScheme]
    operations: Dict[str, Operation]
    resources: Dict[str, ResourceNode]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "version": self.version,
            "base_url": self.base_url,
            "auth_schemes": {k: v.to_dict() for k, v in self.auth_schemes.items()},
            "operations": {k: v.to_dict() for k, v in self.operations.items()},
            "resources": {k: v.to_dict() for k, v in self.resources.items()},
        }

    def get_operation(self, operation_id: str) -> Operation:
        return self.operations[operation_id]


# ---------------------------------------------------------------------------
# $ref resolution (one level, per the documented scope limit)
# ---------------------------------------------------------------------------

def resolve_ref(spec: Dict[str, Any], node: Any) -> Any:
    if not isinstance(node, dict) or "$ref" not in node:
        return node
    ref = node["$ref"]
    if not ref.startswith("#/"):
        return node  # external refs unsupported
    target: Any = spec
    for part in ref.lstrip("#/").split("/"):
        target = target.get(part, {}) if isinstance(target, dict) else {}
    return target


# ---------------------------------------------------------------------------
# Spec Ingestor (section 1.3)
# ---------------------------------------------------------------------------

class SpecIngestor:
    def ingest_file(self, path: Path) -> APIGraph:
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in (".yaml", ".yml"):
            import yaml

            spec = yaml.safe_load(text)
        else:
            spec = json.loads(text)
        return self.ingest_dict(spec)

    def ingest_dict(self, spec: Dict[str, Any]) -> APIGraph:
        is_v3 = "openapi" in spec
        info = spec.get("info", {})
        title = info.get("title", "untitled-api")
        version = str(info.get("version", "0.0.0"))
        base_url = self._extract_base_url(spec, is_v3)
        auth_schemes = self._extract_auth_schemes(spec, is_v3)
        global_security = self._extract_security_names(spec.get("security", []))

        operations: Dict[str, Operation] = {}
        for path_template, path_item in spec.get("paths", {}).items():
            path_item = resolve_ref(spec, path_item)
            shared_params = [resolve_ref(spec, p) for p in path_item.get("parameters", [])]
            for method in HTTP_METHODS:
                op_obj = path_item.get(method)
                if not op_obj:
                    continue
                operation = self._build_operation(spec, method, path_template, op_obj, shared_params, is_v3, global_security)
                operations[operation.operation_id] = operation

        resources = self._build_resources(operations)
        return APIGraph(title, version, base_url, auth_schemes, operations, resources)

    @staticmethod
    def _extract_base_url(spec: Dict[str, Any], is_v3: bool) -> str:
        if is_v3:
            servers = spec.get("servers", [])
            if servers:
                return servers[0].get("url", "")
            return ""
        scheme = (spec.get("schemes") or ["https"])[0]
        host = spec.get("host", "")
        base_path = spec.get("basePath", "")
        return f"{scheme}://{host}{base_path}" if host else ""

    @staticmethod
    def _extract_security_names(security_list: List[Dict[str, Any]]) -> Tuple[str, ...]:
        names: List[str] = []
        for requirement in security_list:
            names.extend(requirement.keys())
        return tuple(dict.fromkeys(names))  # de-duplicate, preserve order

    def _extract_auth_schemes(self, spec: Dict[str, Any], is_v3: bool) -> Dict[str, AuthScheme]:
        raw_schemes = spec.get("components", {}).get("securitySchemes", {}) if is_v3 else spec.get("securityDefinitions", {})
        schemes: Dict[str, AuthScheme] = {}
        for name, definition in raw_schemes.items():
            scheme_type = definition.get("type", "apiKey")
            flows = tuple(definition.get("flows", {}).keys()) if is_v3 and scheme_type == "oauth2" else ()
            schemes[name] = AuthScheme(
                name=name,
                scheme_type=scheme_type,
                location=definition.get("in"),
                param_name=definition.get("name"),
                bearer_format=definition.get("bearerFormat"),
                oauth2_flows=flows,
            )
        return schemes

    def _build_operation(
        self, spec: Dict[str, Any], method: str, path_template: str, op_obj: Dict[str, Any],
        shared_params: List[Dict[str, Any]], is_v3: bool, global_security: Tuple[str, ...],
    ) -> Operation:
        operation_id = op_obj.get("operationId") or f"{method}_{_slugify(path_template)}"
        raw_params = shared_params + [resolve_ref(spec, p) for p in op_obj.get("parameters", [])]

        parameters: List[Parameter] = []
        request_body_fields: List[Parameter] = []
        for raw in raw_params:
            location = raw.get("in", "query")
            if location == "body":  # Swagger v2 body parameter
                schema = resolve_ref(spec, raw.get("schema", {}))
                request_body_fields.extend(self._flatten_schema_fields(spec, schema))
            else:
                parameters.append(self._param_from_definition(raw, location))

        if is_v3 and "requestBody" in op_obj:
            content = op_obj["requestBody"].get("content", {})
            for media_type, media_obj in content.items():
                schema = resolve_ref(spec, media_obj.get("schema", {}))
                request_body_fields.extend(self._flatten_schema_fields(spec, schema))
                break  # first content type is enough for sample generation purposes

        responses = tuple(sorted(op_obj.get("responses", {}).keys()))
        own_security = op_obj.get("security")
        security_names = self._extract_security_names(own_security) if own_security is not None else global_security

        return Operation(
            operation_id=operation_id,
            method=method.upper(),
            path_template=path_template,
            parameters=tuple(parameters),
            request_body_fields=tuple(request_body_fields),
            response_status_codes=responses,
            security_requirements=security_names,
            tags=tuple(op_obj.get("tags", [])),
            summary=op_obj.get("summary", ""),
        )

    @staticmethod
    def _param_from_definition(raw: Dict[str, Any], location: str) -> Parameter:
        schema = raw.get("schema", raw)  # v3 nests under "schema"; v2 puts type at top level
        return Parameter(
            name=raw.get("name", ""),
            location=location,
            required=bool(raw.get("required", False)),
            schema_type=schema.get("type", "string"),
            example=raw.get("example", schema.get("example")),
            enum=tuple(schema.get("enum", [])),
            format=schema.get("format"),
        )

    def _flatten_schema_fields(self, spec: Dict[str, Any], schema: Dict[str, Any]) -> List[Parameter]:
        schema = resolve_ref(spec, schema)
        properties = schema.get("properties", {})
        required_fields = set(schema.get("required", []))
        fields: List[Parameter] = []
        for field_name, field_schema in properties.items():
            field_schema = resolve_ref(spec, field_schema)
            fields.append(Parameter(
                name=field_name,
                location="body",
                required=field_name in required_fields,
                schema_type=field_schema.get("type", "object"),
                example=field_schema.get("example"),
                enum=tuple(field_schema.get("enum", [])),
                format=field_schema.get("format"),
            ))
        return fields

    @staticmethod
    def _build_resources(operations: Dict[str, Operation]) -> Dict[str, ResourceNode]:
        resources: Dict[str, ResourceNode] = {}
        for operation in operations.values():
            segments = [s for s in operation.path_template.split("/") if s and not s.startswith("{")]
            resource_name = segments[0] if segments else "root"
            resources.setdefault(resource_name, ResourceNode(name=resource_name)).operations.append(operation.operation_id)
        return resources


def _slugify(path_template: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", path_template).strip("_").lower()


# ---------------------------------------------------------------------------
# Constraint solving / sample value generation (section 1.7)
# ---------------------------------------------------------------------------

def generate_sample_value(param: Parameter) -> Any:
    if param.example is not None:
        return param.example
    if param.enum:
        return param.enum[0]
    if param.schema_type == "string":
        return _sample_string(param)
    if param.schema_type == "integer":
        return 1
    if param.schema_type == "number":
        return 1.0
    if param.schema_type == "boolean":
        return True
    if param.schema_type == "array":
        return []
    return {}  # object or unrecognized type: generic placeholder


def _sample_string(param: Parameter) -> str:
    if param.format == "uuid":
        return str(uuid.uuid4())
    if param.format in ("date", "date-time"):
        now = datetime.now(timezone.utc)
        return now.date().isoformat() if param.format == "date" else now.isoformat()
    if param.format == "email":
        return "test.user@example.com"
    return f"sample-{param.name or 'value'}"


@dataclass
class SampleRequest:
    method: str
    path: str
    query_params: Dict[str, Any]
    headers: Dict[str, Any]
    body: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def build_sample_request(operation: Operation, overrides: Optional[Dict[str, Any]] = None) -> SampleRequest:
    overrides = overrides or {}
    path = operation.path_template
    query_params: Dict[str, Any] = {}
    headers: Dict[str, Any] = {}

    for param in operation.parameters:
        value = overrides.get(param.name, generate_sample_value(param))
        if param.location == "path":
            path = path.replace(f"{{{param.name}}}", str(value))
        elif param.location == "query":
            query_params[param.name] = value
        elif param.location in ("header", "cookie"):
            headers[param.name] = value

    body = {field.name: overrides.get(field.name, generate_sample_value(field)) for field in operation.request_body_fields}

    return SampleRequest(method=operation.method, path=path, query_params=query_params, headers=headers, body=body)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

SELF_TEST_SPEC: Dict[str, Any] = {
    "openapi": "3.0.0",
    "info": {"title": "Orders API", "version": "1.0.0"},
    "servers": [{"url": "https://api.example.com"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
            "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        },
        "schemas": {
            "OrderCreate": {
                "type": "object",
                "required": ["item_id", "quantity"],
                "properties": {
                    "item_id": {"type": "string", "format": "uuid"},
                    "quantity": {"type": "integer"},
                    "notes": {"type": "string"},
                },
            }
        },
    },
    "security": [{"bearerAuth": []}],
    "paths": {
        "/orders/{id}": {
            "get": {
                "operationId": "getOrderById",
                "tags": ["orders"],
                "summary": "Fetch an order by ID",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}},
                ],
                "responses": {"200": {"description": "OK"}, "403": {"description": "Forbidden"}, "404": {"description": "Not found"}},
            },
            "delete": {
                "operationId": "deleteOrderById",
                "tags": ["orders"],
                "summary": "Delete an order by ID",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}},
                ],
                "responses": {"204": {"description": "No content"}},
            },
        },
        "/orders": {
            "post": {
                "operationId": "createOrder",
                "tags": ["orders"],
                "summary": "Create a new order",
                "security": [{"apiKeyAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/OrderCreate"}}},
                },
                "responses": {"201": {"description": "Created"}},
            }
        },
    },
}


def run_self_test() -> Dict[str, Any]:
    graph = SpecIngestor().ingest_dict(SELF_TEST_SPEC)
    sample = build_sample_request(graph.get_operation("getOrderById"))
    return {
        "title": graph.title,
        "operation_count": len(graph.operations),
        "resource_names": sorted(graph.resources.keys()),
        "auth_scheme_names": sorted(graph.auth_schemes.keys()),
        "get_order_security": graph.get_operation("getOrderById").security_requirements,
        "create_order_security": graph.get_operation("createOrder").security_requirements,
        "create_order_body_fields": [f.name for f in graph.get_operation("createOrder").request_body_fields],
        "sample_request_for_get_order": sample.to_dict(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="CBAD Stage 8 OpenAPI/Swagger interface ingestor")
    parser.add_argument("--spec", help="Path to an OpenAPI/Swagger JSON or YAML file")
    parser.add_argument("--output", help="Optional path to write the parsed API graph as JSON")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if not args.spec and not args.self_test:
        parser.error("Provide --spec <file> or --self-test")

    if args.self_test:
        print(json.dumps(run_self_test(), indent=2, default=str))
        return 0

    graph = SpecIngestor().ingest_file(Path(args.spec))
    output_text = json.dumps(graph.to_dict(), indent=2, default=str)
    if args.output:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"Wrote API graph with {len(graph.operations)} operations to {args.output}")
    else:
        print(output_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
