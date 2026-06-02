"""
GraphQL ingestion (Stage 1). Parses an SDL schema (or introspection JSON) and
registers each query/mutation/subscription as an endpoint so the playbooks treat
them as first-class attack surface. GraphQL is especially IDOR-prone because of
nested object resolution, so id-bearing fields are tagged `object_reference`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..core.registry import Endpoint, EndpointRegistry, Parameter

# Matches: type Query { ... }  /  type Mutation { ... }  /  type Subscription { ... }
_BLOCK = re.compile(r"\btype\s+(Query|Mutation|Subscription)\s*\{([^}]*)\}", re.IGNORECASE | re.DOTALL)
# Matches a field:  name(arg: Type, ...): ReturnType
_FIELD = re.compile(r"^\s*(\w+)\s*(?:\(([^)]*)\))?\s*:\s*([\[\]\w!]+)", re.MULTILINE)
_ARG = re.compile(r"(\w+)\s*:\s*([\[\]\w!]+)")


def _kind_method(kind: str) -> str:
    return "GET" if kind.lower() == "query" else "POST"


def _add_field(registry: EndpointRegistry, kind: str, name: str, args: str, ret: str) -> None:
    params = [Parameter(name=a, location="body", type="string",
                        required=t.endswith("!")) for a, t in _ARG.findall(args or "")]
    ep = Endpoint(
        path=f"/graphql#{kind.lower()}.{name}",
        method=_kind_method(kind),
        source=["graphql"],
        auth_required=True,
        parameters=params,
    )
    arg_names = {a.lower() for a, _ in _ARG.findall(args or "")}
    if {"id", "userid", "user_id", "accountid"} & arg_names or "id" in ret.lower():
        ep.business_rule_tags.append("object_reference")
    registry.add(ep)


def parse_graphql_sdl(path: str | Path, registry: EndpointRegistry) -> int:
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    added = 0
    for kind, body in _BLOCK.findall(text):
        for name, args, ret in _FIELD.findall(body):
            _add_field(registry, kind, name, args, ret)
            added += 1
    return added


def parse_graphql_introspection(path: str | Path, registry: EndpointRegistry) -> int:
    """Parse a standard introspection result (__schema.types with queryType etc.)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    schema = data.get("data", {}).get("__schema") or data.get("__schema") or {}
    roots = {schema.get("queryType", {}).get("name"): "Query",
             schema.get("mutationType", {}).get("name"): "Mutation",
             schema.get("subscriptionType", {}).get("name"): "Subscription"}
    added = 0
    for t in schema.get("types", []):
        kind = roots.get(t.get("name"))
        if not kind:
            continue
        for f in t.get("fields") or []:
            args = ", ".join(f"{a['name']}: X" for a in (f.get("args") or []))
            ret = json.dumps(f.get("type", {}))
            _add_field(registry, kind, f["name"], args, ret)
            added += 1
    return added
