"""
OpenAPI / Swagger ingestion (Stage 1 - highest fidelity).

Parses paths, methods, parameters, request bodies, security requirements, and
vendor `x-` extensions. Flags `deprecated`, `x-internal`, and `x-admin` markers
as under-secured surfaces.
"""

from __future__ import annotations

import json
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:  # YAML support is optional
    yaml = None

from ..core.registry import Endpoint, EndpointRegistry, Parameter

_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}


def _load(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        if yaml is None:
            raise RuntimeError("PyYAML not installed - needed for YAML specs. pip install pyyaml")
        return yaml.safe_load(text)
    return json.loads(text)


def _params(method_obj: dict, path_obj: dict) -> list[Parameter]:
    out: list[Parameter] = []
    for p in (path_obj.get("parameters", []) + method_obj.get("parameters", [])):
        if not isinstance(p, dict):
            continue
        schema = p.get("schema", {})
        out.append(Parameter(
            name=p.get("name", "?"),
            location=p.get("in", "query"),
            type=schema.get("type", "string"),
            required=bool(p.get("required", p.get("in") == "path")),
        ))
    # Request body fields -> body parameters
    body = method_obj.get("requestBody", {})
    for _, media in body.get("content", {}).items():
        props = media.get("schema", {}).get("properties", {})
        required = set(media.get("schema", {}).get("required", []))
        for name, sch in props.items():
            out.append(Parameter(
                name=name, location="body",
                type=sch.get("type", "string") if isinstance(sch, dict) else "string",
                required=name in required,
            ))
        break  # first media type is representative
    return out


def parse_openapi(path: str | Path, registry: EndpointRegistry) -> int:
    spec = _load(Path(path))
    servers = spec.get("servers", [])
    base_path = ""
    if servers and isinstance(servers[0], dict):
        # Use only the path component of the server URL as a prefix hint.
        from urllib.parse import urlparse
        base_path = urlparse(servers[0].get("url", "")).path.rstrip("/")

    added = 0
    for raw_path, path_obj in spec.get("paths", {}).items():
        if not isinstance(path_obj, dict):
            continue
        full_path = f"{base_path}{raw_path}" if base_path else raw_path
        for method, mobj in path_obj.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(mobj, dict):
                continue
            security = mobj.get("security", spec.get("security"))
            ep = Endpoint(
                path=full_path,
                method=method.upper(),
                source=["openapi"],
                auth_required=security is not None and security != [],
                parameters=_params(mobj, path_obj),
                deprecated=bool(mobj.get("deprecated", False)),
            )
            tags = set(mobj.get("tags", []))
            if mobj.get("x-internal") or "x-internal" in mobj:
                ep.business_rule_tags.append("privileged")
            if mobj.get("x-admin") or any(t.lower() == "admin" for t in tags):
                ep.business_rule_tags.append("privileged")
            registry.add(ep)
            added += 1
    return added
