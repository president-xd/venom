"""
Ingestion orchestrator. Walks a directory of artifacts (or an explicit list),
dispatches each file to the right parser in priority order, and returns a
populated EndpointRegistry plus a sequence map and notes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from ..core.registry import EndpointRegistry
from . import openapi as _openapi
from . import jsbundle as _jsbundle
from . import graphql as _graphql
from .traffic import SequenceMap, parse_har, parse_burp_xml, reconcile_shadow

logger = logging.getLogger("venom.ingest")


@dataclass
class IngestResult:
    registry: EndpointRegistry
    sequence_map: SequenceMap
    notes: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)


def _looks_like_openapi(path: Path) -> bool:
    if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:4000].lower()
    except Exception:  # noqa: BLE001
        return False
    return ("openapi" in head or "swagger" in head) and "paths" in head


def _looks_like_har(path: Path) -> bool:
    if path.suffix.lower() != ".har" and path.suffix.lower() != ".json":
        return False
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:2000].lower()
    except Exception:  # noqa: BLE001
        return False
    return '"log"' in head and '"entries"' in head


def _looks_like_introspection(path: Path) -> bool:
    if path.suffix.lower() != ".json":
        return False
    try:
        return "__schema" in path.read_text(encoding="utf-8", errors="ignore")[:4000]
    except Exception:  # noqa: BLE001
        return False


def ingest(paths: list[str | Path]) -> IngestResult:
    """Ingest a list of files and/or directories into a unified registry."""
    registry = EndpointRegistry()
    seq = SequenceMap()
    result = IngestResult(registry=registry, sequence_map=seq)

    files: list[Path] = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files.extend(sorted(f for f in p.rglob("*") if f.is_file()))
        elif p.is_file():
            files.append(p)
        else:
            result.notes.append(f"Skipped (not found): {p}")

    # Stage 1 first (specs), then behavioral sources, so shadow detection works.
    specs = [f for f in files if _looks_like_openapi(f)]
    gql_sdl = [f for f in files if f.suffix.lower() in {".graphql", ".gql"}]
    introspection = [f for f in files if f not in specs and _looks_like_introspection(f)]
    hars = [f for f in files if f not in specs and f not in introspection and _looks_like_har(f)]
    burps = [f for f in files if f.suffix.lower() == ".xml"]
    js = [f for f in files if f.suffix.lower() in {".js", ".mjs", ".cjs"}]

    for f in specs:
        n = _openapi.parse_openapi(f, registry)
        result.notes.append(f"OpenAPI {f.name}: {n} endpoints")
    for f in gql_sdl:
        n = _graphql.parse_graphql_sdl(f, registry)
        result.notes.append(f"GraphQL SDL {f.name}: {n} operations")
    for f in introspection:
        try:
            n = _graphql.parse_graphql_introspection(f, registry)
            result.notes.append(f"GraphQL introspection {f.name}: {n} operations")
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"GraphQL introspection {f.name}: parse failed ({exc})")
    for f in hars:
        n = parse_har(f, registry, seq)
        result.notes.append(f"HAR {f.name}: {n} requests")
    for f in burps:
        try:
            n = parse_burp_xml(f, registry, seq)
            result.notes.append(f"Burp XML {f.name}: {n} requests")
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"Burp XML {f.name}: parse failed ({exc})")
    for f in js:
        info = _jsbundle.parse_js_bundle(f, registry)
        result.notes.append(
            f"JS {f.name}: {info['endpoints_added']} shadow paths"
            + (f", {len(info['possible_secrets'])} possible secret(s)" if info["possible_secrets"] else "")
        )
        result.secrets.extend(info["possible_secrets"])

    reconcile_shadow(registry)
    logger.info("Ingestion complete: %d endpoints from %d files", len(registry), len(files))
    return result
