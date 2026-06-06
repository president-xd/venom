"""
Behavioral ingestion (Stage 2) - HAR captures and Burp Suite XML exports.

Endpoints seen in traffic but absent from the OpenAPI spec are marked as shadow
endpoints (highest-priority targets). A simple sequence map records which
endpoints follow which in observed user flows.
"""

from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

from ..core.registry import Endpoint, EndpointRegistry

# Path segments that look like IDs get normalized to {id} so we can merge
# /orders/123 and /orders/456 into one endpoint template.
_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONGHEX = re.compile(r"^[0-9a-fA-F]{16,}$")


def _templatize(path: str) -> str:
    parts = []
    for seg in path.split("/"):
        if _NUMERIC.match(seg) or _UUID.match(seg) or _LONGHEX.match(seg):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/".join(parts)


class SequenceMap:
    """Directed counts of endpoint-key -> next endpoint-key within a flow."""

    def __init__(self) -> None:
        self.edges: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def record(self, ordered_keys: list[str]) -> None:
        for a, b in zip(ordered_keys, ordered_keys[1:]):
            self.edges[a][b] += 1

    def to_dict(self) -> dict:
        return {a: dict(nxt) for a, nxt in self.edges.items()}


def _ingest_entries(entries: list[tuple[str, str, list[str]]],
                    registry: EndpointRegistry,
                    seq: SequenceMap) -> int:
    """entries: list of (method, url, observed_roles). Returns count added."""
    flow_keys: list[str] = []
    added = 0
    for method, url, roles in entries:
        parsed = urlparse(url)
        path = _templatize(parsed.path) or "/"
        ep = Endpoint(
            path=path,
            method=method.upper(),
            source=["traffic"],
            roles_observed=list(roles),
            shadow_endpoint=True,  # provisional; cleared if spec also defines it
        )
        registry.add(ep)
        flow_keys.append(ep.key)
        added += 1
    seq.record(flow_keys)
    return added


def parse_har(path: str | Path, registry: EndpointRegistry, seq: SequenceMap) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = []
    for e in data.get("log", {}).get("entries", []):
        req = e.get("request", {})
        method, url = req.get("method", "GET"), req.get("url", "")
        if not url:
            continue
        # Pull an Authorization/role hint if present (best-effort, never logged).
        roles = []
        for h in req.get("headers", []):
            if h.get("name", "").lower() == "x-role":
                roles.append(h.get("value", ""))
        entries.append((method, url, roles))
    return _ingest_entries(entries, registry, seq)


def parse_burp_xml(path: str | Path, registry: EndpointRegistry, seq: SequenceMap) -> int:
    """Parse a Burp Suite 'Save items' XML export (<items><item>...)."""
    root = ET.parse(Path(path)).getroot()
    entries = []
    for item in root.findall("item"):
        url = (item.findtext("url") or "").strip()
        method = (item.findtext("method") or "GET").strip()
        if not url:
            continue
        # Burp stores request base64-encoded; we only need method+url here.
        req_el = item.find("request")
        if req_el is not None and req_el.get("base64") == "true" and not method:
            try:
                raw = base64.b64decode(req_el.text or "").decode("latin-1", "ignore")
                method = raw.split(" ", 1)[0] or "GET"
            except Exception:  # noqa: BLE001
                method = "GET"
        entries.append((method, url, []))
    return _ingest_entries(entries, registry, seq)


def reconcile_shadow(registry: EndpointRegistry) -> None:
    """Any endpoint whose source includes 'openapi' is NOT a shadow endpoint."""
    for ep in registry:
        if "openapi" in ep.source:
            ep.shadow_endpoint = False
        ep.tag()
