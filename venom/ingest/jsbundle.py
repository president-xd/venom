"""
JavaScript bundle ingestion (Stage 2) — extract "shadow endpoints": URL paths
referenced by the frontend that may not appear in any official spec, plus
fetch/axios/XHR call sites and likely-hardcoded secrets.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..core.registry import Endpoint, EndpointRegistry

# API-ish path literals: "/api/v1/orders", "/v2/wallet/withdraw", etc.
_PATH_LITERAL = re.compile(r"""["'`](/(?:api/|v\d+/|graphql|internal/|admin/)[A-Za-z0-9_\-/{}.:]*)["'`]""")
_CALL_URL = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|axios|XMLHttpRequest[^;]*?\.open)\s*\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)
# Loud secret patterns (best-effort; never printed in full).
_SECRET = re.compile(
    r"""(sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"""
)
_METHOD_HINT = re.compile(r"""axios\.(get|post|put|patch|delete)""", re.IGNORECASE)


def parse_js_bundle(path: str | Path, registry: EndpointRegistry) -> dict:
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    found_paths: set[str] = set()

    for m in _PATH_LITERAL.finditer(text):
        found_paths.add(m.group(1))
    for m in _CALL_URL.finditer(text):
        url = m.group(1)
        if url.startswith("/"):
            found_paths.add(url.split("?")[0])

    added = 0
    for p in sorted(found_paths):
        # We rarely know the verb from a literal; default GET, tag as shadow.
        ep = Endpoint(path=p, method="GET", source=["js_bundle"], shadow_endpoint=True)
        registry.add(ep)
        added += 1

    secrets = sorted({s[:6] + "…(redacted)" for s in _SECRET.findall(text)})
    return {
        "paths_found": len(found_paths),
        "endpoints_added": added,
        "possible_secrets": secrets,  # redacted previews only
    }
