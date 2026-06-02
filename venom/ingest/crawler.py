"""
Live discovery crawler (web-app mode). Given a target URL (and an authenticated
session), it walks the site within scope, extracts forms + links + parameters,
and registers them as endpoints — so VENOM can be pointed at a URL instead of
being hand-fed artifacts. Optional forced-browsing uses a bundled wordlist to
surface hidden/privileged paths (the raw material for access-control tests).

Pure stdlib HTML parsing (no extra dependency); every request is scope-guarded
and rate-limited like any other.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs

_PRICE_RE = re.compile(r"[\$£€]\s?([\d,]+\.\d{2})")
_CREDIT_RE = re.compile(r"store credit:\s*[\$£€]\s?([\d,]+\.\d{2})", re.IGNORECASE)


def _to_minor(s: str) -> int:
    return int(round(float(s.replace(",", "")) * 100))

from ..core.registry import Endpoint, EndpointRegistry, Parameter
from ..core.scope import Scope
from ..engine.http_client import ScopedClient

logger = logging.getLogger("venom.ingest.crawler")

WORDLIST = Path(__file__).resolve().parent.parent / "data" / "wordlists" / "common.txt"


class _FormLinkParser(HTMLParser):
    """Collects <a href>, <form> (action/method/inputs)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method") or "GET").upper(),
                         "inputs": []}
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            self._cur["inputs"].append({
                "name": a.get("name", ""), "type": a.get("type", "text"),
                "value": a.get("value", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _same_site(url: str, base_hosts: set[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in base_hosts


def _path_of(url: str) -> str:
    p = urlparse(url)
    return p.path or "/"


def _ref_of(url: str) -> str:
    """Relative ref INCLUDING the query string (so parameterized pages render)."""
    p = urlparse(url)
    return (p.path or "/") + (f"?{p.query}" if p.query else "")


def _register_form(registry: EndpointRegistry, base: str, page_url: str, form: dict) -> None:
    action = urljoin(page_url, form["action"] or page_url)
    params, defaults = [], {}
    for i in form["inputs"]:
        if not i["name"]:
            continue
        hidden = i["type"] == "hidden"
        params.append(Parameter(name=i["name"], location="form", type="string", required=not hidden))
        # Capture default values (productId, price, redir, ...) so we can replay
        # the exact form and tamper a single field — CSRF is re-scraped live.
        defaults[i["name"]] = i.get("value", "")
    ep = Endpoint(path=_path_of(action), method=form["method"], source=["crawl"],
                  parameters=params, form_defaults=defaults, discovered_on=_ref_of(page_url))
    # Hidden fields carrying price/role/id are prime tampering candidates.
    names = {i["name"].lower() for i in form["inputs"]}
    if names & {"price", "amount", "total", "quantity", "qty", "role", "is_admin", "userid", "user_id"}:
        ep.business_rule_tags.append("client_trust")
    registry.add(ep)


async def crawl(scope: Scope, registry: EndpointRegistry, *, seeds: list[str] | None = None,
                auth_state=None, transport=None, max_pages: int = 40,
                forced_browse: bool = True) -> dict:
    base = scope.authorized_base_urls[0]
    base_hosts = {(urlparse(b).hostname or "").lower() for b in scope.authorized_base_urls}
    seeds = seeds or ["/"]
    seen: set[str] = set()
    queue: deque[str] = deque(seeds)
    pages, forms_found = 0, 0

    async with ScopedClient(scope, base, role="crawler", transport=transport) as client:
        if auth_state is not None:
            client.apply_auth(auth_state)

        # Forced browsing: enqueue interesting wordlist paths up front.
        if forced_browse and WORDLIST.exists():
            for line in WORDLIST.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    queue.append("/" + line.lstrip("/"))

        while queue and pages < max_pages:
            ref = queue.popleft()                    # ref keeps its query string
            if ref in seen:
                continue
            seen.add(ref)
            url = urljoin(base + "/", ref.lstrip("/"))
            if not scope.is_url_in_scope(url):
                continue
            try:
                resp = await client.request("GET", ref, follow_redirects=True)
            except Exception as exc:  # noqa: BLE001 — scope or network
                logger.debug("crawl skip %s: %s", ref, exc)
                continue
            if resp is None or resp.status_code >= 400:
                continue
            pages += 1
            # Register the GET endpoint, capturing any query params it carries.
            q = urlparse(url).query
            qparams = [Parameter(name=k, location="query", type="string") for k in parse_qs(q)]
            registry.add(Endpoint(path=_path_of(url), method="GET", source=["crawl"],
                                  parameters=qparams))

            ctype = resp.headers.get("content-type", "")
            if "html" not in ctype.lower():
                continue

            # Capture shop intelligence: product prices + the buyer's store credit.
            pid = parse_qs(q).get("productId", [None])[0]
            if pid:
                m = _PRICE_RE.search(resp.text)
                if m:
                    try:
                        registry.catalog[pid] = _to_minor(m.group(1))
                    except ValueError:
                        pass
            cm = _CREDIT_RE.search(resp.text)
            if cm:
                try:
                    registry.store_credit = _to_minor(cm.group(1))
                except ValueError:
                    pass

            parser = _FormLinkParser()
            try:
                parser.feed(resp.text)
            except Exception:  # noqa: BLE001
                continue
            for form in parser.forms:
                _register_form(registry, base, url, form)
                forms_found += 1
            for href in parser.links:
                nxt = urljoin(url, href)
                if not (_same_site(nxt, base_hosts) and scope.is_url_in_scope(nxt)):
                    continue
                nref = _ref_of(nxt)                  # follow links WITH their query
                if nref not in seen:
                    queue.append(nref)

    logger.info("Crawl complete: %d pages, %d forms, %d endpoints", pages, forms_found, len(registry))
    return {"pages": pages, "forms": forms_found, "endpoints": len(registry)}
