"""
Context budgeting for free / small-context LLM tiers.

Free NIM tiers reject very long messages, so VENOM never sends raw HTML or giant
JSON dumps to a model. Everything an agent sees is trimmed and HTML is compacted
to its security-relevant skeleton (forms, inputs, links, visible text) first.

Tunable via VENOM_LLM_MAX_CHARS (per-message budget; default 6000).
"""

from __future__ import annotations

import os
import re

MAX_CHARS = int(os.getenv("VENOM_LLM_MAX_CHARS", "6000"))

_TAG = re.compile(r"(?is)<[^>]+>")
_SCRIPT = re.compile(r"(?is)<(script|style|svg|noscript)[^>]*>.*?</\1>")
_WS = re.compile(r"\s+")
_FORM = re.compile(r"(?is)<form\b[^>]*>.*?</form>")
_INPUT = re.compile(r'(?is)<(?:input|select|textarea|button)\b[^>]*>')
# Tolerant of quoted AND unquoted attributes (PortSwigger HTML uses unquoted).
_ATTR = re.compile(r"""([\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s">]+))""")
_HREF = re.compile(r"""(?i)href\s*=\s*(?:"([^"#]+)"|'([^'#]+)'|([^\s">]+))""")


def _attrs(tag_html: str) -> dict:
    return {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "")
            for m in _ATTR.finditer(tag_html)}


def trim(text: str | None, limit: int = MAX_CHARS) -> str | None:
    """Head+tail truncation with a marker, so both ends stay visible."""
    if text is None or len(text) <= limit:
        return text
    head = int(limit * 0.7)
    tail = max(0, limit - head - 40)
    return f"{text[:head]}\n...[{len(text) - limit} chars trimmed]...\n{text[-tail:]}"


def _form_skeleton(form_html: str) -> dict:
    attrs = _attrs(form_html.split(">", 1)[0])
    fields = []
    for tag in _INPUT.findall(form_html):
        a = _attrs(tag)
        if a.get("name"):
            fields.append({"name": a["name"], "type": a.get("type", "text"),
                           "value": a.get("value", "")})
    return {"action": attrs.get("action", ""), "method": (attrs.get("method") or "GET").upper(),
            "fields": fields}


def compact_html(html: str | None, *, max_forms: int = 6, max_links: int = 30,
                 text_limit: int = 1200) -> dict:
    """Reduce an HTML page to a compact, security-relevant skeleton."""
    if not html:
        return {}
    cleaned = _SCRIPT.sub(" ", html)
    forms = [_form_skeleton(f) for f in _FORM.findall(cleaned)[:max_forms]]
    links = sorted({(m.group(1) or m.group(2) or m.group(3)) for m in _HREF.finditer(cleaned)})[:max_links]
    text = _WS.sub(" ", _TAG.sub(" ", cleaned)).strip()
    return {"forms": forms, "links": links, "text": trim(text, text_limit)}


def budget_messages(messages: list[dict], limit: int = MAX_CHARS) -> list[dict]:
    """Trim each message's content to the per-message budget (non-destructive copy)."""
    out = []
    for m in messages:
        c = m.get("content", "")
        out.append({**m, "content": trim(c, limit) if isinstance(c, str) else c})
    return out
