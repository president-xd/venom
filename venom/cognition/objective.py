"""
The engagement Objective — what "success" means, made checkable on ANY web app.

Real-world business-logic wins are not lab banners ("is-solved"). They are
*state transitions*: a forbidden action becomes possible, a protected resource
becomes reachable, a value changes that shouldn't. So the primary oracle is
DIFFERENTIAL — it performs the win action and compares against a baseline taken
before exploitation:

    win  ==  (the win action FAILED as the un-escalated user)   [baseline]
         and (the win action SUCCEEDS after the exploit)         [post]

This needs no product-specific string. A marker mode is kept ONLY for targets
where the operator EXPLICITLY describes success as a substring (success_text or
win_signals). Crucially, there are NO product-baked default signals: VENOM never
assumes a PortSwigger-style "is-solved" banner on an unknown app. If the operator
defines neither a win_action nor a marker, the objective cannot be auto-confirmed
(check() returns False) — an honest "unknown", not a false win.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# No baked-in lab/marker strings. Marker mode activates only when the operator
# supplies success_text or win_signals explicitly.
_DEFAULT_SIGNALS: tuple[str, ...] = ()
_SUCCESS_STATUS = (200, 201, 202, 204, 302, 303)


@dataclass
class Objective:
    description: str = "achieve the engagement objective"
    # Primary, app-agnostic oracle: a concrete win action + what success looks like.
    win_action: dict | None = None          # {"method","path","data"?} — the forbidden op
    success_status: tuple[int, ...] = _SUCCESS_STATUS
    success_text: str = ""                   # optional substring proving the op worked
    failure_text: str = ""                   # optional substring proving it was blocked
    # Legacy fallback (no win_action): fetch a URL and look for a marker.
    win_url: str = "/"
    win_signals: tuple[str, ...] = _DEFAULT_SIGNALS

    async def _run_win_action(self, toolbox) -> tuple[bool, int | None]:
        """Perform the win action once; return (looks_successful, status)."""
        a = self.win_action or {}
        method = (a.get("method") or "GET").upper()
        path = a.get("path") or self.win_url
        if method == "GET":
            r = await toolbox.http_get(path)
        else:
            r = await toolbox.http_post_form(path, a.get("data") or {})
        status = (r.data or {}).get("status")
        text = (toolbox.last_text or "").lower()
        ok = status in self.success_status
        if ok and self.success_text:
            ok = self.success_text.lower() in text
        if ok and self.failure_text and self.failure_text.lower() in text:
            ok = False
        return ok, status

    async def baseline(self, toolbox) -> bool:
        """Whether the win action ALREADY works before exploitation (then it's not a flaw)."""
        if not self.win_action:
            return False
        ok, _ = await self._run_win_action(toolbox)
        return ok

    async def check(self, toolbox) -> bool:
        """True if the objective is currently met.

        Primary: the differential win action succeeds. Fallback: an operator-DEFINED
        marker (success_text / win_signals) appears at win_url. With neither defined
        we return False — VENOM does not guess at success via baked-in lab strings."""
        if self.win_action:
            ok, _ = await self._run_win_action(toolbox)
            return ok
        markers = tuple(s for s in self.win_signals if s)
        if not (markers or self.success_text):
            return False                       # nothing the operator defined as "won"
        await toolbox.http_get(self.win_url)
        text = (toolbox.last_text or "").lower()
        if self.success_text and self.success_text.lower() in text:
            return True
        return any(s.lower() in text for s in markers)

    @classmethod
    def from_scope(cls, scope, fallback: str = "") -> "Objective":
        obj = dict(getattr(scope, "objective", {}) or {})
        return cls(
            description=obj.get("description") or fallback or "achieve the engagement objective",
            win_action=obj.get("win_action"),
            success_status=tuple(obj.get("success_status", _SUCCESS_STATUS)),
            success_text=obj.get("success_text", ""),
            failure_text=obj.get("failure_text", ""),
            win_url=obj.get("win_url", "/"),
            win_signals=tuple(obj.get("win_signals", ())),   # no baked-in defaults
        )
