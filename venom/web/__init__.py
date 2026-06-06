"""
VENOM web console - a thin HTTP layer over the real engagement engine.

This package is *additive*: it only consumes the existing engine (scope guard,
``run_engagement``, the knowledge base, the provider router) and never weakens
any safety boundary. The server is std-lib ``http.server`` (same shape as
``vulnlab/app.py::serve``) so it adds no runtime dependency.

  - server.py   : ThreadingHTTPServer - static UI + JSON API + SSE run stream
  - routes.py   : pure request router (unit-testable, no socket I/O)
  - api.py      : JSON handlers backed by real venom modules
  - runs.py     : RunManager - launches real engagements, streams their trace
  - mappers.py  : engine objects -> the exact shapes the React UI expects
"""

from __future__ import annotations

from .server import serve

__all__ = ["serve"]
