"""
VENOM — Context-aware business-logic penetration testing agent.

Runtime implementation of the CIPHER system prompt: ingest application context,
reconstruct the intended business model, generate adversarial test cases, execute
them safely within an authorized scope, and report confirmed findings.

Every outbound request passes through the scope guard (venom.core.scope). There
is no code path that reaches the network without an authorized, unexpired scope.
"""

__version__ = "0.1.0"

from .core.scope import Scope, ScopeError

__all__ = ["Scope", "ScopeError", "__version__"]
