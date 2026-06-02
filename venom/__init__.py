"""
VENOM — Context-aware business-logic penetration testing agent.

Ingests application context, reconstructs the intended business model, generates
adversarial test cases, executes them safely within an authorized scope, and
reports confirmed findings.

Every outbound request passes through the scope guard (venom.core.scope). There
is no code path that reaches the network without an authorized, unexpired scope.
"""

__version__ = "0.1.0"

from .core.scope import Scope, ScopeError

__all__ = ["Scope", "ScopeError", "__version__"]
