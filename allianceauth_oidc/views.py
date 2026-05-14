"""
Public view re-exports.

The views layer was originally a single ``views.py``; it grew past
~800 lines covering three independent endpoints (token, authorize,
discovery) that never share code with each other. Splitting them
into three sibling modules — ``views_token`` / ``views_authorize`` /
``views_discovery`` — keeps each file focused on one HTTP entry
point. They sit at the same level as the rest of the package so
sibling-relative imports (``from .signals import ...`` etc.) stay
homogeneous with every other module.

External callers (``urls.py``, tests, the operator-facing admin
command) keep importing from ``allianceauth_oidc.views`` — this
module re-exports the same names so the split is transparent to
them.

Tests pinning ``extensions.allianceauth_oidc.views`` for log
assertions continue to capture records from the new submodule
loggers (``views_token`` / ``views_authorize``): they live at the
same hierarchy level and assertLogs's parent capture covers
``extensions.allianceauth_oidc.*`` via propagation. Tests that filter
captured records by ``LogRecord.name`` need to widen the predicate
to include the sibling-named loggers — see ``tests/test_logging``.
"""

from __future__ import annotations

from .views_authorize import AuthAuthorizationView
from .views_discovery import AllianceAuthDiscoveryView
from .views_token import TokenAudit, TokenView, classify_token_format

__all__ = [
    "AllianceAuthDiscoveryView",
    "AuthAuthorizationView",
    "TokenAudit",
    "TokenView",
    "classify_token_format",
]
