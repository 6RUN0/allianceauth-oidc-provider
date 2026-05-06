"""
DOT-facing PKCE adapter for ``OAUTH2_PROVIDER['PKCE_REQUIRED']``.

This module is intentionally tiny: operators import
``per_app_pkce_required`` from inside their Django settings module,
which Django evaluates BEFORE ``apps.populate()`` runs. Anything this
module pulls in transitively must stay clear of Django models and
``oauth2_provider`` validators (both of which require the apps
registry).

``security`` is safe because the policy class no longer touches the
ORM; the model import below is deferred to call time, after
``django.setup()``.
"""

from __future__ import annotations

import logging

from .security import DEFAULT_POLICY

logger = logging.getLogger(f"extensions.{__name__}")


def per_app_pkce_required(client_id: str | None) -> bool:
    """
    Adapter — DOT references this directly via
    ``OAUTH2_PROVIDER['PKCE_REQUIRED']``.

    Resolves ``client_id`` to an ``AllianceAuthApplication`` row and
    delegates to :meth:`security.AccessPolicy.pkce_required` for the
    decision. Unknown / ``None`` / empty ``client_id`` falls back to
    ``True`` per RFC 9700 (an unknown client must always take the
    strict path) with a log line at ``WARNING`` so anomalous traffic
    is visible in the audit trail.

    The query is bounded to ``pkce_required`` via ``.only(...)`` because
    this hook runs on every authorize / token request.

    The unknown-client log uses ``%a`` (ASCII repr) rather than ``%r``:
    ``client_id`` arrives unsanitised from an HTTP parameter and
    ``%r`` would let stray newline / ANSI escapes flow into log
    storage.

    ``OAUTH2_PROVIDER['PKCE_REQUIRED']`` must be assigned the function
    object, not a dotted-path string. DOT does **not** auto-import this
    setting — see ``oauth2_provider/settings.py`` (``IMPORT_STRINGS``)
    and ``oauth2_validators.py`` (``is_pkce_required``).
    """
    from .models import AllianceAuthApplication

    try:
        app = AllianceAuthApplication.objects.only("pkce_required").get(
            client_id=client_id
        )
    except AllianceAuthApplication.DoesNotExist:
        logger.warning(
            "OIDC PKCE: unknown client_id=%a -> fail-safe True", client_id
        )
        return True
    return DEFAULT_POLICY.pkce_required(app)
