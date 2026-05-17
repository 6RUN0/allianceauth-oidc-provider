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

from .security import DEFAULT_POLICY, resolve_per_app_setting


def per_app_pkce_required(client_id: str | None) -> bool:
    """
    Adapter — DOT references this directly via
    ``OAUTH2_PROVIDER['PKCE_REQUIRED']``.

    Resolves ``client_id`` to an ``AllianceAuthApplication`` row and
    delegates to :meth:`security.AccessPolicy.requires_pkce` for the
    decision. Unknown / ``None`` / empty ``client_id`` falls back to
    ``True`` per RFC 9700 (an unknown client must always take the
    strict path) with a log line at ``WARNING`` so anomalous traffic
    is visible in the audit trail.

    The recipe (column-narrowed query → DoesNotExist fail-safe with
    one WARNING log → delegate to policy) lives in
    :func:`security.resolve_per_app_setting` so this adapter and the
    sibling JWT-format adapter (:func:`tokens._resolve_access_token_format`)
    cannot drift on the contract.

    ``OAUTH2_PROVIDER['PKCE_REQUIRED']`` must be assigned the function
    object, not a dotted-path string. DOT does **not** auto-import this
    setting — see ``oauth2_provider/settings.py`` (``IMPORT_STRINGS``)
    and ``oauth2_validators.py`` (``is_pkce_required``).
    """
    return resolve_per_app_setting(
        client_id,
        field="pkce_required",
        policy_method=DEFAULT_POLICY.requires_pkce,
        fail_safe_default=True,
        log_prefix="OIDC PKCE",
    )
