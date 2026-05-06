"""
DOT-facing PKCE adapter for ``OAUTH2_PROVIDER['PKCE_REQUIRED']``.

This module is intentionally tiny: operators import
``per_app_pkce_required`` from inside their Django settings module,
which Django evaluates BEFORE ``apps.populate()`` runs. Anything this
module pulls in transitively must stay clear of Django models and
``oauth2_provider`` validators (both of which require the apps
registry).

``security`` is safe because it only does the ORM lookup inside method
bodies (deferred to call time, after ``django.setup()``).
"""

from .security import DEFAULT_POLICY


def per_app_pkce_required(client_id: str) -> bool:
    """
    Adapter — DOT references this directly via
    ``OAUTH2_PROVIDER['PKCE_REQUIRED']``.

    Delegates to :meth:`security.AccessPolicy.pkce_required` so the
    decision body lives next to the rest of the access policy
    (``decide / is_allowed / enforce``) and benefits from the same DI
    seam (injected logger, ``AppLike`` Protocol).

    ``OAUTH2_PROVIDER['PKCE_REQUIRED']`` must be assigned the function
    object, not a dotted-path string. DOT does **not** auto-import this
    setting — see ``oauth2_provider/settings.py`` (``IMPORT_STRINGS``)
    and ``oauth2_validators.py`` (``is_pkce_required``).
    """
    return DEFAULT_POLICY.pkce_required(client_id)
