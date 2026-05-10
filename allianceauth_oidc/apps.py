"""Django AppConfig for the OIDC provider."""

import logging

from django.apps import AppConfig
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _
from typing_extensions import override

from . import __version__

logger = logging.getLogger(f"extensions.{__name__}")


def _check_jwt_wiring() -> None:
    """
    Log a warning when JWT mode is on but the dispatcher is missing.

    Mitigates the "operator activated JWT mode but forgot to wire
    ``ACCESS_TOKEN_GENERATOR``" failure mode (Pre-mortem Scenario 4
    in ``.omc/plans/jwt-access-tokens-plan-v3.md``). SAFE-by-design:
    log-only, no settings mutation. Wrapped in ``try/except`` because
    reading ``oauth2_settings.ACCESS_TOKEN_GENERATOR`` triggers DOT's
    ``perform_import`` (``oauth2_provider/settings.py``); a bogus
    dotted-path string would raise ``ImportError`` here, and a
    diagnostic helper that crashes app startup is worse than the
    failure mode it's diagnosing.

    The substring identity match is advisory — operator wrappers
    around :func:`allianceauth_oidc.tokens.dispatching_access_token_generator`
    legitimately produce a non-matching ``__qualname__`` (and a
    false-positive WARNING). Operators with custom wrappers can
    silence the line via the standard ``logging`` configuration on
    the ``extensions.allianceauth_oidc.apps`` logger.

    Public name (no leading underscore on the docstring level)
    despite the ``_`` prefix on the symbol — the function is
    importable for direct testing under ``override_settings`` (see
    ``tests/test_jwt_access_tokens.py::TestStartupWiringCheck``).
    """
    try:
        from django.conf import settings
        from oauth2_provider.settings import oauth2_settings

        provider = getattr(settings, "OAUTH2_PROVIDER", {}) or {}
        default_format = provider.get(
            "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT", "opaque"
        )
        if default_format != "jwt":
            return
        expected = (
            "allianceauth_oidc.tokens.dispatching_access_token_generator"
        )
        actual = oauth2_settings.ACCESS_TOKEN_GENERATOR
        if actual is None:
            actual_name = "<None>"
        elif callable(actual):
            actual_name = (
                f"{getattr(actual, '__module__', '')}."
                f"{getattr(actual, '__qualname__', '')}"
            )
        else:
            actual_name = str(actual)
        if expected not in actual_name:
            logger.warning(
                "OIDC: ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT='jwt' but OAUTH2_PROVIDER['ACCESS_TOKEN_GENERATOR'] is %a (expected %a). JWT mode will NOT be active. See README opt-in section.",  # noqa: E501
                actual_name,
                expected,
            )
    except Exception:
        # ``logger.exception`` already attaches the traceback; the
        # explicit message keeps log lines greppable per the existing
        # ``OIDC: ...`` prefix convention used elsewhere in the
        # module.
        logger.exception("OIDC: JWT-wiring check skipped due to exception")


class AllianceAuthOIDC(AppConfig):
    """Connects the ``oidc_token_issued`` audit receiver on app load."""

    name = "allianceauth_oidc"
    label = "allianceauth_oidc"

    # ``format_lazy`` keeps the verbose_name translation lazy so the
    # admin renders it in the active language at request time, not the
    # language that happened to be active at import.
    verbose_name = format_lazy(
        _("Alliance Auth OIDC v{version}"),
        version=__version__,
    )

    @override
    def ready(self):
        """Wire OIDC signals + cache invalidators on app load."""
        # Explicit connect calls — see ``signals.connect_default_receiver``
        # and ``app_settings.connect_invalidator`` for why these are
        # not side-effects on module import.
        from .app_settings import connect_invalidator
        from .signals import connect_default_receiver

        connect_default_receiver()
        connect_invalidator()
        _check_jwt_wiring()
