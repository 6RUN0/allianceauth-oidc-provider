"""Django AppConfig for the OIDC provider."""

import logging

from django.apps import AppConfig
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _
from typing_extensions import override

from . import __version__

logger = logging.getLogger(f"extensions.{__name__}")


def _apply_default_oauth2_provider_settings() -> None:
    """
    Default-on the OIDC RP-Initiated Logout endpoint.

    DOT's stock ``OIDC_RP_INITIATED_LOGOUT_ENABLED`` defaults to
    ``False`` (see ``oauth2_provider.settings.DEFAULTS``). That value
    gates BOTH the ``/o/logout/`` route AND DOT's
    ``end_session_endpoint`` advertising in discovery. Our
    :class:`AllianceAuthDiscoveryView` already emits
    ``backchannel_logout_supported=True``; advertising back-channel
    logout without RP-initiated end-session is a half-paved street —
    RP libraries can feature-detect on it but have no URL to call.

    ``setdefault`` preserves operator opt-out: an explicit
    ``OAUTH2_PROVIDER["OIDC_RP_INITIATED_LOGOUT_ENABLED"] = False``
    is respected and stays ``False``; only the absent-key case gets
    the ``True`` default. The companion ``…_ALWAYS_PROMPT`` flag
    stays at DOT's default (``True``) — surfacing a confirm-and-
    submit page to the end user is the safer posture; deployers who
    want silent logout opt in explicitly via the same
    ``OAUTH2_PROVIDER`` dict.

    ``oauth2_settings`` is synced after the dict edit because DOT's
    ``OAuth2ProviderSettings`` is a lazy reader that caches each
    attribute on first access. A dict mutation alone would not
    propagate once an earlier app's ``ready()`` has already touched
    the attribute.
    """
    from django.conf import settings

    provider = getattr(settings, "OAUTH2_PROVIDER", None)
    if not isinstance(provider, dict):
        # No DOT configuration at all — nothing to default-on against.
        # Letting the import below run would still no-op cleanly, but
        # the early return makes the intent legible.
        return
    provider.setdefault("OIDC_RP_INITIATED_LOGOUT_ENABLED", True)
    try:
        from oauth2_provider.settings import oauth2_settings
    except ImportError:
        # DOT not installed yet (extremely degraded import order — the
        # app config wouldn't even load without DOT). Logged at warning
        # so the absence is visible in startup logs.
        logger.warning(
            "OIDC: oauth2_provider not importable; "
            "OIDC_RP_INITIATED_LOGOUT_ENABLED default not synced.",
        )
        return
    # DOT's ``OAuth2ProviderSettings`` exposes settings via a
    # ``__getattr__``-driven lazy reader, so basedpyright flags a
    # direct attribute assignment as ``reportAttributeAccessIssue``.
    # ``setattr`` with a variable attr name is the cleanest
    # cross-checker path: it bypasses basedpyright's static lookup
    # AND ruff's ``B010`` (which only fires on a *constant* attr in
    # ``setattr``). Runtime behaviour is identical.
    attr_name = "OIDC_RP_INITIATED_LOGOUT_ENABLED"
    setattr(oauth2_settings, attr_name, provider[attr_name])


def _connect_bcl_pre_save_gate() -> None:
    """
    Register a ``pre_save`` gate on :class:`AllianceAuthApplication`
    so non-admin write paths cannot bypass the BCL SSRF validator.

    Django's ``full_clean()`` (and therefore ``clean()``) is invoked
    automatically by ``ModelForm`` saves, but NOT by
    ``Application.objects.create(...)`` / ``Application(...).save()``
    / ``fixtures`` / ``data migrations``. Without this signal, an
    operator who registers a BCL URI through a non-admin code path
    bypasses the public-IP requirement and the
    ``_validate_no_nul_in_uri_fields`` gate.

    The signal-side gate runs ONLY when
    ``backchannel_logout_uri`` is non-empty so the typical
    ``Application.save()`` under the OAuth code-exchange path (which
    never touches BCL fields) pays no DNS cost. The validator itself
    is non-blocking on transient DNS failures (per AC-3b) — so a
    flaky resolver does not break unrelated app saves.

    ``weak=False`` keeps the receiver alive past local scope (the
    closure would otherwise be garbage-collected after ``ready()``
    returns). ``dispatch_uid`` makes the wire-up idempotent across
    test reloads.
    """
    from django.db.models.signals import pre_save
    from django.dispatch import receiver

    @receiver(
        pre_save,
        sender="allianceauth_oidc.AllianceAuthApplication",
        dispatch_uid="allianceauth_oidc.bcl_uri_save_gate",
        weak=False,
    )
    def _enforce(  # pyright: ignore[reportUnusedFunction]
        sender,  # noqa: ARG001
        instance,
        **kwargs,  # noqa: ARG001
    ) -> None:
        if getattr(instance, "backchannel_logout_uri", ""):
            instance._validate_uri_target_safety()  # noqa: SLF001


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

    Detection is by object identity against
    :func:`allianceauth_oidc.tokens.dispatching_access_token_generator`.
    Operator wrappers that wrap our dispatcher are legitimately a
    different callable and will produce an advisory WARNING — silence
    the line via the standard ``logging`` configuration on the
    ``extensions.allianceauth_oidc.apps`` logger if the wrapper is
    intentional. A formatted ``module.qualname`` is still emitted in
    the message so operators can see what DOT actually loaded.

    Public name (no leading underscore on the docstring level)
    despite the ``_`` prefix on the symbol — the function is
    importable for direct testing under ``override_settings`` (see
    ``tests/test_jwt_validation.py::TestStartupWiringCheck``).
    """
    try:
        from oauth2_provider.settings import oauth2_settings

        from .tokens import dispatching_access_token_generator

        default_format = oauth2_settings.user_settings.get(
            "ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT", "opaque"
        )
        if default_format != "jwt":
            return
        expected = (
            "allianceauth_oidc.tokens.dispatching_access_token_generator"
        )
        actual = oauth2_settings.ACCESS_TOKEN_GENERATOR
        if actual is dispatching_access_token_generator:
            return
        if actual is None:
            actual_name = "<None>"
        elif callable(actual):
            actual_name = (
                f"{getattr(actual, '__module__', '')}."
                f"{getattr(actual, '__qualname__', '')}"
            )
        else:
            actual_name = str(actual)
        logger.warning(
            "OIDC: ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT='jwt' but OAUTH2_PROVIDER['ACCESS_TOKEN_GENERATOR'] is %a (expected %a). JWT mode will NOT be active. See README opt-in section.",  # noqa: E501
            actual_name,
            expected,
        )
    except Exception:  # noqa: BLE001
        # Diagnostic check, not a hard error: an ImportError or a
        # bogus ACCESS_TOKEN_GENERATOR dotted-path string would land
        # here. Catching ``Exception`` is intentional: any failure
        # in a non-blocking startup advisory is preferable to
        # crashing app load, and a narrower handler would risk
        # missing the "DOT's ``perform_import`` raised something we
        # didn't predict" branch. ``logger.warning`` with
        # ``exc_info=True`` keeps the full traceback for operator
        # debugging without dumping a red-text exception line into
        # the startup log for what is supposed to be a non-fatal
        # advisory. Operators who want JWT-mode misconfiguration
        # to be a startup-blocker should configure a system check,
        # not lean on this diagnostic.
        logger.warning(
            "OIDC: JWT-wiring check skipped due to exception",
            exc_info=True,
        )


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
        from . import (
            checks,
            receivers,
        )
        from ._metrics import connect_metrics_receivers
        from .app_settings import connect_invalidator
        from .logout import dispatch_backchannel_logout
        from .signals import (
            connect_default_code_reuse_receiver,
            connect_default_introspect_receiver,
            connect_default_logout_receiver,
            connect_default_receiver,
        )

        # Importing ``checks`` runs the ``@register`` decorator that
        # wires ``allianceauth_oidc.E001`` into Django's system-check
        # framework — the module is "used" for that side effect.
        # Touch a public attribute so pyright doesn't flag the import
        # as unused; ``E001_ID`` is the public id constant.
        _ = checks.E001_ID
        connect_default_receiver()
        connect_default_code_reuse_receiver()
        connect_default_introspect_receiver()
        connect_default_logout_receiver(dispatch_backchannel_logout)
        receivers.connect_all()
        connect_invalidator()
        # Always wire the metrics receivers — when django-prometheus
        # is absent the receivers run but every metric call is a
        # no-op stub, which preserves a single startup path and keeps
        # the receiver chain testable without conditional fixtures.
        connect_metrics_receivers()
        # Apply settings defaults BEFORE the JWT-wiring advisory so
        # both helpers observe the same final oauth2_settings state.
        _apply_default_oauth2_provider_settings()
        _check_jwt_wiring()
        _connect_bcl_pre_save_gate()
