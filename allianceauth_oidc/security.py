"""Per-user / per-application OIDC access policy checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final, Literal, Protocol, runtime_checkable

from django.core.exceptions import PermissionDenied

from .constants import PERM_ACCESS_OIDC

# This module intentionally uses getattr/callable checks:
# - these functions are called from multiple places (views/validators) and must
#   tolerate partially mocked objects in tests/integrations.
# - failures should become PermissionDenied, not AttributeError.

logger = logging.getLogger(f"extensions.{__name__}")


@runtime_checkable
class UserLike(Protocol):
    """
    Smallest shape ``AccessPolicy`` requires for a ``user`` argument.

    Django's ``User`` model satisfies this directly; ``AnonymousUser``
    satisfies it via its stub ``has_perm`` / ``is_authenticated`` /
    ``is_superuser``; test ``SimpleNamespace`` doubles satisfy it as
    long as they expose the three attrs listed below.

    ``profile`` and ``groups`` are NOT on this Protocol —
    ``AnonymousUser`` doesn't carry them, and ``_check_app`` reads
    them via ``getattr`` so a partial mock can still pass through
    the gate.

    ``runtime_checkable`` so ``isinstance(..., UserLike)`` works in
    ad-hoc debugging; it costs one extra structural check at the
    interpreter level but keeps the contract introspectable.
    """

    is_authenticated: bool
    is_superuser: bool

    def has_perm(self, perm: str) -> bool:
        """Standard Django permission gate — see ``User.has_perm``."""
        ...


@runtime_checkable
class AppLike(Protocol):
    """
    Shape of the ``app`` (client / application) argument to
    ``AccessPolicy._check_app``.

    All three fields are typed ``Any`` because django-stubs renders
    Django model fields as opaque descriptors
    (``BooleanField[Unknown, Unknown]``, ``ManyRelatedManager[...]``)
    that fail Protocol invariance against plain ``bool`` / ``Manager``
    annotations. ``Any`` keeps the Protocol value as documentation
    + ``isinstance`` runtime check while letting the static checker
    accept a concrete ``AllianceAuthApplication`` argument without a
    cast at every call site. The runtime semantics are unchanged:
    the policy only reads ``.debug_mode``, ``.states``, ``.groups``.
    """

    debug_mode: Any
    states: Any
    groups: Any
    pkce_required: Any


@runtime_checkable
class TokenLike(Protocol):
    """
    Smallest shape ``TokenAudit`` and ``audit_oidc_token_issued``
    require for an issued ``AccessToken``.

    Fields are typed ``Any`` for the same reason ``AppLike`` does:
    django-stubs renders FK descriptors and model managers as opaque
    objects that fail Protocol invariance against concrete types.
    ``Any`` keeps the Protocol as a typo-catching contract — a
    consumer accidentally reading ``token.applicaiton`` is rejected
    statically — without forcing casts on the producer side.
    """

    application: Any
    user: Any
    id: Any
    scope: Any


@runtime_checkable
class OAuthRequestLike(Protocol):
    """
    Shape of the oauthlib ``Request`` as DOT mutates it before
    handing it to validator methods.

    ``oauthlib`` does not ship type stubs; DOT adds ``application``
    dynamically on top of oauthlib's ``Request`` (the attribute is
    not declared on oauthlib's class). Capturing the four attrs we
    actually read (``user`` / ``client`` / ``application`` / ``POST``)
    here means a typo on the validator side surfaces as a Protocol
    mismatch at type-check time rather than ``AttributeError`` at
    request time.
    """

    user: Any
    client: Any
    application: Any
    POST: Any


class DenyReason(str, Enum):
    """
    Structured reason for an authorize-request denial.

    The values are stable identifiers safe for Prometheus labels,
    structured logs, and audit sinks — translated user-facing text
    lives at the rendering boundary (``views.py``), not on this enum.
    Mixin with ``str`` (instead of ``StrEnum``, 3.11+) keeps the floor
    at Python 3.10.
    """

    GLOBAL = "global"  # missing PERM_ACCESS_OIDC permission
    APP = "app"  # state/group restriction failed for the chosen app


@dataclass(frozen=True, slots=True)
class AllowedDecision:
    """
    The "request passes" branch of :data:`AccessDecision`.

    ``app`` is echoed back so the caller can render it without a
    second lookup; ``None`` when the request carried no
    ``client_id`` (DOT's ``AuthorizationView`` then surfaces the
    missing-client error itself).
    """

    app: AppLike | None
    allowed: Literal[True] = field(default=True, init=False)
    deny_reason: None = field(default=None, init=False)


@dataclass(frozen=True, slots=True)
class GlobalDeny:
    """
    Denial at the global ``access_oidc`` permission gate.

    ``app`` is intentionally pinned to ``None`` — anti-enumeration
    invariant: a global denial must NOT leak which application
    triggered the lookup back to the renderer (otherwise a malicious
    actor probing ``client_id``s could distinguish "client exists,
    you lack perm" from "client does not exist").
    """

    allowed: Literal[False] = field(default=False, init=False)
    deny_reason: Literal[DenyReason.GLOBAL] = field(
        default=DenyReason.GLOBAL, init=False
    )
    app: None = field(default=None, init=False)


@dataclass(frozen=True, slots=True)
class AppDeny:
    """
    Denial at the per-app state/group gate; ``app`` is non-None by
    construction so the renderer can show the app name.
    """

    app: AppLike
    allowed: Literal[False] = field(default=False, init=False)
    deny_reason: Literal[DenyReason.APP] = field(
        default=DenyReason.APP, init=False
    )


# Discriminated union: callers narrow either via ``decision.allowed``
# (boolean discriminator → AllowedDecision vs the two deny variants)
# or ``decision.deny_reason`` (Literal discriminator → GlobalDeny vs
# AppDeny). The invariant "deny_reason is APP ⇒ app is non-None" is
# now in the type, not in the logic — :func:`typing.assert_never` in
# ``AuthAuthorizationView.dispatch`` makes a future fourth variant a
# type-checker error rather than a silent fall-through.
AccessDecision = AllowedDecision | GlobalDeny | AppDeny


@dataclass(frozen=True, slots=True)
class AccessPolicy:
    """
    Three-form OIDC access policy with one source of truth.

    Three public methods cover the three call shapes the codebase
    needs:

    - ``decide(user, app) -> AccessDecision`` for views that branch on
      structured outcome (``AuthAuthorizationView.dispatch``).
    - ``is_allowed(user, app) -> bool`` for validators that just need
      a yes/no (``validate_code`` / ``validate_refresh_token`` via
      ``_enforce_policy``).
    - ``enforce(user, app) -> None`` for code paths that want the
      raise-form (``save_bearer_token`` translates the raise into
      ``InvalidGrantError``).

    Symmetric with ``ClaimsBuilder`` / ``TokenAudit`` / ``OIDCSettings``
    / ``SecretRedactor``: frozen dataclass with one optional injected
    dependency (``log``) so tests can capture warnings on a per-test
    logger without ``assertLogs`` on the module global.
    """

    log: logging.Logger = field(default=logger)

    # ---- helpers --------------------------------------------------

    @staticmethod
    def is_superuser(user: UserLike | None) -> bool:
        """Return whether ``user`` is a superuser (defensive against mocks)."""
        return getattr(user, "is_superuser", False)

    # ---- public API ------------------------------------------------

    def decide(
        self, user: UserLike | None, app: AppLike | None
    ) -> AccessDecision:
        """
        Evaluate the policy and return a structured decision.

        ``user=None`` is accepted (and treated as a global-deny via
        the ``has_perm`` callable check inside ``_check_global``):
        DOT validators occasionally hand us a stub request before
        auth middleware populates ``request.user``.
        """
        try:
            self._check_global(user)
        except PermissionDenied:
            return GlobalDeny()
        if app is None:
            return AllowedDecision(app=None)
        try:
            self._check_app(user, app)
        except PermissionDenied:
            return AppDeny(app=app)
        return AllowedDecision(app=app)

    def is_allowed(self, user: UserLike | None, app: AppLike | None) -> bool:
        """Convenience: ``decide(...).allowed``."""
        return self.decide(user, app).allowed

    def enforce(self, user: UserLike | None, app: AppLike | None) -> None:
        """
        Raise ``PermissionDenied`` if the decision is not allowed.

        ``deny_reason`` is folded into the exception message so log
        receivers and oauth-error translators can route on it.
        """
        decision = self.decide(user, app)
        if decision.allowed:
            return
        raise PermissionDenied(
            f"OIDC access denied (reason={decision.deny_reason})"
        )

    def requires_pkce(self, app: AppLike | None) -> bool:
        """
        Return whether PKCE is required for ``app``.

        Pure-logic counterpart to ``decide`` / ``is_allowed`` /
        ``enforce``: takes a pre-loaded ``AppLike`` and returns the
        ``pkce_required`` flag (default ``True`` if absent / ``None``,
        per RFC 9700 secure-by-default). ORM-resolution from a raw
        ``client_id`` lives in :mod:`allianceauth_oidc.pkce` (the DOT
        adapter) so the policy stays DI-testable with synthetic
        ``AppLike`` doubles.

        Verb-form name (``requires_pkce``) keeps the method out of
        identifier collision with ``AppLike.pkce_required`` — the
        attribute the method reads. ``policy.pkce_required`` would be
        ambiguous between "method on the policy" and "attribute on a
        captured app".
        """
        return bool(getattr(app, "pkce_required", True))

    # ---- internal building blocks (raise-form) --------------------

    def _check_global(self, user: UserLike | None) -> None:
        """
        Enforce the global ``access_oidc`` permission gate.

        Decision-level logging lives at the *callers* (``views.dispatch``
        for HTTP, ``auth_provider`` for validators); this method is a
        pure gate that raises ``PermissionDenied`` on failure. No log
        here would otherwise duplicate the caller's structured warning.
        """
        if self.is_superuser(user):
            return
        has_perm = getattr(user, "has_perm", None)
        # has_perm is the standard Django contract. If it's missing,
        # treat the object as an invalid user and deny access.
        if not callable(has_perm):
            raise PermissionDenied("Invalid user object (no has_perm)")
        if not has_perm(PERM_ACCESS_OIDC):
            raise PermissionDenied(f"Missing {PERM_ACCESS_OIDC} permission")

    def _check_app(self, user: UserLike | None, app: AppLike) -> None:
        """
        Enforce per-application state/group access for ``user``.

        Materialises the app's ``states`` / ``groups`` managers once
        each via ``list(...)`` so that consumers using
        ``prefetch_related("states", "groups")``
        (``views._get_app``) hit the prefetch cache instead of two
        round-trips per check (``exists()`` + ``filter().exists()``).
        Validator-path callers (no prefetch) still benefit: one
        SELECT all instead of one ``exists()`` plus one ``filter
        ... exists()``.
        """
        if self.is_superuser(user):
            return

        debug_mode = getattr(app, "debug_mode", False)
        app_states_mgr = getattr(app, "states", None)
        app_groups_mgr = getattr(app, "groups", None)

        # If the application doesn't look like the expected DOT model,
        # deny rather than accidentally allowing access.
        if app_states_mgr is None or app_groups_mgr is None:
            raise PermissionDenied(
                "Invalid application object (missing states/groups)"
            )

        # Materialise once: with prefetch_related the cache is hit
        # (zero queries); without it, one query per manager.
        app_states = list(app_states_mgr.all())
        app_groups = list(app_groups_mgr.all())

        # No app-level restrictions ⇒ allow without further checks.
        if not app_states and not app_groups:
            return

        state_access = False
        group_access = False

        if app_states:
            profile = getattr(user, "profile", None)
            user_state = (
                getattr(profile, "state", None)
                if profile is not None
                else None
            )
            user_state_pk = getattr(user_state, "pk", None)
            state_pks = {s.pk for s in app_states}
            state_access = (
                user_state_pk is not None and user_state_pk in state_pks
            )
            # The STATE / GROUP debug logs expose what matched (not
            # the decision itself), so they survive the M1 logging
            # consolidation. Materialised lists are reused for both
            # the access check and the log line.
            if debug_mode and self.log.isEnabledFor(logging.INFO):
                self.log.info(
                    "OIDC STATE: user_state=%s app_states=%s",
                    user_state,
                    [s.name for s in app_states],
                )

        if app_groups:
            user_groups_mgr = getattr(user, "groups", None)
            if user_groups_mgr is not None:
                user_groups = list(user_groups_mgr.all())
                if debug_mode and self.log.isEnabledFor(logging.INFO):
                    self.log.info(
                        "OIDC GROUP: user_groups=%s app_groups=%s",
                        [g.name for g in user_groups],
                        [g.name for g in app_groups],
                    )
                group_pks = {g.pk for g in app_groups}
                group_access = any(g.pk in group_pks for g in user_groups)

        if group_access or state_access:
            return

        raise PermissionDenied("User not allowed for this application")


# Process-wide default policy. Module-level singleton so callers
# don't pay for repeated dataclass construction; tests that need a
# different logger / receiver pattern construct
# ``AccessPolicy(log=...)`` directly.
DEFAULT_POLICY: Final[AccessPolicy] = AccessPolicy()
