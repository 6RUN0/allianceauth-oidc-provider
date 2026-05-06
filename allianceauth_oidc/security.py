"""Per-user / per-application OIDC access policy checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final, NamedTuple, Protocol, runtime_checkable

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


class AccessDecision(NamedTuple):
    """
    Outcome of ``AccessPolicy.decide`` — three-way (allowed,
    denied-global, denied-app) folded into a typed record.

    ``app`` is echoed back so the caller can render it without a second
    lookup; for an allowed request with no ``client_id`` the field is
    ``None``.
    """

    allowed: bool
    deny_reason: DenyReason | None
    app: AppLike | None


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
            return AccessDecision(
                allowed=False, deny_reason=DenyReason.GLOBAL, app=None
            )
        if app is None:
            return AccessDecision(allowed=True, deny_reason=None, app=None)
        try:
            self._check_app(user, app)
        except PermissionDenied:
            return AccessDecision(
                allowed=False, deny_reason=DenyReason.APP, app=app
            )
        return AccessDecision(allowed=True, deny_reason=None, app=app)

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

    def pkce_required(self, client_id: str) -> bool:
        """
        Return whether PKCE is required for the application identified
        by ``client_id``.

        Looks up the :class:`AllianceAuthApplication` row keyed by
        ``client_id`` and returns its ``pkce_required`` flag. When no
        row matches, logs a warning and returns ``True`` (fail-safe to
        strict): an unknown client must always take the strict path.
        The query is bounded to a single column via
        ``.only("pkce_required")`` because this hook runs on every
        authorize / token request.

        Shape asymmetry vs. ``decide`` / ``is_allowed`` / ``enforce``:
        those methods take pre-loaded ``(user, app)`` objects because
        their callers (the authorize view, the validators) have already
        resolved the application. ``pkce_required`` instead takes a
        raw ``client_id`` and owns the ORM lookup itself, because DOT's
        ``is_pkce_required(client_id, request)`` call site does not
        provide a loaded ``App``. Owning the resolution here keeps the
        adapter (``auth_provider.per_app_pkce_required``) trivial; the
        alternative — loading the app in the adapter — would just shift
        the same lookup one frame up without testability gain.
        """
        from .models import AllianceAuthApplication

        try:
            app = AllianceAuthApplication.objects.only("pkce_required").get(
                client_id=client_id
            )
        except AllianceAuthApplication.DoesNotExist:
            self.log.warning(
                "OIDC PKCE: unknown client_id=%r → fail-safe True",
                client_id,
            )
            return True
        return bool(app.pkce_required)

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
