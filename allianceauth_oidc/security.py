"""Per-user / per-application OIDC access policy checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Final, NamedTuple

from django.core.exceptions import PermissionDenied

from .constants import PERM_ACCESS_OIDC

# This module intentionally uses getattr/callable checks:
# - these functions are called from multiple places (views/validators) and must
#   tolerate partially mocked objects in tests/integrations.
# - failures should become PermissionDenied, not AttributeError.

logger = logging.getLogger(f"extensions.{__name__}")


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
    app: object | None


def is_superuser(user: object) -> bool:
    """Return whether ``user`` is a superuser (defensive against mocks)."""
    return getattr(user, "is_superuser", False)


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

    # ---- public API ------------------------------------------------

    def decide(self, user: object, app: object | None) -> AccessDecision:
        """Evaluate the policy and return a structured decision."""
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

    def is_allowed(self, user: object, app: object | None) -> bool:
        """Convenience: ``decide(...).allowed``."""
        return self.decide(user, app).allowed

    def enforce(self, user: object, app: object | None) -> None:
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

    # ---- internal building blocks (raise-form) --------------------

    def _check_global(self, user: object) -> None:
        """
        Enforce the global ``access_oidc`` permission gate.

        Decision-level logging lives at the *callers* (``views.dispatch``
        for HTTP, ``auth_provider`` for validators); this method is a
        pure gate that raises ``PermissionDenied`` on failure. No log
        here would otherwise duplicate the caller's structured warning.
        """
        if is_superuser(user):
            return
        has_perm = getattr(user, "has_perm", None)
        # has_perm is the standard Django contract. If it's missing,
        # treat the object as an invalid user and deny access.
        if not callable(has_perm):
            raise PermissionDenied("Invalid user object (no has_perm)")
        if not has_perm(PERM_ACCESS_OIDC):
            raise PermissionDenied(f"Missing {PERM_ACCESS_OIDC} permission")

    def _check_app(self, user: object, app: object) -> None:
        """Enforce per-application state/group access for ``user``."""
        # Global gate runs first; this method is only reached after
        # ``_check_global`` already passed (via ``decide``) but is
        # also invoked directly by the legacy
        # ``check_user_state_and_groups`` wrapper, so the global
        # check is repeated there for parity with the old contract.
        if is_superuser(user):
            return

        debug_mode = getattr(app, "debug_mode", False)
        app_states = getattr(app, "states", None)
        app_groups = getattr(app, "groups", None)

        # If the application doesn't look like the expected DOT model,
        # deny rather than accidentally allowing access.
        if app_states is None or app_groups is None:
            raise PermissionDenied(
                "Invalid application object (missing states/groups)"
            )

        has_state_restrictions = app_states.exists()
        has_group_restrictions = app_groups.exists()

        # No app-level restrictions ⇒ allow without further checks.
        if not has_state_restrictions and not has_group_restrictions:
            return

        state_access = False
        group_access = False

        if has_state_restrictions:
            profile = getattr(user, "profile", None)
            user_state = (
                getattr(profile, "state", None)
                if profile is not None
                else None
            )
            user_state_pk = getattr(user_state, "pk", None)
            state_access = (
                bool(user_state_pk)
                and app_states.filter(pk=user_state_pk).exists()
            )
            # ``list(queryset)`` is expensive — only materialise when
            # debug_mode AND the INFO level is enabled. The STATE /
            # GROUP debug logs expose what matched (not the decision
            # itself), so they survive the M1 logging consolidation.
            if debug_mode and self.log.isEnabledFor(logging.INFO):
                self.log.info(
                    "OIDC STATE: user_state=%s app_states=%s",
                    user_state,
                    list(app_states.values_list("name", flat=True)),
                )

        if has_group_restrictions:
            user_groups = getattr(user, "groups", None)
            if user_groups is not None:
                if debug_mode and self.log.isEnabledFor(logging.INFO):
                    self.log.info(
                        "OIDC GROUP: user_groups=%s app_groups=%s",
                        list(user_groups.values_list("name", flat=True)),
                        list(app_groups.values_list("name", flat=True)),
                    )
                user_group_ids = user_groups.values_list("id", flat=True)
                group_access = app_groups.filter(
                    id__in=user_group_ids
                ).exists()

        if group_access or state_access:
            return

        raise PermissionDenied("User not allowed for this application")


# Process-wide default policy. Module-level singleton so callers
# don't pay for repeated dataclass construction; tests that need a
# different logger / receiver pattern construct
# ``AccessPolicy(log=...)`` directly.
DEFAULT_POLICY: Final[AccessPolicy] = AccessPolicy()
