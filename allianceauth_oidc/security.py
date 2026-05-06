"""Per-user / per-application OIDC access policy checks."""

from __future__ import annotations

import logging
from enum import Enum
from typing import NamedTuple

from django.core.exceptions import PermissionDenied

from .constants import PERM_ACCESS_OIDC
from .utils import app_log

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
    Outcome of ``evaluate_access`` — three-way (allowed, denied-global,
    denied-app) folded into a typed record.

    ``app`` is echoed back so the caller can render it without a second
    lookup; for an allowed request with no ``client_id`` the field is
    ``None``.
    """

    allowed: bool
    deny_reason: DenyReason | None
    app: object | None


def evaluate_access(user: object, app: object | None) -> AccessDecision:
    """
    Run the global + per-app policy and return a structured decision.

    Splits the policy out of the view so it can be unit-tested without
    spinning up ``RequestFactory`` + template loader. The exception-
    raising checkers stay in place (they're the protocol the validator
    layer uses) — this function just composes them and converts the
    raises into a ``DenyReason``.

    Order is preserved from the previous in-line ``dispatch`` body:
    global first, app-level second. ``app=None`` (no ``client_id`` in
    the request, or unknown / inactive client) skips the app branch and
    delegates the missing-client_id error to DOT's ``AuthorizationView``
    downstream.
    """
    try:
        check_user_global_oidc_access(user)
    except PermissionDenied:
        return AccessDecision(
            allowed=False, deny_reason=DenyReason.GLOBAL, app=None
        )
    if app is None:
        return AccessDecision(allowed=True, deny_reason=None, app=None)
    try:
        check_user_state_and_groups(user, app)
    except PermissionDenied:
        return AccessDecision(
            allowed=False, deny_reason=DenyReason.APP, app=app
        )
    return AccessDecision(allowed=True, deny_reason=None, app=app)


def is_superuser(user: object) -> bool:
    """Return whether ``user`` is a superuser (defensive against mocks)."""
    return getattr(user, "is_superuser", False)


def check_user_global_oidc_access(user: object) -> None:
    """
    Enforce the global ``allianceauth_oidc.access_oidc`` permission gate.

    Superusers bypass; everyone else needs the explicit permission.
    """
    if is_superuser(user):
        logger.debug("OIDC ALLOWED: superuser user=%s", user)
        return
    has_perm = getattr(user, "has_perm", None)
    # has_perm is the standard Django contract. If it's missing, treat the
    # object as an invalid user and deny access.
    if not callable(has_perm):
        raise PermissionDenied("Invalid user object (no has_perm)")
    if not has_perm(PERM_ACCESS_OIDC):
        logger.warning("OIDC DENIED: missing global permission user=%s", user)
        raise PermissionDenied(f"Missing {PERM_ACCESS_OIDC} permission")


def check_user_state_and_groups(user: object, app: object) -> None:
    """
    Enforce per-application state/group access for ``user``.

    Rules:
    - If app has no states and no groups: allow.
    - If app has states and/or groups: allow if (state matches)
      OR (any group matches).
    - Superuser bypasses.

    Also enforces the global permission via
    ``check_user_global_oidc_access``.
    """
    check_user_global_oidc_access(user)
    if is_superuser(user):
        return

    debug_mode = getattr(app, "debug_mode", False)
    app_states = getattr(app, "states", None)
    app_groups = getattr(app, "groups", None)

    # If the application doesn't look like the expected Django OAuth Toolkit
    # model, deny rather than accidentally allowing access.
    if app_states is None or app_groups is None:
        raise PermissionDenied(
            "Invalid application object (missing states/groups)"
        )

    has_state_restrictions = app_states.exists()
    has_group_restrictions = app_groups.exists()

    # No app-level restrictions
    if not has_state_restrictions and not has_group_restrictions:
        app_log(
            logger,
            app,
            "OIDC ALLOWED: no app restrictions user=%s app=%s",
            user,
            app,
        )
        return

    state_access = False
    group_access = False

    if has_state_restrictions:
        profile = getattr(user, "profile", None)
        user_state = (
            getattr(profile, "state", None) if profile is not None else None
        )
        user_state_pk = getattr(user_state, "pk", None)
        state_access = (
            bool(user_state_pk)
            and app_states.filter(pk=user_state_pk).exists()
        )
        # list(queryset) can be expensive, so we guard it with
        # isEnabledFor(INFO). Otherwise, even with debug_mode we'd create
        # unnecessary DB load.
        if debug_mode and logger.isEnabledFor(logging.INFO):
            # In debug_mode we intentionally log at INFO
            # for admin convenience.
            logger.info(
                "OIDC STATE: user_state=%s app_states=%s",
                user_state,
                list(app_states.values_list("name", flat=True)),
            )

    if has_group_restrictions:
        user_groups = getattr(user, "groups", None)
        if user_groups is not None:
            # Similarly: serializing group lists can be expensive,
            # so only log when INFO is enabled.
            if debug_mode and logger.isEnabledFor(logging.INFO):
                logger.info(
                    "OIDC GROUP: user_groups=%s app_groups=%s",
                    list(user_groups.values_list("name", flat=True)),
                    list(app_groups.values_list("name", flat=True)),
                )
            user_group_ids = user_groups.values_list("id", flat=True)
            group_access = app_groups.filter(id__in=user_group_ids).exists()

    if group_access or state_access:
        reason = []
        if group_access:
            reason.append("group")
        if state_access:
            reason.append("state")
        app_log(
            logger,
            app,
            "OIDC ALLOWED: (%s access): user=%s app=%s",
            ", ".join(reason),
            user,
            app,
        )
        return

    logger.warning(
        "OIDC DENIED: app restrictions user=%s app=%s group_access=%s state_access=%s",  # noqa: E501
        user,
        app,
        group_access,
        state_access,
    )
    raise PermissionDenied("User not allowed for this application")
