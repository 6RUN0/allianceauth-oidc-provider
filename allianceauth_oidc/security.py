import logging
from typing import Any

from django.core.exceptions import PermissionDenied

log = logging.getLogger(__name__)


def check_user_global_oidc_access(user: Any) -> None:
    """
    Global gate: user must have the allianceauth_oidc.access_oidc permission,
    unless they are superuser.
    """
    if getattr(user, "is_superuser", False):
        return
    has_perm = getattr(user, "has_perm", None)
    if not callable(has_perm):
        raise PermissionDenied("Invalid user object (no has_perm)")
    if not has_perm("allianceauth_oidc.access_oidc"):
        raise PermissionDenied(
            "Missing allianceauth_oidc.access_oidc permission"
        )


def check_user_state_and_groups(user: Any, app: Any) -> None:
    """
    App gate:
    - If app has no states and no groups: allow.
    - If app has states and/or groups: allow if (state matches)
      OR (any group matches).
    - Superuser bypasses.
    Also enforces global permission via check_user_global_oidc_access().
    """
    check_user_global_oidc_access(user)
    if getattr(user, "is_superuser", False):
        log.debug("%s is superuser; allowing OIDC access", user)
        return

    app_states = getattr(app, "states", None)
    app_groups = getattr(app, "groups", None)

    if app_states is None or app_groups is None:
        raise PermissionDenied(
            "Invalid application object (missing states/groups)"
        )

    has_state_restrictions = app_states.exists()
    has_group_restrictions = app_groups.exists()

    # No app-level restrictions
    if not has_state_restrictions and not has_group_restrictions:
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
        log.debug(
            "OAUTH STATE user_state=%s app_states=%s",
            user_state,
            list(app_states.values_list("name", flat=True)),
        )

    if has_group_restrictions:
        user_groups = getattr(user, "groups", None)
        if user_groups is not None:
            log.debug(
                "OAUTH GROUP user_groups=%s app_groups=%s",
                list(user_groups.values_list("name", flat=True)),
                list(app_groups.values_list("name", flat=True)),
            )
            user_group_ids = user_groups.values_list("id", flat=True)
            group_access = app_groups.filter(id__in=user_group_ids).exists()

    if group_access or state_access:
        return

    log.warning(
        "OIDC denied (app restrictions): user=%s app=%s group_access=%s state_access=%s",  # noqa E501
        user,
        app,
        group_access,
        state_access,
    )
    raise PermissionDenied("User not allowed for this application")
