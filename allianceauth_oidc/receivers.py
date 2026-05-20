"""
Django signal receivers that emit ``oidc_logout_required``.

Five trigger sites in addition to the ``oidc_revoke_user_tokens``
management command (which emits the signal directly from its
handler):

1. ``User.is_active`` flip True→False — :func:`on_user_pre_save` /
   :func:`on_user_post_save` use a pre-save snapshot stored on the
   instance.
2. ``User.groups`` m2m changes — :func:`on_user_groups_changed`
   re-runs ``DEFAULT_POLICY.is_allowed`` after the change and fires
   only when an RP's policy newly denies the user.
3. Alliance Auth's ``state_changed`` signal — :func:`on_state_changed`
   mirrors the groups path for state policy changes.
4. ``User`` deletion — :func:`on_user_pre_delete` snapshots the
   ``application_id`` list into a module-level
   :class:`weakref.WeakKeyDictionary`; :func:`on_user_post_delete`
   reads + pops it and emits one signal per RP.
5. Admin bulk action "Send test back-channel logout" in
   :mod:`admin` — operator-triggered emission with
   ``reason="admin_test"``; used to verify BCL wiring against a
   live RP without waiting for a real lifecycle event.

Wiring lives in ``apps.py:ready()``; the helpers here only define
the receivers + the per-receiver ``dispatch_uid`` strings so the
test suite can disconnect them cleanly.

Newly-denied gating: only ``groups_changed`` and ``state_changed``
gate on ``DEFAULT_POLICY.is_allowed`` (the "newly denied" check);
``user_revoked``, ``user_deactivated``, and ``user_deleted`` emit
unconditionally on RT/AT presence — the user already lost access
by definition.
"""

from __future__ import annotations

import logging
import weakref
from typing import Any

from .logout import apps_with_active_tokens
from .security import DEFAULT_POLICY
from .signals import oidc_logout_required

# settings.ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS — when True, the
# dead-letter receiver also records successful dispatches. Off by
# default keeps the audit table focused on what the name promises:
# delivery attempts that need operator attention.
_AUDIT_SUCCESS_SETTING = "ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS"

logger = logging.getLogger(f"extensions.{__name__}")

UID_IS_ACTIVE_PRE_SAVE = "allianceauth_oidc.is_active_pre_save"
UID_IS_ACTIVE_POST_SAVE = "allianceauth_oidc.is_active_post_save"
UID_GROUPS_M2M_CHANGED = "allianceauth_oidc.groups_m2m_changed"
UID_STATE_CHANGED = "allianceauth_oidc.state_changed"
UID_USER_PRE_DELETE = "allianceauth_oidc.user_pre_delete"
UID_USER_POST_DELETE = "allianceauth_oidc.user_post_delete"

# WeakKeyDictionary key-stability rationale:
# Django's Collector loop sends post_delete BEFORE clearing
# instance.pk. The ordering claim is the load-bearing fact:
# pre_delete -> SQL delete -> post_delete -> instance.pk = None,
# IN THAT ORDER. So ``instance`` is a valid (non-None-pk, hashable)
# weak-referenceable key in BOTH signal handlers, and the dict entry
# survives long enough to be popped in post_delete. The weakref
# backstop ensures any error-path leak is GC'd rather than retained
# indefinitely.
_PENDING_LOGOUTS: weakref.WeakKeyDictionary[Any, Any] = (
    weakref.WeakKeyDictionary()
)


# ---------- Trigger 1: User.is_active flip ----------


def on_user_pre_save(sender: Any, instance: Any, **kwargs: Any) -> None:
    """
    Capture the persisted ``is_active`` BEFORE the save so the
    post-save receiver can diff against the new value.

    Reads from the DB rather than relying on ``Model.__init__``
    instance state — that state is stale if the caller mutated
    ``instance.is_active`` before calling ``save()``.
    """
    if not getattr(instance, "pk", None):
        # First save (insert) — by definition no prior is_active to
        # compare against.
        instance._allianceauth_oidc_was_active = None
        return
    try:
        prior = sender.objects.only("is_active").get(pk=instance.pk)
        instance._allianceauth_oidc_was_active = bool(prior.is_active)
    except sender.DoesNotExist:
        instance._allianceauth_oidc_was_active = None


def on_user_post_save(
    sender: Any, instance: Any, created: bool, **kwargs: Any
) -> None:
    """
    Fire ``oidc_logout_required`` for each RP the user has active
    tokens with when ``is_active`` transitions True → False.
    """
    if created:
        return
    was_active = getattr(instance, "_allianceauth_oidc_was_active", None)
    if was_active is None or was_active == bool(instance.is_active):
        return
    if instance.is_active:
        # False -> True is a re-activation; no logout to dispatch.
        return
    for app in apps_with_active_tokens(instance):
        oidc_logout_required.send(
            sender=sender,
            user=instance,
            application=app,
            reason="user_deactivated",
        )


# ---------- Trigger 2: User.groups m2m change ----------


def on_user_groups_changed(
    sender: Any, instance: Any, action: str, **kwargs: Any
) -> None:
    """
    Re-evaluate ``DEFAULT_POLICY.is_allowed`` after group removal /
    clear; fire signal for RPs that newly deny access.

    ``post_add`` is intentionally ignored — adding a group grants
    access, doesn't revoke it. ``pre_*`` actions fire before the
    membership is committed; we want the post-state policy so we
    listen on ``post_remove`` / ``post_clear``.
    """
    from django.contrib.auth import get_user_model

    User = get_user_model()
    if not isinstance(instance, User):
        # Reverse m2m (``Group.user_set.add``) sends Group instances.
        # Out of scope for v1 — the realistic ops flow is
        # ``user.groups.remove(...)``.
        return
    if action not in ("post_remove", "post_clear"):
        return
    # ``UserLike`` is a structural Protocol; pyright's ``_UserModel``
    # proxy can't prove the runtime ``User`` satisfies it (Django's
    # ``is_authenticated`` is a property, not a plain bool). ``Any``-
    # bind keeps the call shape honest at runtime.
    user_arg: Any = instance
    for app in apps_with_active_tokens(instance):
        if not DEFAULT_POLICY.is_allowed(user_arg, app):
            oidc_logout_required.send(
                sender=sender,
                user=instance,
                application=app,
                reason="groups_changed",
            )


# ---------- Trigger 3: AA state_changed ----------


def on_state_changed(
    sender: Any, user: Any, state: Any = None, **kwargs: Any
) -> None:
    """
    Receiver for ``allianceauth.authentication.signals.state_changed``.

    AA fires this when ``UserProfile.assign_state()`` runs (e.g.
    member became Guest after losing main character). Mirrors the
    groups path: re-runs ``DEFAULT_POLICY.is_allowed`` per RP.
    """
    if user is None:
        return
    for app in apps_with_active_tokens(user):
        if not DEFAULT_POLICY.is_allowed(user, app):
            oidc_logout_required.send(
                sender=sender,
                user=user,
                application=app,
                reason="state_changed",
            )


# ---------- Trigger 4: User pre_delete + post_delete ----------


def on_user_pre_delete(sender: Any, instance: Any, **kwargs: Any) -> None:
    """
    Snapshot the list of application PKs the user has tokens with,
    so :func:`on_user_post_delete` can fan out logouts after the
    cascading delete has already removed the tokens themselves.
    """
    app_ids = [app.pk for app in apps_with_active_tokens(instance)]
    if app_ids:
        _PENDING_LOGOUTS[instance] = app_ids


def on_user_post_delete(sender: Any, instance: Any, **kwargs: Any) -> None:
    """
    Read the pre-delete snapshot and emit one signal per RP with
    ``reason="user_deleted"``. Pops the entry to free the weakref
    slot promptly.

    NB: by post_delete, ``instance.pk`` has not yet been zeroed, and
    the tokens themselves are gone — so we cannot re-derive
    application set from the DB here. Hence the pre-delete snapshot.

    Rehydrate with ``active=True`` to match the snapshot taken in
    :func:`on_user_pre_delete` — ``apps_with_active_tokens`` filters on
    ``active=True`` at snapshot time, so an app deactivated in the
    micro-window between ``pre_delete`` and ``post_delete`` (long-running
    cascade on a heavy User row, concurrent admin save) must NOT
    receive a BCL fan-out. :func:`dispatch_backchannel_logout` already
    has a downstream ``is_usable`` kill-switch, but symmetrising the
    rehydrate filter closes the gap one layer earlier and keeps the
    invariant local to this receiver.
    """
    from oauth2_provider.models import get_application_model

    app_ids = _PENDING_LOGOUTS.pop(instance, [])
    if not app_ids:
        return
    Application = get_application_model()
    for app in Application.objects.filter(pk__in=app_ids, active=True):
        oidc_logout_required.send(
            sender=sender,
            user=instance,
            application=app,
            reason="user_deleted",
        )


# ---------- BCL dead-letter / audit recorder ----------


def record_backchannel_logout_attempt(
    sender: Any,
    application: Any,
    jti: str,
    success: bool,
    attempt_count: int,
    user_pk: int | None = None,
    reason: str | None = None,
    **kwargs: Any,
) -> None:
    """
    Persist one ``oidc_logout_dispatched`` event as a
    :class:`allianceauth_oidc.models.BackChannelLogoutAttempt` row.

    By default records only failures (``success is False``); flip
    ``settings.ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS=True`` to also
    record successful dispatches.

    Defensive against partial bodies: ``application`` may be the
    model or a duck-typed mock during tests, and ``user_pk`` is
    optional (older custom senders may not pass it). ``int()`` on
    ``user_pk`` normalises None / numeric strings / odd types into
    either an int or None so the model column never receives garbage.
    """
    from django.conf import settings

    from .models import BackChannelLogoutAttempt

    audit_success = getattr(settings, _AUDIT_SUCCESS_SETTING, False)
    if success and not audit_success:
        return
    app_pk = getattr(application, "pk", None)
    if app_pk is None:
        # Without an FK target we can't write a row; the signal
        # contract guarantees ``application`` is a real Application
        # in every code path the project owns, so this branch only
        # fires for malformed third-party senders. WARN so operators
        # can spot the misuse.
        logger.warning(
            "OIDC BCL: dead-letter recorder received oidc_logout_dispatched without an application — skipping row"  # noqa: E501
        )
        return
    normalised_user_pk: int | None
    if user_pk is None:
        normalised_user_pk = None
    else:
        try:
            normalised_user_pk = int(user_pk)
        except (TypeError, ValueError):
            normalised_user_pk = None
    # Snapshot client_id + name at row-insert time. Both survive the
    # FK becoming NULL after admin-driven RP deletion,
    # so per-RP forensic queries still work for historical rows.
    client_id_snapshot = (getattr(application, "client_id", "") or "")[:100]
    name_snapshot = (getattr(application, "name", "") or "")[:255]
    try:
        BackChannelLogoutAttempt.objects.create(
            application_id=app_pk,
            user_pk=normalised_user_pk,
            jti=jti or "",
            success=bool(success),
            attempt_count=int(attempt_count or 0),
            reason=reason or "",
            application_client_id_snapshot=client_id_snapshot,
            application_name_snapshot=name_snapshot,
        )
    except Exception:
        # Audit MUST NOT break the dispatcher. Failing to persist a
        # dead-letter row is logged with a traceback and swallowed
        # so the originating signal sender (Celery task or
        # dispatcher) finishes its own work normally.
        logger.exception(
            "OIDC BCL: failed to persist dead-letter row (app_pk=%s, jti=%s, reason=%s)",  # noqa: E501
            app_pk,
            jti,
            reason,
        )


def connect_all() -> None:
    """
    Wire every receiver in this module against its signal under the
    documented ``dispatch_uid`` so tests can disconnect them cleanly.

    Called from ``apps.py:ready()``.
    """
    from django.contrib.auth import get_user_model
    from django.db.models.signals import (
        m2m_changed,
        post_delete,
        post_save,
        pre_delete,
        pre_save,
    )

    from .constants import BCL_AUDIT_DISPATCH_UID
    from .signals import oidc_logout_dispatched

    oidc_logout_dispatched.connect(
        record_backchannel_logout_attempt,
        dispatch_uid=BCL_AUDIT_DISPATCH_UID,
        weak=False,
    )

    User = get_user_model()
    pre_save.connect(
        on_user_pre_save,
        sender=User,
        dispatch_uid=UID_IS_ACTIVE_PRE_SAVE,
    )
    post_save.connect(
        on_user_post_save,
        sender=User,
        dispatch_uid=UID_IS_ACTIVE_POST_SAVE,
    )
    # ``User.groups`` is a ``ManyToManyField`` whose ``through`` table
    # is the join model — but pyright's ``_UserModel`` proxy strips
    # the attribute. The runtime is correct; cast via ``Any``.
    User_any: Any = User
    user_groups = User_any.groups
    m2m_changed.connect(
        on_user_groups_changed,
        sender=user_groups.through,
        dispatch_uid=UID_GROUPS_M2M_CHANGED,
    )
    pre_delete.connect(
        on_user_pre_delete,
        sender=User,
        dispatch_uid=UID_USER_PRE_DELETE,
    )
    post_delete.connect(
        on_user_post_delete,
        sender=User,
        dispatch_uid=UID_USER_POST_DELETE,
    )
    try:
        from allianceauth.authentication.signals import (
            state_changed as aa_state_changed,
        )

        aa_state_changed.connect(
            on_state_changed,
            dispatch_uid=UID_STATE_CHANGED,
        )
    except ImportError:
        # AA's signal module is not importable (e.g. in a stripped-
        # down test settings); log and continue. The state-change
        # logout path is degraded but the others still work.
        logger.warning(
            "OIDC BCL: allianceauth.authentication.signals.state_changed not importable; state-change logout dispatch disabled."  # noqa: E501
        )
