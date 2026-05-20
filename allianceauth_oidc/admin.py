"""Django admin registration for ``AllianceAuthApplication``."""

from typing import Any

from django.contrib import admin, messages
from django.db.models import QuerySet
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _
from typing_extensions import override

from .models import BackChannelLogoutAttempt
from .signals import oidc_logout_required


class ApplicationAdmin(admin.ModelAdmin):
    """ModelAdmin shown via ``OAUTH2_PROVIDER['APPLICATION_ADMIN_CLASS']``."""

    list_display = (
        "id",
        "name",
        "user",
        "client_type",
        "authorization_grant_type",
        "pkce_required",
        "access_token_format",
        "backchannel_logout_uri",
    )

    # Bulk-selectable admin actions exposed in the changelist. The
    # default action set (``delete_selected``) stays — the list is
    # additive, not a replacement.
    actions = ("send_test_backchannel_logout",)
    # `user` is rendered in `list_display` for every row in the
    # changelist; without `list_select_related`, Django issues one
    # extra query per row to fetch the FK. Trivial today (most
    # installs have <100 OAuth apps) but free to fix.
    list_select_related = ("user",)
    list_filter = (
        "client_type",
        "authorization_grant_type",
        "skip_authorization",
        "pkce_required",
        "access_token_format",
        "backchannel_logout_on_revoke_only",
    )
    filter_horizontal = ("states", "groups")
    radio_fields = {
        "client_type": admin.HORIZONTAL,
        "authorization_grant_type": admin.VERTICAL,
    }
    raw_id_fields = ("user",)

    @admin.action(description=_("Send test back-channel logout"))
    def send_test_backchannel_logout(
        self,
        request: HttpRequest,
        queryset: QuerySet[Any],
    ) -> None:
        """
        Dispatch a synthetic ``oidc_logout_required`` for each
        selected application, addressed to the operator running the
        admin.

        Operators wire back-channel logout by setting
        ``backchannel_logout_uri`` on an application and pointing it
        at their RP's logout endpoint. The first end-to-end test
        usually means logging a real user out — slow, disruptive,
        and pollutes the audit trail with synthetic activity. This
        action does the equivalent without the user-facing side
        effects: it fires the same signal the production triggers
        emit (``reason="admin_test"``), the Celery dispatcher builds
        a real ``logout_token``, the RP receives a fully-signed
        token, and the dead-letter table records the outcome.

        Apps without ``backchannel_logout_uri`` are skipped with a
        warning rather than failing the whole action — selecting
        the full changelist and only firing on the BCL-configured
        subset is the common operator workflow.

        Apps with ``backchannel_logout_on_revoke_only=True`` ALSO
        skip with their own warning. The downstream dispatcher
        (``logout.dispatch_backchannel_logout``) silently no-ops on
        any ``reason != "user_revoked"`` event when that flag is set,
        so the admin's "test BCL" button would otherwise look
        successful while delivering nothing. The dual-layer check
        (admin pre-skip + dispatcher post-skip) is consistent with
        the codebase's three-layer policy pattern: the admin can
        report a fast, accurate result, and the dispatcher's check
        remains the security boundary for any out-of-band triggers.
        """
        sent = 0
        skipped_no_uri = 0
        skipped_revoke_only = 0
        for app in queryset:
            if not getattr(app, "backchannel_logout_uri", ""):
                skipped_no_uri += 1
                continue
            if getattr(app, "backchannel_logout_on_revoke_only", False):
                skipped_revoke_only += 1
                continue
            oidc_logout_required.send(
                sender=type(self),
                user=request.user,
                application=app,
                reason="admin_test",
            )
            sent += 1
        if sent:
            messages.success(
                request,
                _(
                    "Test back-channel logout dispatched for "
                    "%(count)d application(s) (reason='admin_test')."
                )
                % {"count": sent},
            )
        if skipped_no_uri:
            messages.warning(
                request,
                _(
                    "Skipped %(count)d application(s) without "
                    "backchannel_logout_uri."
                )
                % {"count": skipped_no_uri},
            )
        if skipped_revoke_only:
            messages.warning(
                request,
                _(
                    "Skipped %(count)d application(s) with "
                    "backchannel_logout_on_revoke_only=True "
                    "(only fires on real user-revoke events; not on "
                    "admin test)."
                )
                % {"count": skipped_revoke_only},
            )

    @override
    def get_search_fields(self, request):
        """
        Build ``search_fields`` at request time, not import time.

        ``get_user_model()`` resolves the swappable ``AUTH_USER_MODEL``
        — if the app registry is not fully populated when this module
        first imports (a real risk under test bootstrap or circular
        imports), the resolution can return a half-built class. By
        deferring the lookup to ``get_search_fields`` we run it after
        Django has guaranteed the registry is hot.
        """
        from django.contrib.auth import get_user_model

        user_model = get_user_model()
        # ``tuple[str, ...]`` annotation — appending to a literal
        # ``tuple[str]`` would otherwise trip mypy's invariant
        # tuple-length inference on the assignment below.
        fields: tuple[str, ...] = ("name",)
        if hasattr(user_model, "email"):
            fields += ("user__email",)
        return fields


@admin.register(BackChannelLogoutAttempt)
class BackChannelLogoutAttemptAdmin(admin.ModelAdmin):
    """
    Read-only audit view of BCL fan-out outcomes (dead-letter table).

    Operators use this to answer "which RP has a broken
    backchannel_logout_uri?" without grep'ing logs. Add / change /
    edit are disabled — audit rows are immutable by design. Delete
    stays allowed so superusers can prune the table manually (or
    schedule a Celery beat job that does it on a retention policy).
    """

    list_display = (
        "created_at",
        "application",
        "user_pk",
        "success",
        "reason",
        "attempt_count",
        "jti",
    )
    list_select_related = ("application",)
    list_filter = ("success", "reason", "application")
    search_fields = ("jti", "user_pk", "reason")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)
    # Everything's readonly — the audit row is a faithful record of
    # what actually happened on the wire and MUST NOT be edited.
    readonly_fields = (
        "application",
        "user_pk",
        "jti",
        "success",
        "attempt_count",
        "reason",
        "created_at",
    )

    @override
    def has_add_permission(self, request, obj=None):
        return False

    @override
    def has_change_permission(self, request, obj=None):
        # ``False`` on the changelist still leaves the per-row
        # change-link active for read-only inspection because every
        # editable field is in ``readonly_fields``.
        return False
