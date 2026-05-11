"""Django admin registration for ``AllianceAuthApplication``."""

from django.contrib import admin
from django.contrib.auth import get_user_model
from typing_extensions import override

from .models import BackChannelLogoutAttempt

has_email = hasattr(get_user_model(), "email")


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
    search_fields = ("name",) + (("user__email",) if has_email else ())
    raw_id_fields = ("user",)


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
