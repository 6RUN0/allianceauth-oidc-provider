"""Django admin registration for ``AllianceAuthApplication``."""

from django.contrib import admin
from typing_extensions import override

from .models import BackChannelLogoutAttempt


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
    raw_id_fields = ("user",)

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
