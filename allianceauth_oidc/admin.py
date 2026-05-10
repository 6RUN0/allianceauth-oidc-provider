"""Django admin registration for ``AllianceAuthApplication``."""

from django.contrib import admin
from django.contrib.auth import get_user_model

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
    )
    filter_horizontal = ("states", "groups")
    radio_fields = {
        "client_type": admin.HORIZONTAL,
        "authorization_grant_type": admin.VERTICAL,
    }
    search_fields = ("name",) + (("user__email",) if has_email else ())
    raw_id_fields = ("user",)
