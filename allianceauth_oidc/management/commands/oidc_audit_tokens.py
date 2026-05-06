"""``manage.py oidc_audit_tokens`` — read-only listing of active tokens."""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
)

from ._format import FORMAT_CHOICES, render_rows


class Command(BaseCommand):
    """
    List currently-issued access tokens, optionally filtered by user
    or application.

    Read-only — never modifies state. Useful for "who is currently
    authenticated against RP X?" and "does this user still have
    refreshable sessions?" diagnostics.
    """

    # See ``oidc_create_app.Command.help`` for the type-ignore rationale.
    help = _(  # type: ignore[assignment]  # pyright: ignore[reportAssignmentType]
        "List active OIDC access tokens with optional filters."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--username",
            help=_("Filter by exact username."),
        )
        parser.add_argument(
            "--client-id",
            help=_("Filter by application client_id."),
        )
        parser.add_argument(
            "--include-expired",
            action="store_true",
            help=_("Include tokens past their expiry timestamp."),
        )
        parser.add_argument(
            "--format",
            default="table",
            choices=FORMAT_CHOICES,
        )

    def handle(self, *args: Any, **options: Any) -> None:
        AccessToken = get_access_token_model()
        qs = AccessToken.objects.select_related("user", "application")

        if not options["include_expired"]:
            qs = qs.filter(expires__gte=timezone.now())

        if options["username"]:
            User = get_user_model()
            try:
                user = User.objects.get(username=options["username"])
            except User.DoesNotExist as exc:
                raise CommandError(
                    f"username={options['username']!r} not found"
                ) from exc
            qs = qs.filter(user=user)

        if options["client_id"]:
            Application = get_application_model()
            try:
                app = Application.objects.get(client_id=options["client_id"])
            except Application.DoesNotExist as exc:
                raise CommandError(
                    f"client_id={options['client_id']!r} not found"
                ) from exc
            qs = qs.filter(application=app)

        # ``pkce_required`` mirrors the matching ``AllianceAuthApplication``'s
        # field. The ``select_related("application")`` above keeps this an
        # in-memory attribute access — no extra query per row. Useful when
        # triaging "did this token come from a strict-PKCE client?" without
        # context-switching to admin. Column name matches the model field
        # for symmetry with ``oidc_create_app`` output.
        rows = [
            {
                "id": t.id,
                "user": getattr(t.user, "username", None),
                "client_id": getattr(t.application, "client_id", None),
                "scope": t.scope,
                "expires": t.expires.isoformat() if t.expires else "",
                "pkce_required": getattr(t.application, "pkce_required", None),
            }
            for t in qs.order_by("-expires").iterator()
        ]
        self.stdout.write(
            render_rows(
                rows,
                columns=(
                    "id",
                    "user",
                    "client_id",
                    "scope",
                    "expires",
                    "pkce_required",
                ),
                fmt=options["format"],
            )
        )
