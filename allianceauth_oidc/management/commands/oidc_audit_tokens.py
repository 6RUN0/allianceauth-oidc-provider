"""``manage.py oidc_audit_tokens`` — read-only listing of active tokens."""

from __future__ import annotations

from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
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

    help = "List active OIDC access tokens with optional filters."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--username",
            help="Filter by exact username.",
        )
        parser.add_argument(
            "--client-id",
            help="Filter by application client_id.",
        )
        parser.add_argument(
            "--include-expired",
            action="store_true",
            help="Include tokens past their expiry timestamp.",
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
                app = Application.objects.get(
                    client_id=options["client_id"]
                )
            except Application.DoesNotExist as exc:
                raise CommandError(
                    f"client_id={options['client_id']!r} not found"
                ) from exc
            qs = qs.filter(application=app)

        rows = [
            {
                "id": t.id,
                "user": getattr(t.user, "username", None),
                "client_id": getattr(t.application, "client_id", None),
                "scope": t.scope,
                "expires": t.expires.isoformat() if t.expires else "",
            }
            for t in qs.order_by("-expires").iterator()
        ]
        self.stdout.write(
            render_rows(
                rows,
                columns=("id", "user", "client_id", "scope", "expires"),
                fmt=options["format"],
            )
        )
