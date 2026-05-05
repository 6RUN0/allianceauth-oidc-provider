"""``manage.py oidc_rotate_secret`` — regenerate an app's client_secret."""

from __future__ import annotations

import logging
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from oauth2_provider.generators import generate_client_secret
from oauth2_provider.models import get_application_model

from ._format import FORMAT_CHOICES, render_rows

logger = logging.getLogger(f"extensions.{__name__}")


class Command(BaseCommand):
    """
    Rotate the ``client_secret`` of a registered OIDC application.

    The old secret is invalidated immediately on save (DOT hashes the
    new one); already-issued access/refresh tokens stay valid until
    expiry. Use ``oidc_revoke_user_tokens`` to also invalidate
    in-flight tokens for a specific user.
    """

    help = "Regenerate the client_secret of an OIDC application."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--client-id", required=True)
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would change without writing.",
        )
        parser.add_argument(
            "--format",
            default="table",
            choices=FORMAT_CHOICES,
        )

    def handle(self, *args: Any, **options: Any) -> None:
        Application = get_application_model()
        try:
            app = Application.objects.get(client_id=options["client_id"])
        except Application.DoesNotExist as exc:
            raise CommandError(
                f"no application with client_id={options['client_id']!r}"
            ) from exc

        new_secret = generate_client_secret()

        if options["dry_run"]:
            self.stdout.write(
                render_rows(
                    [
                        {
                            "client_id": app.client_id,
                            "name": app.name,
                            "would_set_secret_prefix": new_secret[:4]
                            + "…",
                            "dry_run": True,
                        }
                    ],
                    columns=(
                        "client_id",
                        "name",
                        "would_set_secret_prefix",
                        "dry_run",
                    ),
                    fmt=options["format"],
                )
            )
            return

        with transaction.atomic():
            app.client_secret = new_secret
            app.save(update_fields=["client_secret"])

        logger.warning(
            "OIDC rotate_secret: client_id=%s name=%s",
            app.client_id,
            app.name,
        )
        self.stdout.write(
            render_rows(
                [
                    {
                        "client_id": app.client_id,
                        "name": app.name,
                        "client_secret": new_secret,
                    }
                ],
                columns=("client_id", "name", "client_secret"),
                fmt=options["format"],
            )
        )
