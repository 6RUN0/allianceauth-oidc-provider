"""``manage.py oidc_revoke_user_tokens`` — revoke all tokens of a user."""

from __future__ import annotations

import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils.translation import gettext_lazy as _
from oauth2_provider.models import (
    get_access_token_model,
    get_refresh_token_model,
)
from typing_extensions import override

from ._format import FORMAT_CHOICES, render_rows

logger = logging.getLogger(f"extensions.{__name__}")


class Command(BaseCommand):
    """
    Revoke every active OAuth2 token (access + refresh) belonging to a
    user — used after a leave/compromise.

    Iterates per-token rather than ``QuerySet.delete()`` so DOT's
    ``revoke()`` lifecycle (cascading + signal emission) runs for each
    one. Idempotent: a re-run on an already-clean user is a no-op.
    """

    # See ``oidc_create_app.Command.help`` for the type-ignore rationale.
    help = _(  # type: ignore[assignment]  # pyright: ignore[reportAssignmentType]
        "Revoke all OAuth2 tokens for a given user."
    )

    @override
    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--username",
            required=True,
            help=_("username to revoke (exact match)"),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=_("Count tokens that would be revoked without revoking."),
        )
        parser.add_argument(
            "--format",
            default="table",
            choices=FORMAT_CHOICES,
        )

    @override
    def handle(self, *args: Any, **options: Any) -> None:
        User = get_user_model()
        try:
            user = User.objects.get(username=options["username"])
        except User.DoesNotExist as exc:
            raise CommandError(
                f"username={options['username']!r} not found"
            ) from exc

        AccessToken = get_access_token_model()
        RefreshToken = get_refresh_token_model()

        access = AccessToken.objects.filter(user=user)
        refresh = RefreshToken.objects.filter(user=user)
        access_count = access.count()
        refresh_count = refresh.count()

        username = user.get_username()

        if options["dry_run"]:
            self.stdout.write(
                render_rows(
                    [
                        {
                            "username": username,
                            "access_tokens": access_count,
                            "refresh_tokens": refresh_count,
                            "dry_run": True,
                        }
                    ],
                    columns=(
                        "username",
                        "access_tokens",
                        "refresh_tokens",
                        "dry_run",
                    ),
                    fmt=options["format"],
                )
            )
            return

        revoked_access = 0
        revoked_refresh = 0
        with transaction.atomic():
            for token in access.iterator():
                token.revoke()
                revoked_access += 1
            for token in refresh.iterator():
                token.revoke()
                revoked_refresh += 1

        logger.warning(
            "OIDC revoke_user_tokens: user_id=%s username=%s access=%d refresh=%d",  # noqa: E501
            user.pk,
            username,
            revoked_access,
            revoked_refresh,
        )
        self.stdout.write(
            render_rows(
                [
                    {
                        "username": username,
                        "revoked_access": revoked_access,
                        "revoked_refresh": revoked_refresh,
                    }
                ],
                columns=(
                    "username",
                    "revoked_access",
                    "revoked_refresh",
                ),
                fmt=options["format"],
            )
        )
