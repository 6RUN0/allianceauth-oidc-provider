"""``manage.py oidc_create_app`` — bootstrap a new OIDC application."""

from __future__ import annotations

import argparse
import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils.translation import gettext as _
from oauth2_provider.generators import (
    generate_client_id,
    generate_client_secret,
)
from oauth2_provider.models import AbstractApplication, get_application_model
from typing_extensions import override

from ._format import FORMAT_CHOICES, render_rows

logger = logging.getLogger(f"extensions.{__name__}")

_GRANT_CHOICES = (
    AbstractApplication.GRANT_AUTHORIZATION_CODE,
    AbstractApplication.GRANT_CLIENT_CREDENTIALS,
    AbstractApplication.GRANT_PASSWORD,
    AbstractApplication.GRANT_IMPLICIT,
)
_CLIENT_TYPES = (
    AbstractApplication.CLIENT_CONFIDENTIAL,
    AbstractApplication.CLIENT_PUBLIC,
)


class Command(BaseCommand):
    """
    Create a new OIDC application from arguments only — no interactive
    prompts, so the command is safe to call from CI / Ansible / Salt.

    Prints the generated ``client_id`` and the *raw* ``client_secret``
    in the requested format. The raw secret is shown ONCE (DOT hashes
    it on save when ``HASH_CLIENT_SECRET`` is True, which is the
    default), so capture it from this output.
    """

    help = _("Create a new AllianceAuthApplication and print its credentials.")

    @override
    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--name", required=True)
        parser.add_argument(
            "--user-id",
            required=True,
            type=int,
            help=_("ID of the User who owns the app."),
        )
        parser.add_argument(
            "--client-type",
            default=AbstractApplication.CLIENT_CONFIDENTIAL,
            choices=_CLIENT_TYPES,
        )
        parser.add_argument(
            "--grant-type",
            default=AbstractApplication.GRANT_AUTHORIZATION_CODE,
            choices=_GRANT_CHOICES,
        )
        parser.add_argument(
            "--redirect-uri",
            action="append",
            default=[],
            help=_("Allowed redirect URI (repeat for multiple)."),
        )
        parser.add_argument(
            "--state",
            action="append",
            default=[],
            help=_("Allowed AA state name (repeat for multiple)."),
        )
        parser.add_argument(
            "--group",
            action="append",
            default=[],
            help=_("Allowed Django group name (repeat for multiple)."),
        )
        parser.add_argument("--debug-mode", action="store_true")
        # Default ``True`` matches ``AllianceAuthApplication.pkce_required``'s
        # field default (RFC 9700 secure-by-default). ``BooleanOptionalAction``
        # surfaces both ``--pkce-required`` and ``--no-pkce-required`` so the
        # operator can be explicit either way; ``--debug-mode`` uses
        # ``store_true`` because its default is ``False`` and there is no
        # opt-out direction worth naming.
        parser.add_argument(
            "--pkce-required",
            action=argparse.BooleanOptionalAction,
            default=True,
            help=_(
                "Require PKCE on the authorization endpoint for this app (RFC 7636 / 9700). Default: True. Pass --no-pkce-required for known-incompatible legacy clients."  # noqa: E501
            ),
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
            owner = User.objects.get(pk=options["user_id"])
        except User.DoesNotExist as exc:
            raise CommandError(
                f"user_id={options['user_id']} not found"
            ) from exc

        Application = get_application_model()

        # State / group lookups validate names BEFORE the app is saved
        # so a typo doesn't leave a half-configured app behind.
        from allianceauth.authentication.models import State
        from django.contrib.auth.models import Group

        states = list(State.objects.filter(name__in=options["state"]))
        if len(states) != len(options["state"]):
            missing = set(options["state"]) - {s.name for s in states}
            raise CommandError(f"unknown state(s): {sorted(missing)}")

        groups = list(Group.objects.filter(name__in=options["group"]))
        if len(groups) != len(options["group"]):
            missing = set(options["group"]) - {g.name for g in groups}
            raise CommandError(f"unknown group(s): {sorted(missing)}")

        client_id = generate_client_id()
        raw_secret = generate_client_secret()

        with transaction.atomic():
            app = Application.objects.create(
                client_id=client_id,
                client_secret=raw_secret,
                name=options["name"],
                user=owner,
                client_type=options["client_type"],
                authorization_grant_type=options["grant_type"],
                redirect_uris=" ".join(options["redirect_uri"]),
                debug_mode=options["debug_mode"],
                pkce_required=options["pkce_required"],
            )
            if states:
                app.states.set(states)
            if groups:
                app.groups.set(groups)

        # Audit trail: log + admin LogEntry so the action is visible
        # in /admin/ without a code change.
        owner_id = owner.pk
        logger.info(
            "OIDC create_app: id=%s name=%s user_id=%s grant=%s",
            app.id,
            app.name,
            owner_id,
            options["grant_type"],
        )
        try:
            from django.contrib.admin.models import ADDITION, LogEntry

            # ``log_action`` is the Django 4.2 public API; Django 5.1
            # marked it deprecated in favour of bulk ``log_actions``,
            # which the django-stubs we depend on already mirror —
            # hence the typing ignores. We keep the singular call
            # because it matches the runtime AA installation.
            LogEntry.objects.log_action(  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
                user_id=owner_id,
                content_type_id=ContentType.objects.get_for_model(
                    Application
                ).id,
                object_id=app.id,
                object_repr=str(app),
                action_flag=ADDITION,
                change_message=(
                    f"Created via oidc_create_app (grant={options['grant_type']})"  # noqa: E501
                ),
            )
        except Exception:
            # LogEntry is best-effort; failing to record audit must
            # not undo the creation.
            logger.exception("OIDC create_app: failed to write LogEntry")

        out = render_rows(
            [
                {
                    "id": app.id,
                    "client_id": client_id,
                    "client_secret": raw_secret,
                    "name": app.name,
                    "grant_type": options["grant_type"],
                    "pkce_required": app.pkce_required,
                }
            ],
            columns=(
                "id",
                "client_id",
                "client_secret",
                "name",
                "grant_type",
                "pkce_required",
            ),
            fmt=options["format"],
        )
        self.stdout.write(out)
