"""``manage.py oidc_audit_tokens`` — read-only listing of active tokens."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.utils.translation import gettext as _
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
)
from oauth2_provider.settings import oauth2_settings
from typing_extensions import override

from allianceauth_oidc.views import classify_token_format

from ._format import FORMAT_CHOICES, render_rows

# Clock-skew tolerance for the TTL anomaly check. Set wide enough to
# cover small drift between the dispatcher's ``now`` and our ``now``,
# narrow enough not to mask a token issued under a stale TTL config.
_TTL_ANOMALY_SKEW = timedelta(seconds=5)


class Command(BaseCommand):
    """
    List currently-issued access tokens, optionally filtered by user
    or application.

    Read-only — never modifies state. Useful for "who is currently
    authenticated against RP X?" and "does this user still have
    refreshable sessions?" diagnostics.
    """

    help = _("List active OIDC access tokens with optional filters.")

    @override
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
            "--suspicious",
            action="store_true",
            help=_(
                "Restrict output to tokens that do not match the "
                "operator's current configuration: TTL farther in "
                "the future than a freshly-minted token would be, "
                "or issued by an application currently marked "
                "active=False. Adds a ``reasons`` column listing "
                "which checks fired."
            ),
        )
        parser.add_argument(
            "--format",
            default="table",
            choices=FORMAT_CHOICES,
        )

    @override
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

        suspicious_only: bool = options["suspicious"]
        # Anchor "now" once per invocation so TTL anomaly classification
        # is consistent across rows even on slow listings.
        now = timezone.now()

        # ``pkce_required`` mirrors the matching ``AllianceAuthApplication``'s
        # field. The ``select_related("application")`` above keeps this an
        # in-memory attribute access — no extra query per row. Useful when
        # triaging "did this token come from a strict-PKCE client?" without
        # context-switching to admin. Column name matches the model field
        # for symmetry with ``oidc_create_app`` output.
        # ``format`` derives from the persisted token bytes via the
        # heuristic in ``views.classify_token_format`` — JWT tokens
        # render ``"jwt"``, anything else (opaque, hashed-at-rest)
        # renders ``"opaque"``. Documented as the verification step
        # in ``docs/JWT_ACCESS_TOKENS.md`` migration recipe.
        rows: list[dict[str, Any]] = []
        for t in qs.order_by("-expires").iterator():
            row: dict[str, Any] = {
                "id": t.id,
                "user": getattr(t.user, "username", None),
                "client_id": getattr(t.application, "client_id", None),
                "scope": t.scope,
                "expires": t.expires.isoformat() if t.expires else "",
                "pkce_required": getattr(t.application, "pkce_required", None),
                "format": classify_token_format(t.token) or "opaque",
            }
            if suspicious_only:
                reasons = _classify_suspicious(t, now=now)
                if not reasons:
                    continue
                row["reasons"] = ",".join(reasons)
            rows.append(row)

        columns: tuple[str, ...] = (
            "id",
            "user",
            "client_id",
            "scope",
            "expires",
            "pkce_required",
            "format",
        )
        if suspicious_only:
            columns = (*columns, "reasons")

        self.stdout.write(
            render_rows(
                rows,
                columns=columns,
                fmt=options["format"],
            )
        )


def _classify_suspicious(token: Any, *, now: datetime) -> list[str]:
    """
    Return the list of suspicious-check reason codes a token matches.

    Empty list means "looks normal under the operator's current config".

    Checks (each emits its own reason code):

    * ``ttl_anomaly`` — ``expires`` is farther in the future than a
      freshly-minted token would be (``now + ACCESS_TOKEN_EXPIRE_SECONDS
      + skew``). The dispatcher always sets ``expires`` from the
      deployment-default at issue time, so a row past that ceiling
      either pre-dates a TTL reduction or was hand-edited. Either
      way it deserves operator attention.
    * ``disabled_app`` — the application is currently marked
      ``active=False``. ``is_usable()`` returns False so DOT will
      not authorise new requests, but tokens minted earlier remain
      valid until ``expires``. Surfacing them lets operators
      proactively revoke instead of waiting for expiry.

    Reason codes are stable strings (greppable from JSON output).
    Never raises — defensive ``getattr`` keeps the listing useful
    when fed orphaned rows whose ``application`` was deleted.
    """
    reasons: list[str] = []
    expires = getattr(token, "expires", None)
    if expires is not None:
        ceiling = (
            now
            + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
            + _TTL_ANOMALY_SKEW
        )
        if expires > ceiling:
            reasons.append("ttl_anomaly")
    app = getattr(token, "application", None)
    if app is not None and getattr(app, "active", True) is False:
        reasons.append("disabled_app")
    return reasons
