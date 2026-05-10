"""Custom OAuth2 Application model with AA state/group access policy."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import socket
from urllib.parse import urlsplit

from allianceauth.authentication.models import State
from django.conf import settings
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from oauth2_provider.models import AbstractApplication
from typing_extensions import override

from .constants import PERM_ACCESS_OIDC_CODENAME

logger = logging.getLogger(f"extensions.{__name__}")

# Per plan v5 §4.5: ``socket.setdefaulttimeout`` does NOT bound
# ``getaddrinfo`` (a libc resolver call, not a Python socket
# operation). A per-call ``ThreadPoolExecutor`` is the only correct
# way to enforce a wall-clock timeout on the resolver.
_DNS_BOUND_SECONDS = 3


def _resolve_host_bounded(
    host: str, deadline_seconds: int = _DNS_BOUND_SECONDS
) -> list[tuple]:
    """
    Resolve ``host`` with a real wall-clock bound.

    Returns the raw ``socket.getaddrinfo`` result list. Callers must
    extract address strings via ``addr[4][0]``.

    ``max_workers=1`` because exactly one resolver thread is needed
    per call; the executor is GC'd at context-manager exit. Trades
    one thread-creation per admin form save for module-level pool
    lifecycle management — negligible vs the DNS round-trip itself.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(
            socket.getaddrinfo,
            host,
            None,
            type=socket.SOCK_STREAM,
        )
        return fut.result(timeout=deadline_seconds)


# Module-level so admin/forms/tests can re-import the same source of
# truth, mirroring DOT's ``CLIENT_TYPES`` / ``GRANT_TYPES`` pattern on
# ``AbstractApplication``. Translations live on the values; the keys
# travel through DOT/oauthlib unchanged.
ACCESS_TOKEN_FORMAT_OPAQUE = "opaque"  # nosec B105 - enum value, not a password
ACCESS_TOKEN_FORMAT_JWT = "jwt"  # nosec B105 - enum value, not a password
ACCESS_TOKEN_FORMAT_CHOICES = [
    (ACCESS_TOKEN_FORMAT_OPAQUE, _("Opaque (random string)")),
    (ACCESS_TOKEN_FORMAT_JWT, _("JWT (RFC 9068)")),
]


class AllianceAuthApplication(AbstractApplication):
    """OAuth2 Application restricted by Alliance Auth states and groups."""

    logo_url = models.URLField(
        max_length=1024,
        blank=True,
        default="",
        # The default URLValidator allows ftp/ftps too, which are useless
        # for an `<img src>` and only widen the surface for stored XSS via
        # `data:`/`javascript:` hand-crafted around browser quirks.
        # Restrict to the two schemes we actually render.
        validators=[URLValidator(schemes=["http", "https"])],
        help_text=_(
            "URL to the application's icon (128x128). Can be a local static-file URL or an absolute http(s) URL."  # noqa: E501
        ),
    )
    states = models.ManyToManyField(State, blank=True)
    groups = models.ManyToManyField(Group, blank=True)
    active = models.BooleanField(default=True)
    debug_mode = models.BooleanField(
        default=False,
        help_text=_(
            "Enables additional OIDC debug logging (INFO). Secrets/tokens are always redacted/masked according to settings."  # noqa: E501
        ),
    )
    pkce_required = models.BooleanField(
        default=True,
        verbose_name=_("PKCE required"),
        help_text=_(
            "If enabled, this application must use PKCE on the authorization endpoint (RFC 7636 / 9700). Disable only for known-incompatible clients; new applications default to enabled."  # noqa: E501
        ),
    )
    # ``null=True`` is intentional: the form's "blank" state must persist
    # as ``None`` (not ``""``) so the resolver's
    # ``per_app in ("opaque", "jwt")`` gate falls through cleanly to the
    # global default. See plan v3 AC and Critic finding C-N15.
    access_token_format = models.CharField(  # noqa: DJ001
        max_length=8,
        choices=ACCESS_TOKEN_FORMAT_CHOICES,
        blank=True,
        null=True,
        default=None,
        verbose_name=_("Access token format"),
        help_text=_(
            "Wire format of access tokens issued for this application. Leave blank to use the deployment-wide default (OAUTH2_PROVIDER['ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT'], or 'opaque' if unset)."  # noqa: E501
        ),
    )
    # OIDC Back-Channel Logout 1.0 §2.4 — the RP's endpoint that
    # accepts a signed ``logout_token`` POST when the AS terminates
    # the user's session. Empty string disables BCL for this RP.
    # ``URLValidator(schemes=['http','https'])`` mirrors ``logo_url``:
    # ``ftp://`` is meaningless for a token POST and only widens the
    # SSRF surface. The ``clean()`` override adds two additional
    # gates per plan v5 §5.1 AC-3 / AC-3a / AC-3b:
    #   * ``http://`` is rejected unless ``settings.DEBUG`` is True;
    #   * the host's DNS resolution is checked against private /
    #     loopback / link-local / multicast / reserved IPs;
    #   * transient DNS failures are non-blocking (WARNING-logged).
    backchannel_logout_uri = models.URLField(
        max_length=1024,
        blank=True,
        default="",
        validators=[URLValidator(schemes=["http", "https"])],
        verbose_name=_("Back-channel logout URI"),
        help_text=_(
            "RP endpoint that accepts back-channel logout_token POSTs (OIDC Back-Channel Logout 1.0). Leave blank to disable. https:// required unless DEBUG is on; host must resolve to a public IP."  # noqa: E501
        ),
    )

    @override
    def is_usable(self, request):
        """
        Return whether the application is usable.

        The ``request`` argument is required by django-oauth-toolkit's
        ``AbstractApplication`` contract (parameter name must match for type-
        checker override compatibility) but unused — the active flag is a
        property of the app itself, independent of the incoming
        ``oauthlib.common.Request``. The ``@override`` decorator makes the
        contract a checker-enforced invariant: if DOT ever renames or
        removes ``is_usable``, mypy / basedpyright fails the build instead
        of silently letting ``active=False`` apps issue tokens.
        """
        return self.active

    @override
    def clean(self) -> None:
        """
        Reject configurations that would issue tokens with a key
        the operator did not configure.

        ``algorithm="HS256"`` + ``access_token_format="jwt"`` is
        incoherent: the id_token would sign with the per-app HMAC key
        (DOT's ``finalize_id_token`` honours ``self.algorithm``) while
        the JWT access_token would sign with the deployment-wide
        ``OIDC_RSA_PRIVATE_KEY`` (RS256). Two different keys for two
        tokens of the same session is a confusing failure mode that
        breaks the operator's mental model and surfaces only at
        runtime as ``MalformedFraming`` if no RSA key is configured.

        Raised at ``full_clean()`` so the admin form rejects the
        combination before persistence; the error is keyed on
        ``access_token_format`` so the form points at the offending
        field.
        """
        super().clean()
        if (
            self.access_token_format == ACCESS_TOKEN_FORMAT_JWT
            and self.algorithm == self.HS256_ALGORITHM
        ):
            raise ValidationError(
                {
                    "access_token_format": _(
                        "JWT access tokens require the application's id_token signing algorithm to be RS256, not HS256. Either set Algorithm to RS256 or pick an opaque (or blank) access-token format."  # noqa: E501
                    ),
                }
            )
        if self.backchannel_logout_uri:
            self._validate_backchannel_logout_uri()

    def _validate_backchannel_logout_uri(self) -> None:
        """
        Plan v5 §5.1 AC-3 / AC-3a / AC-3b — enforce TLS in production
        and gate DNS resolution against private/loopback/link-local
        IPs to close the SSRF surface on the worker's outbound POST.

        Per AC-3b, transient resolver failures are non-blocking: the
        admin save is allowed and a WARNING is logged for monitoring.
        Operators decide whether to alert on the warning frequency.
        """
        parsed = urlsplit(self.backchannel_logout_uri)
        if parsed.scheme == "http" and not settings.DEBUG:
            raise ValidationError(
                {
                    "backchannel_logout_uri": _(
                        "backchannel_logout_uri must use https:// unless DEBUG is enabled (development only)."  # noqa: E501
                    ),
                }
            )
        host = parsed.hostname or ""
        if not host:
            return
        try:
            infos = _resolve_host_bounded(host)
        except (
            TimeoutError,
            socket.gaierror,
            OSError,
            concurrent.futures.TimeoutError,
        ) as err:
            logger.warning(
                "could not verify backchannel_logout_uri host resolves to a public address: %s: %r",  # noqa: E501
                host,
                err,
            )
            return
        allow_private = getattr(
            settings,
            "ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE",
            False,
        )
        if allow_private:
            return
        for info in infos:
            addr_str = info[4][0]
            try:
                addr = ipaddress.ip_address(addr_str)
            except ValueError:
                continue
            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_reserved
            ):
                raise ValidationError(
                    {
                        "backchannel_logout_uri": _(
                            "backchannel_logout_uri must resolve to a public IP; private/loopback/link-local addresses are blocked. Set ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True for dev environments."  # noqa: E501
                        ),
                    }
                )

    class Meta:
        # `ordering` makes the admin changelist's pagination stable.
        # Without it, PostgreSQL returns rows in storage order, which
        # shifts as updates rewrite tuples — page 2 today is not page 2
        # tomorrow. `name` matches the admin's primary search field.
        ordering = ("name",)
        verbose_name = _("Alliance Auth OIDC application")
        verbose_name_plural = _("Alliance Auth OIDC applications")
        permissions = [
            (
                PERM_ACCESS_OIDC_CODENAME,
                _("Can Authenticate External Apps with OIDC"),
            )
        ]
