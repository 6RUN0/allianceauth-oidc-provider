"""Custom OAuth2 Application model with AA state/group access policy."""

from __future__ import annotations

import concurrent.futures
import logging
import socket
from typing import Any
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

from . import _dns_safety
from .constants import PERM_ACCESS_OIDC_CODENAME

logger = logging.getLogger(f"extensions.{__name__}")

# Fields scanned by ``AllianceAuthApplication._validate_no_nul_in_uri_fields``.
# Module-level so adding a new URI-shaped field to the model is a one-
# entry diff here, not a hidden append inside the validator loop.
_NUL_GUARDED_URI_FIELDS: tuple[str, ...] = (
    "redirect_uris",
    "post_logout_redirect_uris",
    "backchannel_logout_uri",
)


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
    states = models.ManyToManyField(
        State,
        blank=True,
        related_name="oidc_applications",
        help_text=_(
            "Whitelist of Alliance Auth states allowed to "
            "authenticate this application. Leave empty (with "
            "Groups also empty) to open the app to every user "
            "holding the global OIDC permission."
        ),
    )
    groups = models.ManyToManyField(
        Group,
        blank=True,
        related_name="oidc_applications",
        help_text=_(
            "Whitelist of Django groups allowed to authenticate "
            "this application. A user is granted access if their "
            "state OR any of their groups appears in either "
            "whitelist; leave both empty to open the app."
        ),
    )
    active = models.BooleanField(
        default=True,
        verbose_name=_("Active"),
        help_text=_(
            "Deactivated applications (``Active`` unchecked) cannot "
            "issue authorization codes or tokens. Toggling this off "
            "is the operator-facing kill switch for a compromised "
            "or retired client."
        ),
    )
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
    # Default ``False`` preserves v1 ("all five triggers fire")
    # semantics so the migration is a no-op for existing
    # deployments. Gating contract lives in
    # ``logout.dispatch_backchannel_logout``: any reason ≠
    # ``"user_revoked"`` is silently skipped when the flag is
    # True, including unknown reasons from custom receivers.
    backchannel_logout_on_revoke_only = models.BooleanField(
        default=False,
        verbose_name=_("Back-Channel Logout: explicit revoke only"),
        help_text=_(
            "When checked, this RP receives a back-channel logout_token ONLY when an operator runs oidc_revoke_user_tokens. Lifecycle events (deactivation, group/state changes, account deletion) will NOT fan out to this RP. Default is unchecked (all five triggers fire)."  # noqa: E501
        ),
    )

    @override
    def is_usable(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, request: Any
    ) -> bool:
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
        self._validate_no_nul_in_uri_fields()

    def _validate_no_nul_in_uri_fields(self) -> None:
        r"""
        Reject NUL bytes (``\x00``) in registered URI fields.

        Django's stock ``URLValidator`` regex permits non-control
        bytes in the path segment, including the NUL byte — so a
        URI like ``https://rp/cb\x00.evil/`` survives ``full_clean``
        on a vanilla ``URLField``. Legacy C-string parsers (some
        load balancers, log analysers, syslog forwarders) truncate
        at the first NUL and would dispatch to ``https://rp/cb``
        while the audit log records the full ``.../cb\x00.evil/``
        string. Reject up front so the registered URI cannot mean
        two different things to two different consumers.

        Keyed per field so the admin form points at the offending
        input.
        """
        offending = next(
            (
                f
                for f in _NUL_GUARDED_URI_FIELDS
                if "\x00" in (getattr(self, f, "") or "")
            ),
            None,
        )
        if offending is not None:
            raise ValidationError(
                {
                    offending: _(
                        "NUL byte (\\x00) is not permitted in URI "
                        "fields; legacy parsers truncate at NUL "
                        "and would mean two different things to "
                        "two different consumers."
                    ),
                }
            )

    def _validate_backchannel_logout_uri(self) -> None:
        """
        Plan v5 §5.1 AC-3 / AC-3a / AC-3b — enforce TLS in production
        and gate DNS resolution against private/loopback/link-local
        IPs to close the SSRF surface on the worker's outbound POST.

        Per AC-3b, transient resolver failures are non-blocking: the
        admin save is allowed and a WARNING is logged for monitoring.
        Operators decide whether to alert on the warning frequency.

        Internally split into a scheme half (TLS / DEBUG policy) and
        a target half (DNS-resolved IP). The split exists so the
        ``pre_save`` SSRF gate in
        :func:`allianceauth_oidc.apps._connect_bcl_pre_save_gate`
        can re-run the target half against non-admin write paths
        (``Application.objects.create``, data migrations) without
        also re-running scheme rejection — admin-form-only concerns
        like ``http`` under ``DEBUG=False`` belong on the form, not
        on the model's save path (where they would fail loudly on
        legacy rows already persisted with ``http`` before the
        validator existed).
        """
        self._validate_uri_scheme_safety()
        self._validate_uri_target_safety()

    def _validate_uri_scheme_safety(self) -> None:
        """Admin-form half: reject ``http://`` unless DEBUG is on."""
        parsed = urlsplit(self.backchannel_logout_uri)
        if parsed.scheme == "http" and not settings.DEBUG:
            raise ValidationError(
                {
                    "backchannel_logout_uri": _(
                        "backchannel_logout_uri must use https:// unless DEBUG is enabled (development only)."  # noqa: E501
                    ),
                }
            )

    def _validate_uri_target_safety(self) -> None:
        """
        SSRF half: reject hostnames resolving to private / loopback /
        link-local / multicast / reserved / unspecified IPs.

        Transient DNS failures are non-blocking (admin save allowed,
        WARNING logged); the operator-facing
        ``ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE`` flag bypasses
        the check for dev / in-cluster RPs.

        Shared by the admin-form ``clean()`` path and the
        ``pre_save`` signal in ``apps._connect_bcl_pre_save_gate``;
        the ``send_logout_token`` Celery task ALSO re-runs the
        underlying ``resolve_host_bounded`` +
        ``addresses_have_unsafe`` check at request time as the
        final TOCTOU defence against DNS rebinding between save
        and dispatch.
        """
        parsed = urlsplit(self.backchannel_logout_uri)
        host = parsed.hostname or ""
        if not host:
            return
        try:
            # Module-level reference (not a local ``from … import``)
            # so ``mock.patch("…._dns_safety.resolve_host_bounded")``
            # in tests substitutes the function the runtime call site
            # actually resolves. A ``from`` import would create a
            # local binding that ignores later patching.
            infos = _dns_safety.resolve_host_bounded(host)
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
        if _dns_safety.addresses_have_unsafe(infos):
            raise ValidationError(
                {
                    "backchannel_logout_uri": _(
                        "backchannel_logout_uri must resolve to a public IP; private/loopback/link-local/unspecified addresses are blocked. Set ALLIANCEAUTH_OIDC_LOGOUT_URI_ALLOW_PRIVATE=True for dev environments."  # noqa: E501
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


class BackChannelLogoutAttempt(models.Model):
    """
    Dead-letter / audit row for one ``oidc_logout_dispatched`` event.

    Per-event (not per-``jti``): the dispatcher and the Celery task
    emit exactly one terminal ``oidc_logout_dispatched`` signal per
    logout_token, so a row maps 1:1 to a single dispatch outcome.
    Celery's per-request 5xx retries are transparent — only the
    final ``retries_exhausted`` (or earlier terminal status) lands
    here.

    Defaults to recording **failures only**. Set
    ``ALLIANCEAUTH_OIDC_BCL_AUDIT_SUCCESS=True`` to also record
    successful dispatches (e.g. for full SIEM correlation); off by
    default keeps this table focused on what its name promises —
    deliveries that need operator attention.

    The ``user_pk`` column is a plain integer (not an FK) because
    the ``user_deleted`` trigger fires AFTER the row is gone. A
    nullable column with no FK constraint keeps the audit log
    historically faithful even when the originating user no longer
    exists. Use :meth:`get_user` for a best-effort lookup.

    C-3: the ``application`` FK is ``on_delete=SET_NULL``, NOT
    ``CASCADE`` — admin-driven deletion of an application row must
    NOT wipe its dead-letter history (the operator most needs that
    history when removing a compromised or buggy RP). Two
    snapshot columns (``application_client_id_snapshot`` /
    ``application_name_snapshot``) preserve enough context to
    correlate the row after the FK becomes NULL.
    """

    application = models.ForeignKey(
        "AllianceAuthApplication",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="backchannel_logout_attempts",
        verbose_name=_("Application"),
    )
    # C-3: snapshot columns survive ``application`` becoming NULL on
    # admin-driven RP deletion. Indexed so per-RP forensic queries
    # work for historical rows whose FK is gone. Populated on insert
    # by ``receivers.record_backchannel_logout_attempt`` from the
    # live application instance — the receiver is the single insert
    # path, so backfill cost is zero for existing rows (migration
    # data-copies them once).
    application_client_id_snapshot = models.CharField(
        max_length=100,
        blank=True,
        default="",
        db_index=True,
        verbose_name=_("Application client_id snapshot"),
        help_text=_(
            "Snapshot of the application's client_id at row-insert "
            "time. Survives RP deletion (FK becomes NULL) so per-RP "
            "forensic queries still work for historical events."
        ),
    )
    application_name_snapshot = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name=_("Application name snapshot"),
        help_text=_("Snapshot of the application's name at row-insert time."),
    )
    user_pk = models.PositiveIntegerField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("User PK"),
        help_text=_(
            "Integer primary key of the user whose session was being terminated. Not a ForeignKey because the ``user_deleted`` trigger fires after the row is removed."  # noqa: E501
        ),
    )
    # ``uuid4().hex`` is 32 chars; blank string is intentional for the
    # ``broker_unavailable`` / ``signing_kid_resolve_failed`` cases
    # where the dispatcher never got far enough to mint a jti.
    jti = models.CharField(
        max_length=32,
        blank=True,
        default="",
        db_index=True,
        verbose_name=_("JTI"),
    )
    success = models.BooleanField(
        db_index=True,
        verbose_name=_("Success"),
    )
    attempt_count = models.PositiveSmallIntegerField(
        default=1,
        verbose_name=_("Attempt count"),
        help_text=_(
            "1-based attempt number from the Celery task (1 = first try). Dispatcher-side failures (broker_unavailable, signing_kid_resolve_failed) record 0 because no HTTP attempt was made."  # noqa: E501
        ),
    )
    reason = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        verbose_name=_("Reason"),
        help_text=_(
            "Stable string identifying the dispatch outcome: trigger reason (user_revoked/...) on success, or failure mode (redirect_blocked, rp_client_error, retries_exhausted, signing_kid_retired, broker_unavailable, signing_kid_resolve_failed) on failure."  # noqa: E501
        ),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        verbose_name=_("Created at"),
    )

    class Meta:
        # Newest failures first — operator scanning the dead-letter
        # admin wants "what broke recently", not chronological replay.
        ordering = ("-created_at",)
        verbose_name = _("Back-Channel Logout attempt")
        verbose_name_plural = _("Back-Channel Logout attempts")
        indexes = [
            # Per-RP timeline: "show me failures for app X".
            models.Index(fields=["application", "-created_at"]),
            # Failure-only scan: "show me everything that broke today".
            models.Index(fields=["success", "-created_at"]),
        ]

    @override
    def __str__(self) -> str:
        status = "OK" if self.success else "FAIL"
        # ``application_id`` is the FK's implicit shadow column. The
        # type checker's Django stub does not expose it on the model
        # class, so an ``Any``-typed self-cast keeps the annotation
        # honest without dragging in a per-line ``type: ignore``.
        self_any: Any = self
        return (
            f"BCL {status} app={self_any.application_id} "
            f"jti={self.jti or '-'} reason={self.reason or '-'}"
        )


class IssuedCodeAudit(models.Model):
    """
    Side-table linking an authorization code (by hash) to the tokens
    issued from it, so :meth:`AllianceAuthOAuth2Validator.validate_code`
    can detect reuse and revoke the linked tokens.

    DOT 3.2.0 deletes the ``Grant`` row on first successful exchange,
    leaving ``validate_code`` unable to distinguish "code never
    existed" from "code already used". RFC 6749 §10.5 makes the MUST
    half (reject reuse) automatic — the deleted Grant produces
    ``invalid_grant`` — but the SHOULD half (revoke all tokens issued
    from the reused code) requires keeping the link alive past the
    Grant's lifetime. This model is exactly that link.

    Only a one-way ``sha256`` of the code is stored. The hash is
    deterministic, so reuse-detection at validate-time can re-hash the
    presented code and look it up; the plaintext code is never
    persisted.

    Growth is bounded by :func:`tasks.clear_expired_tokens`, which
    drops rows older than ``REFRESH_TOKEN_EXPIRE_SECONDS`` with
    ``reuse_count=0`` (no security signal, safe to forget) and keeps
    rows with ``reuse_count>=1`` for forensic review until an explicit
    operator cleanup.

    C-4: the ``application`` FK is ``on_delete=SET_NULL``, NOT
    ``CASCADE`` — the docstring promise of preserving
    ``reuse_count>=1`` rows past the cleanup-task TTL must also
    hold against admin-driven app deletion. The
    ``application_client_id_snapshot`` column lets per-RP forensic
    queries continue to work after the FK becomes NULL.
    """

    code_hash = models.CharField(
        max_length=64,
        db_index=True,
        verbose_name=_("Code hash"),
        help_text=_(
            "sha256 hex digest of the authorization code. One-way "
            "by construction — the plaintext code is never stored."
        ),
    )
    application = models.ForeignKey(
        "AllianceAuthApplication",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
        verbose_name=_("Application"),
    )
    application_client_id_snapshot = models.CharField(
        max_length=100,
        blank=True,
        default="",
        db_index=True,
        verbose_name=_("Application client_id snapshot"),
        help_text=_(
            "Snapshot of the application's client_id at row-insert "
            "time. Survives RP deletion (FK becomes NULL) so per-RP "
            "forensic queries still work for ``reuse_count>=1`` "
            "rows after the originating app is gone."
        ),
    )
    # Plain integer PKs (not FKs) for the same reason
    # ``BackChannelLogoutAttempt.user_pk`` is a plain integer: the
    # audit row must survive the target's deletion (e.g. by
    # ``clear_expired_tokens``). A FK with ``on_delete=SET_NULL``
    # would mostly work but would also force Django's migration
    # autodetector to walk DOT's swappable machinery for
    # ``OAUTH2_PROVIDER_ACCESS_TOKEN_MODEL`` /
    # ``OAUTH2_PROVIDER_REFRESH_TOKEN_MODEL``, neither of which this
    # project sets at top level (only the Application swappable is
    # exposed). Looking the tokens up by PK at reuse-detection time
    # gives the same "live or gone" semantic without the dependency.
    access_token_pk = models.PositiveBigIntegerField(
        null=True,
        blank=True,
        verbose_name=_("Access token PK"),
        help_text=_(
            "Integer primary key of the AccessToken row issued by "
            "this code exchange. Resolved at reuse-detection time."
        ),
    )
    refresh_token_pk = models.PositiveBigIntegerField(
        null=True,
        blank=True,
        verbose_name=_("Refresh token PK"),
        help_text=_(
            "Integer primary key of the RefreshToken row issued by "
            "this code exchange. Resolved at reuse-detection time."
        ),
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        verbose_name=_("Created at"),
    )
    reuse_count = models.PositiveIntegerField(
        default=0,
        verbose_name=_("Reuse count"),
        help_text=_(
            "Number of times this code was presented at /o/token/ "
            "after the original exchange. >= 1 indicates a "
            "security-relevant replay attempt."
        ),
    )
    last_reuse_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("Last reuse at"),
    )

    class Meta:
        verbose_name = _("Issued authorization code audit")
        verbose_name_plural = _("Issued authorization code audits")
        # ``(code_hash, application)`` is the natural unique key — two
        # distinct apps could theoretically collide on the same code
        # value (the code generator is per-grant-record, not
        # per-deployment, but the contract is stronger to defend
        # against future generator changes).
        constraints = [
            models.UniqueConstraint(
                fields=["code_hash", "application"],
                name="uniq_codehash_per_app",
            ),
        ]
        indexes = [
            # Cleanup task scans by ``(reuse_count, created_at)`` —
            # see ``tasks.clear_expired_tokens`` for the predicate.
            models.Index(
                fields=["reuse_count", "created_at"],
                name="aaoidc_audit_cleanup_idx",
            ),
        ]

    @override
    def __str__(self) -> str:
        self_any: Any = self
        head = self.code_hash[:12] if self.code_hash else "-"
        return (
            f"IssuedCodeAudit app={self_any.application_id} "
            f"code_hash={head}… reuse_count={self.reuse_count}"
        )
