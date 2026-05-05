"""Custom OAuth2 Application model with AA state/group access policy."""

from allianceauth.authentication.models import State
from django.contrib.auth.models import Group
from django.core.validators import URLValidator
from django.db import models
from oauth2_provider.models import AbstractApplication


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
        help_text="URL to the application's icon (128x128). Can be a local static-file URL or an absolute http(s) URL.",  # noqa: E501
    )
    states = models.ManyToManyField(State, blank=True)
    groups = models.ManyToManyField(Group, blank=True)
    active = models.BooleanField(default=True)
    debug_mode = models.BooleanField(
        default=False,
        help_text="Enables additional OIDC debug logging (INFO). Secrets/tokens are always redacted/masked according to settings.",  # noqa: E501
    )

    def is_usable(self, request):
        """
        Return whether the application is usable.

        The ``request`` argument is required by django-oauth-toolkit's
        ``AbstractApplication`` contract (parameter name must match for
        type-checker override compatibility) but unused — the active flag
        is a property of the app itself, independent of the incoming
        ``oauthlib.common.Request``.
        """
        return self.active

    class Meta:
        permissions = [
            ("access_oidc", "Can Authenticate External Apps with OIDC")
        ]
