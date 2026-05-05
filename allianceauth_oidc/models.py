"""Custom OAuth2 Application model with AA state/group access policy."""

from allianceauth.authentication.models import State
from django.contrib.auth.models import Group
from django.db import models
from oauth2_provider.models import AbstractApplication


class AllianceAuthApplication(AbstractApplication):
    """OAuth2 Application restricted by Alliance Auth states and groups."""

    logo_url = models.URLField(
        max_length=1024,
        blank=True,
        default="",
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
        Return whether the application is usable for ``request``.

        :param request: The oauthlib.common.Request being processed.
        """
        return self.active

    class Meta:
        permissions = [
            ("access_oidc", "Can Authenticate External Apps with OIDC")
        ]
