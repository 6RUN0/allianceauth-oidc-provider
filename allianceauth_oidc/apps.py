"""Django AppConfig for the OIDC provider."""

from django.apps import AppConfig
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

from . import __version__


class AllianceAuthOIDC(AppConfig):
    """Connects the ``oidc_token_issued`` audit receiver on app load."""

    name = "allianceauth_oidc"
    label = "allianceauth_oidc"

    # ``format_lazy`` keeps the verbose_name translation lazy so the
    # admin renders it in the active language at request time, not the
    # language that happened to be active at import.
    verbose_name = format_lazy(
        _("Alliance Auth OIDC v{version}"),
        version=__version__,
    )

    def ready(self):
        """Connect the default audit receiver to ``oidc_token_issued``."""
        # Side-effect import: connects oidc_token_issued signal receivers.

        # bound name is intentionally unused.
        from . import (
            signals,  # noqa: F401  # pyright: ignore[reportUnusedImport]
        )
