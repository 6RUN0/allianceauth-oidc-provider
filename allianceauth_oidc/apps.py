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
        """Wire OIDC signals + cache invalidators on app load."""
        # Explicit connect calls — see ``signals.connect_default_receiver``
        # and ``app_settings.connect_invalidator`` for why these are
        # not side-effects on module import.
        from .app_settings import connect_invalidator
        from .signals import connect_default_receiver

        connect_default_receiver()
        connect_invalidator()
