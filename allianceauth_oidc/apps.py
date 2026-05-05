"""Django AppConfig for the OIDC provider."""

from django.apps import AppConfig

from . import __version__


class AllianceAuthOIDC(AppConfig):
    """Connects the ``oidc_token_issued`` audit receiver on app load."""

    name = "allianceauth_oidc"
    label = "allianceauth_oidc"

    verbose_name = f"Alliance Auth OIDC v{__version__}"

    def ready(self):
        """Connect the default audit receiver to ``oidc_token_issued``."""
        # Side-effect import: connects oidc_token_issued signal receivers.
        import allianceauth_oidc.signals  # noqa: F401  # pyright: ignore[reportUnusedImport]
