from django.apps import AppConfig

from . import __version__


class AllianceAuthOIDC(AppConfig):
    name = "allianceauth_oidc"
    label = "allianceauth_oidc"

    verbose_name = f"Alliance Auth OIDC v{__version__}"

    def ready(self):
        # Side-effect import: connects oidc_token_issued signal receivers.
        import allianceauth_oidc.signals  # noqa: F401  # pyright: ignore[reportUnusedImport]
