"""Alliance Auth OIDC Provider."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

# Single source of truth for the version is ``pyproject.toml``. At
# runtime we read the installed-distribution metadata so the value
# never drifts from the wheel that's actually deployed. The fallback
# matters only for editable / source checkouts where the metadata
# may not be installed yet.
try:
    __version__ = _version("allianceauth-oidc-provider-eveo7")
except PackageNotFoundError:
    __version__ = "0.0.0+local"
