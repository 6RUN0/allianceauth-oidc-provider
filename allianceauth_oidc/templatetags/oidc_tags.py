"""
Template tags / filters for the OIDC provider templates.

Centralised here so the render-side defence can be applied consistently
to every site that emits an admin-controlled URL into a browser context.
"""

from typing import Final
from urllib.parse import urlparse

from django import template

register = template.Library()

_ALLOWED_IMAGE_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})


@register.filter
def safe_image_url(value: object) -> str:
    """
    Return ``value`` only if it parses as an http/https URL, else ``""``.

    Defence-in-depth for ``<img src="...">``: the model's ``URLValidator``
    (see ``models.AllianceAuthApplication.logo_url``) restricts schemes to
    ``http``/``https``, but Django runs validators only when something
    calls ``full_clean()`` — ``bulk_create``, ``loaddata``, raw ``.save()``
    and shell-level ORM writes all bypass it. Filtering at render time
    closes that gap so a stored ``javascript:`` / ``data:`` URL cannot
    reach the browser regardless of how it got into the database.
    """
    if not isinstance(value, str) or not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme.lower() not in _ALLOWED_IMAGE_SCHEMES:
        return ""
    return value
