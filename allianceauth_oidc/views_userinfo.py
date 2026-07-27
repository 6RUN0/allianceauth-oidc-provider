"""
Userinfo endpoint with OIDC §5.3.2-compliant cache headers.

DOT's :class:`oauth2_provider.views.oidc.UserInfoView` returns
identity claims but does not set ``Cache-Control`` — so any HTTP
cache layer between the AS and RP (proxy, CDN, browser disk cache)
may store the response. OIDC Core 1.0 §5.3.2 SHOULD: userinfo
response carries ``Cache-Control: no-store`` and ``Pragma: no-cache``
so identity claims do not survive past the request that produced
them.

The wrapper is a one-line subclass: a class-level
``@method_decorator(cache_control(no_store=True))`` adds the header
before DOT's view writes the body. ``Pragma`` is set explicitly
because :func:`cache_control` only handles ``Cache-Control``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from django.views.decorators.csrf import csrf_exempt
from oauth2_provider.views.oidc import UserInfoView

if TYPE_CHECKING:
    from django.http import HttpRequest, HttpResponseBase


# csrf_exempt must be re-applied here: Django's ``as_view()`` copies
# the marker from ``cls.dispatch``, and overriding ``dispatch`` below
# replaces DOT's decorated method with an unmarked one. Without it,
# cookie-less RP POSTs to userinfo (OIDC Core 1.0 §5.3.1 requires the
# POST binding) die in CsrfViewMiddleware with a 403 HTML page.
@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(cache_control(no_store=True), name="dispatch")
class AllianceAuthUserInfoView(UserInfoView):
    """
    DOT UserInfoView + OIDC §5.3.2 cache headers.

    ``Cache-Control: no-store`` is set by the class-level decorator;
    ``Pragma: no-cache`` is added in :meth:`dispatch` so legacy HTTP/1.0
    caches (or middleware that honours Pragma over Cache-Control) see
    the same intent.
    """

    def dispatch(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> HttpResponseBase:
        """Add Pragma alongside the decorator's Cache-Control."""
        response = super().dispatch(request, *args, **kwargs)
        response["Pragma"] = "no-cache"
        return response
