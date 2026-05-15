"""
Discovery endpoint: augmented ``.well-known/openid-configuration``.

Adds the OIDC Discovery 1.0 §3 RECOMMENDED fields that DOT omits
upstream — ``grant_types_supported`` and ``claim_types_supported``
are flagged by the conformance suite, and back-channel logout RPs
feature-detect off ``backchannel_logout_supported``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final

from django.conf import settings
from oauth2_provider.views.oidc import ConnectDiscoveryInfoView

if TYPE_CHECKING:
    from django.http import HttpRequest, JsonResponse

# OIDC Discovery 1.0 §3 RECOMMENDED fields. ``grant_types_supported``
# defaults to ``["authorization_code", "implicit"]`` per spec — we
# advertise the actual subset DOT routes plus ``refresh_token``, since
# the provider issues refresh tokens. The conformance suite
# (``oidcc-refresh-token``) flags missing
# ``grant_types_supported`` via
# ``EnsureServerConfigurationSupportsRefreshToken`` even though we do
# emit refresh tokens. Note: spec uses RFC 6749 grant-type names
# (underscore) — DOT's *internal* model constants use kebab-case for
# different purposes, do not confuse the two.
_GRANT_TYPES_SUPPORTED: Final[list[str]] = [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "password",
    "implicit",
]


# OIDC Core 1.0 §5.6 defines three claim types: ``normal``,
# ``aggregated``, ``distributed``. We only emit normal claims — the
# aggregated / distributed forms involve external claim providers
# this provider does not implement.
_CLAIM_TYPES_SUPPORTED: Final[list[str]] = ["normal"]


# OIDC Discovery 1.0 §3 OPTIONAL provider-information URLs. Both are
# operator-provided; emit them only when the corresponding Django
# setting is non-empty so the discovery JSON stays minimal by default
# and the GDPR / NIS2 compliance posture is opt-in. Reading via
# ``getattr(settings, ...)`` rather than threading through
# ``OIDCSettings`` because these are one-shot, request-path,
# string-only knobs — the snapshot cache is overkill for two strings
# that change at the same cadence as the rest of ``settings.py``.
_KEY_POLICY_URI: Final[str] = "ALLIANCEAUTH_OIDC_POLICY_URI"
_KEY_TOS_URI: Final[str] = "ALLIANCEAUTH_OIDC_TOS_URI"


# OIDC Core 1.0 §3 — the only response_type this provider implements.
# DOT's stock discovery view echoes its full enum including implicit
# (``token``, ``id_token``) and hybrid (``code id_token``, ...) forms,
# which is misleading: per-app ``authorization_grant_type`` gating
# rejects non-code requests at runtime (see
# ``TestResponseTypeRestriction``). Narrow the advertisement so RP-side
# libraries auto-selecting from this list pick the only flow we
# actually support.
_RESPONSE_TYPES_SUPPORTED: Final[list[str]] = ["code"]


class AllianceAuthDiscoveryView(ConnectDiscoveryInfoView):
    """
    DOT discovery view augmented with OIDC Discovery 1.0 §3 RECOMMENDED
    fields the upstream view omits: ``grant_types_supported`` and
    ``claim_types_supported``. The conformance suite warns about both
    when missing; downstream client libraries also feature-detect via
    ``grant_types_supported`` to decide whether refresh-token rotation
    is offered.
    """

    def get(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> JsonResponse:
        """Decorate the upstream JSON body with our extra fields."""
        upstream = super().get(request, *args, **kwargs)
        # Re-decode upstream JSON rather than reach into DOT internals
        # so a future field rename in DOT doesn't silently desync.
        data = json.loads(upstream.content)
        data["grant_types_supported"] = list(_GRANT_TYPES_SUPPORTED)
        data["claim_types_supported"] = list(_CLAIM_TYPES_SUPPORTED)
        data["response_types_supported"] = list(_RESPONSE_TYPES_SUPPORTED)
        # OIDC Discovery 1.0 §3 — clients that do RFC 9068 JWT
        # access-token validation feature-detect on this field. The
        # provider only signs with RS256 (DOT's only id_token alg
        # we wire up); per-app overrides do not change the algorithm.
        data["access_token_signing_alg_values_supported"] = ["RS256"]
        # OIDC Back-Channel Logout 1.0 §3 discovery — RPs feature-
        # detect on this single flag. v1 is sub-only logout
        # (path-b in plan v5), so we deliberately DO NOT emit
        # ``backchannel_logout_session_supported``; that companion
        # flag promises ``sid``-scoped logout, which the AS reserves
        # for feature v2.
        data["backchannel_logout_supported"] = True
        # OIDC Discovery 1.0 §3 OPTIONAL ``op_policy_uri`` /
        # ``op_tos_uri``: links to the AS's privacy policy and
        # terms-of-service pages. Several compliance frameworks
        # (GDPR Art. 13 transparency, NIS2 incident reporting)
        # require RPs to surface these to end users; advertising
        # them here lets RP-side login pages auto-link without
        # static configuration on every relying party.
        policy_uri = getattr(settings, _KEY_POLICY_URI, "") or ""
        if policy_uri:
            data["op_policy_uri"] = policy_uri
        tos_uri = getattr(settings, _KEY_TOS_URI, "") or ""
        if tos_uri:
            data["op_tos_uri"] = tos_uri
        # Mutate the upstream ``JsonResponse`` in place rather than
        # constructing a fresh one. ``JsonResponse(data)`` would
        # silently drop every header DOT or downstream middleware
        # attached to ``upstream`` (``Vary``, ``Cache-Control``,
        # custom CSP overrides), leaving only the ones we set below.
        # ``response.content = ...`` resets ``Content-Length``;
        # ``Content-Type`` stays ``application/json`` from
        # ``JsonResponse``.
        upstream.content = json.dumps(data).encode("utf-8")
        upstream["Access-Control-Allow-Origin"] = "*"
        return upstream
