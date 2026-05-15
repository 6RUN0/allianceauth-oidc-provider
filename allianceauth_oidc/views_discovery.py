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


# RFC 8414 §2 / OIDC Discovery 1.0 §3 OPTIONAL fields a security-aware
# RP feature-detects on before sending PKCE / ACR / silent-auth flows.
# Each constant corresponds to behaviour already implemented elsewhere
# in this provider; advertising it explicitly closes the conformance
# gap that ``oidcc-discovery-endpoint-verification`` flags as a
# warning ("server claims OIDC but advertises no code_challenge
# method").
#
# * ``S256`` — the only PKCE transform RFC 7636 §4.2 allows in a
#   modern AS; ``plain`` is forbidden by RFC 9700 §2.1.1.
# * ``0`` — RFC 6711 "no specific level" fallback emitted by
#   :meth:`AllianceAuthOAuth2Validator._inject_acr_fallback` when the
#   RP requested ``acr`` but the AS cannot satisfy a concrete level.
# * ``query`` / ``fragment`` / ``form_post`` — the three response
#   delivery modes DOT's authorize view actually implements. SAML-
#   style ``form_post`` is rarely the default but tested via
#   ``response_mode=form_post`` in DOT's own suite.
# * ``none`` / ``login`` / ``consent`` — the prompt values
#   :meth:`AuthAuthorizationView.dispatch` understands (silent auth
#   via ``validate_silent_login`` / ``validate_silent_authorization``;
#   force-reauth via :meth:`_enforce_reauth`; force-consent via
#   :class:`_ForceConsentRequired`). ``select_account`` is
#   deliberately omitted — the provider has no multi-account UX.
_CODE_CHALLENGE_METHODS_SUPPORTED: Final[list[str]] = ["S256"]
_ACR_VALUES_SUPPORTED: Final[list[str]] = ["0"]
_RESPONSE_MODES_SUPPORTED: Final[list[str]] = [
    "query",
    "fragment",
    "form_post",
]
_PROMPT_VALUES_SUPPORTED: Final[list[str]] = ["none", "login", "consent"]


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
        # PKCE / ACR / silent-auth feature flags — emitted
        # unconditionally because each one mirrors a concrete
        # behaviour already implemented in the authorize / token
        # path (see the constants above for the cross-reference).
        data["code_challenge_methods_supported"] = list(
            _CODE_CHALLENGE_METHODS_SUPPORTED
        )
        data["acr_values_supported"] = list(_ACR_VALUES_SUPPORTED)
        data["response_modes_supported"] = list(_RESPONSE_MODES_SUPPORTED)
        data["prompt_values_supported"] = list(_PROMPT_VALUES_SUPPORTED)
        # OIDC Core 1.0 §5.5 ``claims`` request parameter is honoured
        # by ``_select_requested_id_token_claims`` on the validator
        # (used to narrow the id_token and to inject ``acr=0``); RPs
        # that send it depend on this flag to decide whether the
        # request will be respected or silently dropped.
        data["claims_parameter_supported"] = True
        # JAR (RFC 9101 ``request`` JWT) and PAR (RFC 9126 ``request_uri``)
        # are NOT implemented. OIDC Discovery 1.0 §3 requires the
        # flags to default to ``false`` when absent, but several RP
        # libraries fail closed when the keys are missing entirely;
        # emit them explicitly so RP-side preflight logic does not
        # fall over.
        data["request_parameter_supported"] = False
        data["request_uri_parameter_supported"] = False
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
