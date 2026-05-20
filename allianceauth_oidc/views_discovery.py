"""
Discovery endpoint: augmented ``.well-known/openid-configuration``.

Adds the OIDC Discovery 1.0 §3 RECOMMENDED fields that DOT omits
upstream — ``grant_types_supported`` and ``claim_types_supported``
are flagged by the conformance suite, and back-channel logout RPs
feature-detect off ``backchannel_logout_supported``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from django.conf import settings
from oauth2_provider.views.oidc import (
    ConnectDiscoveryInfoView,
    JwksInfoView,
)

if TYPE_CHECKING:
    from django.http import HttpRequest, JsonResponse


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


@dataclass(frozen=True, slots=True)
class DiscoveryCapabilities:
    """
    Closed enumeration of capability lists this provider advertises.

    Bundles the seven RFC 8414 / OIDC Discovery 1.0 §3 capability
    enumerations that previously lived as seven independent
    ``Final[list[str]]`` module constants. Each tuple member is
    structurally a closed value-set documented in the spec; pinning
    them on one frozen dataclass keeps the discovery payload
    contract in one scroll instead of forcing a reader to chase
    each constant + its mapping line independently.

    Tuples (not lists) because the dataclass is ``frozen`` — list
    fields would still be runtime-mutable through the frozen
    wrapper. ``slots=True`` shaves ``__dict__`` for the singleton.
    """

    grant_types_supported: tuple[str, ...]
    claim_types_supported: tuple[str, ...]
    response_types_supported: tuple[str, ...]
    code_challenge_methods_supported: tuple[str, ...]
    acr_values_supported: tuple[str, ...]
    response_modes_supported: tuple[str, ...]
    prompt_values_supported: tuple[str, ...]
    access_token_signing_alg_values_supported: tuple[str, ...]

    def as_discovery_dict(self) -> dict[str, list[str]]:
        """
        Render the capability bundle into the discovery JSON shape.

        Returns plain ``list`` values because OIDC RP libraries
        feature-detect on JSON arrays — DOT's downstream JSON
        encoder also accepts tuples, but RP-side parsers may not.
        Each call constructs fresh lists so a downstream mutation
        cannot corrupt the singleton.
        """
        return {
            "grant_types_supported": list(self.grant_types_supported),
            "claim_types_supported": list(self.claim_types_supported),
            "response_types_supported": list(self.response_types_supported),
            "code_challenge_methods_supported": list(
                self.code_challenge_methods_supported
            ),
            "acr_values_supported": list(self.acr_values_supported),
            "response_modes_supported": list(self.response_modes_supported),
            "prompt_values_supported": list(self.prompt_values_supported),
            "access_token_signing_alg_values_supported": list(
                self.access_token_signing_alg_values_supported
            ),
        }


# Process-wide singleton — read-only after import. Each tuple
# documents the spec citation and the cross-reference to the
# behaviour that backs the advertisement.
#
# * ``grant_types_supported`` — OIDC Discovery 1.0 §3. Defaults to
#   ``["authorization_code", "implicit"]`` per spec; we advertise
#   the actual subset DOT routes plus ``refresh_token`` (the
#   provider issues refresh tokens, and the conformance suite
#   ``oidcc-refresh-token`` flags missing inclusion via
#   ``EnsureServerConfigurationSupportsRefreshToken``). Spec uses
#   RFC 6749 underscore form — DOT's *internal* model constants
#   use kebab-case for different purposes; do not confuse the two.
# * ``claim_types_supported`` — OIDC Core 1.0 §5.6. ``aggregated``
#   / ``distributed`` involve external claim providers this
#   provider does not implement.
# * ``response_types_supported`` — OIDC Core 1.0 §3. DOT's stock
#   discovery view echoes its full enum (implicit + hybrid forms)
#   which is misleading: per-app ``authorization_grant_type`` gating
#   rejects non-code requests at runtime (see
#   ``TestResponseTypeRestriction``).
# * ``code_challenge_methods_supported`` — RFC 7636 §4.2. ``plain``
#   is forbidden by RFC 9700 §2.1.1.
# * ``acr_values_supported`` — RFC 6711 "no specific level"
#   fallback emitted by
#   :meth:`AllianceAuthOAuth2Validator._inject_acr_fallback`.
# * ``response_modes_supported`` — three delivery modes DOT's
#   authorize view actually implements.
# * ``prompt_values_supported`` — the prompt values
#   :meth:`AuthAuthorizationView.dispatch` understands.
#   ``select_account`` deliberately omitted: no multi-account UX.
# * ``access_token_signing_alg_values_supported`` — OIDC Discovery
#   1.0 §3. Clients doing RFC 9068 JWT access-token validation
#   feature-detect on this; provider only signs with RS256.
_CAPABILITIES: Final[DiscoveryCapabilities] = DiscoveryCapabilities(
    # F-5: ``password`` (RFC 6749 §4.3) and ``implicit`` (RFC 6749 §4.2)
    # were deprecated by RFC 9700 §2.1.2/§2.1.1. ``response_types_supported``
    # below already pins ``("code",)`` and per-app
    # ``authorization_grant_type`` gating rejects non-code requests at
    # runtime; advertising them in ``grant_types_supported`` was a
    # spec-conformance lie that invited RP libraries to try
    # password/implicit flows and silently observe ``invalid_grant``
    # responses they could not diagnose. The remaining three reflect
    # what this provider actually issues: authorization_code (the
    # primary OIDC flow), refresh_token (rotation under
    # ``OAUTH2_PROVIDER.ROTATE_REFRESH_TOKEN``), and client_credentials
    # (machine-to-machine; restricted by per-app
    # ``authorization_grant_type``).
    grant_types_supported=(
        "authorization_code",
        "refresh_token",
        "client_credentials",
    ),
    claim_types_supported=("normal",),
    response_types_supported=("code",),
    code_challenge_methods_supported=("S256",),
    acr_values_supported=("0",),
    response_modes_supported=("query", "fragment", "form_post"),
    prompt_values_supported=("none", "login", "consent"),
    access_token_signing_alg_values_supported=("RS256",),
)


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
        # Capability arrays (eight RFC 8414 / OIDC Discovery 1.0 §3
        # fields) come from the single ``_CAPABILITIES`` snapshot —
        # adding a future capability is one tuple entry + one
        # ``as_discovery_dict`` field rather than two scattered edits.
        data.update(_CAPABILITIES.as_discovery_dict())
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


class AllianceAuthJwksInfoView(JwksInfoView):
    """
    Thin wrapper around DOT's ``JwksInfoView`` that adds the
    ``Access-Control-Allow-Origin: *`` header.

    O-1: discovery already advertises the JWKS URI cross-origin
    (via :class:`AllianceAuthDiscoveryView`), but the upstream JWKS
    response itself does not. Browser-based RP libraries
    (``oidc-client-ts``, Auth.js et al.) fetch the JWKS to validate
    id_tokens locally and require CORS on this endpoint or fall back
    to a slower backend round-trip. The header is symmetrically safe
    on JWKS as on discovery: both responses are public-by-design
    crypto metadata.
    """

    def get(
        self, request: HttpRequest, *args: Any, **kwargs: Any
    ) -> JsonResponse:
        """Decorate the upstream JWKS response with a CORS wildcard."""
        response = super().get(request, *args, **kwargs)
        response["Access-Control-Allow-Origin"] = "*"
        return response
