"""Custom DOT OAuth2Validator that enforces Alliance Auth access policy."""

from __future__ import annotations

import logging
from typing import Any, Final

from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749 import errors as oauth_errors

from ._metrics import policy_rejections
from .app_settings import OIDCSettings
from .claims import ClaimsBuilder, build_oidc_claim_scope
from .security import (
    DEFAULT_POLICY,
    AllowedDecision,
    AppDeny,
    AppLike,
    GlobalDeny,
    OAuthRequestLike,
    UserLike,
)

logger = logging.getLogger(f"extensions.{__name__}")


# NOTE: ``per_app_pkce_required`` lives in ``allianceauth_oidc.pkce``,
# not here. Operators must assign the callable to
# ``OAUTH2_PROVIDER['PKCE_REQUIRED']`` from inside their settings
# module, which Django evaluates BEFORE ``apps.populate()``. Importing
# from this module at settings-load time fails with
# ``AppRegistryNotReady`` because ``auth_provider`` transitively
# imports ``oauth2_provider.oauth2_validators`` → DOT's
# ``AbstractApplication`` model class definition. The lighter
# ``allianceauth_oidc.pkce`` module imports only ``DEFAULT_POLICY``
# from ``security`` and is safe to import from settings.


# OIDC Core 1.0 §5.4: scope-mapped claims like ``email`` / ``name`` /
# ``picture`` are obliged to surface in the **userinfo** response, not in
# the id_token, unless the client explicitly requests them via the
# ``claims`` request parameter under the ``id_token`` member. The id
# token itself stays minimal and carries only the reserved claims listed
# below (``sub`` plus the standard JWT / OIDC framing). Without this
# whitelist DOT mirrors id_token and userinfo through the same
# scope-filtered dict, which the conformance suite flags via
# ``EnsureIdTokenDoesNotContainEmailForScopeEmail`` in
# ``oidcc-scope-email``.
_ID_TOKEN_RESERVED_CLAIMS: Final[frozenset[str]] = frozenset(
    {
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "acr",
        "amr",
        "azp",
        "at_hash",
        "c_hash",
        "jti",
    }
)


class AllianceAuthOAuth2Validator(OAuth2Validator):
    """Wrap DOT's validator with state/group checks and AA-specific claims."""

    # Cap the `groups` claim payload. JWTs are URL-encoded in headers /
    # cookies and a pathological 10k-group user would produce a 200KB
    # token nobody can use. The state name still gets appended after
    # truncation so consumers that rely on the state being present don't
    # silently lose it. Override via subclassing if your deployment
    # genuinely needs more.
    MAX_GROUPS_IN_CLAIM = 256

    @property
    def oidc_claim_scope(self) -> dict[str, str]:
        """
        Class-shared map of claim → required scope (DOT's filter key).

        Reads the cached ``OIDCSettings`` snapshot — itself backed by
        ``functools.lru_cache`` invalidated on ``setting_changed`` —
        and delegates to a process-level cache keyed on the snapshot.
        Two validator instances under the same settings receive the
        identical dict (no per-instance copy); a settings flip
        produces a fresh ``OIDCSettings`` instance, so the lru_cache
        misses and rebuilds.

        The "groups" → "profile" binding lives here alongside the
        EVE-claim bindings: DOT's ``get_oidc_claims`` filters claims
        by this map, so any claim missing from it never reaches
        userinfo / id_token.
        """
        return build_oidc_claim_scope(OIDCSettings.from_django())

    # Class-level so tests can ``patch.object(AllianceAuthOAuth2Validator,
    # "policy", AccessPolicy(log=...))`` to exercise validators with a
    # captured logger or a custom DI'd policy.
    policy: Final = DEFAULT_POLICY

    @staticmethod
    def _resolve_user_and_client(
        request: OAuthRequestLike, client_arg: AppLike | None = None
    ) -> tuple[UserLike | None, AppLike | None]:
        """
        Pull (user, client) out of the validator's request shape.

        ``validate_code`` / ``validate_refresh_token`` receive ``client``
        as a positional argument; ``save_bearer_token`` doesn't, so it
        falls back to ``request.client`` then ``request.application``
        (oauthlib's older / newer attr names — DOT mutates one or the
        other depending on grant flow).

        Returns ``(None, None)`` for "skip the policy" cases:
        unauthenticated user, missing user, or missing client. Callers
        only run the policy when both halves are present.
        """
        user = getattr(request, "user", None)
        # Treat AnonymousUser the same as None: client_credentials and
        # similar end-user-less grants must not be funnelled through
        # the state/group gate. ``is_authenticated`` is the canonical
        # Django check that covers both ``None`` and AnonymousUser.
        if user is None or not getattr(user, "is_authenticated", False):
            return None, None
        client = (
            client_arg
            or getattr(request, "client", None)
            or getattr(request, "application", None)
        )
        if client is None:
            return None, None
        return user, client

    def _enforce_policy(
        self,
        request: OAuthRequestLike,
        client: AppLike | None,
        *,
        stage: str,
    ) -> bool:
        """
        Run the per-app state/groups gate against ``request.user``.

        Returns True if the policy allows the operation, False otherwise. Used
        as a post-validation hook by validate_code and validate_refresh_token
        so the same gate runs on every token-issuing path; missing it on either
        side leaves a hole.

        ``stage`` is mandatory keyword-only so the ``policy_rejections``
        counter label cannot be accidentally omitted at a new call
        site (and so a reader of the emit can grep one identifier
        across stages — ``"validate_refresh"`` etc.).
        """
        user, resolved_client = self._resolve_user_and_client(request, client)
        if user is None or resolved_client is None:
            return True
        # ``decide`` is structurally a superset of ``is_allowed`` —
        # same gate, but also returns the reason on rejection so the
        # metric can carry it as a label. Tiny extra cost (one
        # dataclass construction per request) for a major dashboard
        # win on "which gate fired in which stage".
        decision = self.policy.decide(user, resolved_client)
        # ``match`` over the AccessDecision discriminated union — both
        # mypy and basedpyright narrow ``decision.deny_reason`` to a
        # non-Optional ``DenyReason`` inside the deny arms, which the
        # plain ``if decision.allowed`` shape did not give basedpyright
        # (reportOptionalMemberAccess). Mirrors the pattern in
        # ``views_authorize.AuthAuthorizationView.dispatch``.
        match decision:
            case AllowedDecision():
                return True
            case GlobalDeny() | AppDeny():
                reason = decision.deny_reason.value
                policy_rejections.labels(stage=stage, reason=reason).inc()
                # Validator path doesn't render a denied page (the
                # OAuth response is the bool → invalid_grant
                # translation), so log here for operator visibility —
                # the policy gate itself is decision-only after the
                # M1 consolidation.
                logger.warning(
                    "OIDC DENIED: validator stage=%s reason=%s "
                    "user=%s client=%s client_id=%s",
                    stage,
                    reason,
                    user,
                    resolved_client,
                    getattr(resolved_client, "client_id", None),
                )
                return False

    def validate_silent_login(self, request):
        """
        OIDC Core 1.0 §3.1.2.1 ``prompt=none`` silent-login gate.

        Returns True for any caller that reaches this point.
        ``oauthlib`` invokes this from inside
        ``openid_authorization_validator``; by the time we get here
        ``AuthAuthorizationView.dispatch`` (and DOT's
        ``LoginRequiredMixin`` underneath it) have already routed
        anonymous Django sessions through ``handle_no_permission``,
        which redirects to ``redirect_uri`` with
        ``error=login_required`` per OIDC §3.1.2.6 — the
        anonymous case never reaches this validator.

        ``oauthlib`` does not propagate the Django session user onto
        the authorize-time ``request`` object, so a user-aware
        implementation is not possible here without first attaching
        ``request.user`` from the view layer; until then this single
        fact (``LoginRequiredMixin`` already passed`` => session user
        exists``) is the correct semantics.

        Without this override the parent abstract raises
        ``NotImplementedError`` and any ``prompt=none`` request from
        an authenticated user 500s the authorize endpoint.
        """
        return True

    def validate_silent_authorization(self, request):
        """
        OIDC Core 1.0 §3.1.2.4 ``prompt=none`` silent-consent gate.

        Returns ``True`` in either of two cases:

        1. The client is operator-declared trusted
           (``skip_authorization=True``) — DOT's
           ``AuthorizationView.get`` auto-approves these without
           rendering a consent screen, so the silent path is
           consistent with the GET path.

        2. The user has previously granted consent for the requested
           scopes on this client — represented by a non-expired
           ``AccessToken`` covering the requested scope set. This
           mirrors the ``approval_prompt=auto`` branch in DOT's
           ``AuthorizationView.get`` and is the canonical
           silent-refresh-in-iframe pattern from SPAs.

        Returning ``False`` causes oauthlib to raise
        ``ConsentRequired``, which DOT translates into a 302 to
        ``redirect_uri`` with ``error=consent_required`` — the
        spec-prescribed answer when consent would otherwise be
        required but the request forbade UI.

        Scope coverage uses set inclusion: the requested scopes must
        be a subset of an existing token's scopes. A prior
        ``openid`` token does NOT cover a new
        ``openid profile`` request — the user has not yet consented
        to the additional claim.
        """
        client = getattr(request, "client", None)
        if getattr(client, "skip_authorization", False):
            return True
        user = getattr(request, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            return False
        requested = set(getattr(request, "scopes", None) or [])
        if not requested:
            # An empty scope set is not a positive proof of consent —
            # let oauthlib drive the no-scope path.
            return False
        # ``AccessToken.application`` FK accepts any concrete
        # subclass of the swappable model. Filter by ``client_id``
        # rather than ``application=client`` to dodge any proxy /
        # cached-instance mismatch between ``request.client`` and
        # the persisted row.
        from django.utils import timezone
        from oauth2_provider.models import get_access_token_model

        AccessToken = get_access_token_model()
        active = AccessToken.objects.filter(
            user=user,
            application__client_id=getattr(client, "client_id", None),
            expires__gt=timezone.now(),
        ).only("scope")
        for token in active:
            if requested.issubset((token.scope or "").split()):
                return True
        return False

    # NOTE: ``validate_code`` / ``validate_refresh_token`` /
    # ``save_bearer_token`` / ``get_additional_claims`` keep their
    # parameters un-annotated. ``oauth2_provider.oauth2_validators``
    # ships type stubs (basedpyright resolves ``Client`` / ``Request``
    # / ``_BearerToken`` from them) and our local ``AppLike`` /
    # ``OAuthRequestLike`` Protocols are structurally narrower than
    # those concrete types, so an explicit annotation here trips
    # ``reportArgumentType`` at every ``super().method(...)`` call.
    # Internal helpers (``_resolve_user_and_client`` / ``_enforce_policy``)
    # do carry the Protocol annotations — they don't cross the parent
    # boundary, so Liskov compatibility doesn't bite there.

    def validate_bearer_token(self, token, scopes, request):
        """
        Re-check user/app policy on every bearer-authenticated request.

        DOT's default only checks ``AccessToken.expires`` and scope
        membership — once an AT is issued, it stays valid for its full
        TTL regardless of the end-user's current state. This override
        symmetrises the contract with ``validate_code`` and
        ``validate_refresh_token`` (both of which re-run the policy
        gate): a user who lost the global ``access_oidc`` permission,
        was marked inactive, fell out of the per-app state/group
        whitelist, or whose application was deactivated, sees ``401``
        on the next userinfo request rather than waiting for AT expiry.

        Three layers, in order of cheapness:

        1. ``app.is_usable`` — closes the ``active=False`` propagation
           gap. The authorize endpoint's ``_get_app`` already filters
           inactive apps; ``validate_code`` / ``_refresh_token`` get
           the same via DOT's ``validate_client_id``. The bearer path
           bypassed both — this is where we re-introduce the check.
        2. ``_enforce_policy`` — global perm + per-app state/group
           gate. Same routine the refresh path uses.

        The per-request cost is one permission lookup plus one M2M
        check for state/groups — typically ≤ 1ms thanks to Django's
        per-user ``_perm_cache``. The security benefit is immediate
        revocation propagation, which is the standard expectation for
        incident response.

        ``super()`` sets ``request.client`` / ``request.user`` before
        returning True, so the policy check below runs with the same
        client/user reference DOT just resolved.
        """
        if not super().validate_bearer_token(token, scopes, request):
            return False
        client = getattr(request, "client", None)
        # Deactivated app: ``is_usable`` returns ``self.active`` on our
        # model. ``getattr`` guard for client mocks that lack the
        # method (test seams, oauthlib internal calls); the default
        # ``True`` mirrors DOT's "if you can't tell, accept".
        is_usable = getattr(client, "is_usable", None)
        if callable(is_usable) and not is_usable(request):
            # Distinct ``reason`` so a Grafana panel can split
            # "deactivated app" (operator-driven, often planned) from
            # "user lost group" (policy churn, often unplanned).
            policy_rejections.labels(
                stage="validate_bearer", reason="app_unusable"
            ).inc()
            return False
        return self._enforce_policy(request, client, stage="validate_bearer")

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """
        Ensure app/user policy is enforced during authorization_code
        exchange (before a token is persisted).

        Also implements the RFC 6749 §10.5 SHOULD clause: if the code
        is rejected by DOT (Grant missing), check the audit side-table
        — a hit indicates the same code was successfully exchanged
        earlier, so any tokens still in flight are revoked here.
        DOT's MUST half (return ``invalid_grant``) survives the
        defence-in-depth wrap.
        """
        if not super().validate_code(
            client_id, code, client, request, *args, **kwargs
        ):
            try:
                self._handle_potential_code_reuse(code, client)
            except Exception:
                # Defence-in-depth must never escalate to 500.
                # The MUST half (``invalid_grant``) is already armed
                # by ``super().validate_code`` returning False; this
                # branch is a SHOULD overlay. A failing audit lookup
                # or revocation gets logged loudly so the operator
                # can investigate, but the protocol response is
                # unchanged.
                logger.exception(
                    "OIDC: code-reuse detection failed; "
                    "invalid_grant still returned"
                )
            return False
        return self._enforce_policy(request, client, stage="validate_code")

    def validate_refresh_token(
        self, refresh_token, client, request, *args, **kwargs
    ):
        """Ensure app/user policy is enforced during refresh_token flow."""
        if not super().validate_refresh_token(
            refresh_token, client, request, *args, **kwargs
        ):
            return False
        return self._enforce_policy(request, client, stage="validate_refresh")

    def save_bearer_token(self, token, request, *args, **kwargs):
        """
        Final guard: block persistence if policy fails.

        This prevents "token issued then denied" races/500s.
        """
        user, client = self._resolve_user_and_client(request)
        if user is not None and client is not None:
            decision = self.policy.decide(user, client)
            # ``match`` narrows ``deny_reason`` for basedpyright; see
            # the ``_enforce_policy`` site for the rationale.
            match decision:
                case AllowedDecision():
                    pass
                case GlobalDeny() | AppDeny():
                    reason = decision.deny_reason.value
                    policy_rejections.labels(
                        stage="save_bearer", reason=reason
                    ).inc()
                    logger.warning(
                        "OIDC DENIED: save_bearer_token reason=%s "
                        "user=%s client=%s client_id=%s",
                        reason,
                        user,
                        client,
                        getattr(client, "client_id", None),
                    )
                    # Convert the policy decision into the protocol-
                    # level error response (no 500). ``from None``
                    # keeps the OAuth response stack-trace-free even
                    # if a future change to ``decide`` starts raising
                    # under us.
                    raise oauth_errors.InvalidGrantError(
                        description="Access denied"
                    ) from None
        elif user is not None and client is None:
            # The policy gate is intentionally skipped on grant types
            # that do not carry a client on the oauthlib request
            # (e.g. password / client_credentials variants that DOT
            # serves through code paths where ``request.client`` is
            # populated elsewhere). Emit an INFO marker so an
            # operator scanning logs after a regression that nulled
            # out ``client`` upstream can spot the silent skip
            # instead of guessing why a deny never fired.
            logger.info(
                "OIDC policy skipped: save_bearer_token user=%s no_client",
                user,
            )
        result = super().save_bearer_token(token, request, *args, **kwargs)
        # Record the code → tokens link only for the original
        # authorization_code exchange — refresh_token grants reuse the
        # same audit row from the first exchange and would otherwise
        # double-insert under a different code. ``request.code`` is set
        # by oauthlib during ``authorization_code`` token requests.
        if getattr(request, "grant_type", None) == "authorization_code":
            code = getattr(request, "code", None)
            if code:
                try:
                    self._record_code_issuance(code, request, token, client)
                except Exception:
                    # Same defence-in-depth posture as
                    # ``validate_code``: a failed audit insert cannot
                    # be allowed to break a legitimate token
                    # issuance. Lose the SHOULD overlay, keep the
                    # tokens; alert via the log instead.
                    logger.exception(
                        "OIDC: code-issuance audit failed for "
                        "client_id=%s — revoke-on-reuse degraded "
                        "for this code",
                        getattr(client, "client_id", None),
                    )
        return result

    def _record_code_issuance(self, code, request, token, client):
        """
        Persist the ``code_hash → (AccessToken, RefreshToken)`` link
        used by :meth:`_handle_potential_code_reuse` for revocation.

        Only the sha256 of the code is stored. ``token`` is the dict
        oauthlib hands to ``save_bearer_token`` (raw bearer strings);
        we re-query the persisted ``AccessToken`` / ``RefreshToken``
        rows by their ``token`` column so we hold the database PKs,
        not the bearer values, in the audit table.
        """
        import hashlib

        from oauth2_provider.models import (
            get_access_token_model,
            get_refresh_token_model,
        )

        from .models import IssuedCodeAudit

        application = client or getattr(request, "client", None)
        if application is None:
            return

        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        AccessToken = get_access_token_model()
        RefreshToken = get_refresh_token_model()

        access_token_value = token.get("access_token")
        refresh_token_value = token.get("refresh_token")
        at_pk = (
            AccessToken.objects.filter(token=access_token_value)
            .values_list("pk", flat=True)
            .first()
            if access_token_value
            else None
        )
        rt_pk = (
            RefreshToken.objects.filter(token=refresh_token_value)
            .values_list("pk", flat=True)
            .first()
            if refresh_token_value
            else None
        )

        # ``update_or_create`` keeps the operation idempotent against
        # a (vanishingly rare) replay of the issuance path that would
        # otherwise trip the ``(code_hash, application)`` unique
        # constraint and crash the issuance.
        IssuedCodeAudit.objects.update_or_create(
            code_hash=code_hash,
            application=application,
            defaults={
                "access_token_pk": at_pk,
                "refresh_token_pk": rt_pk,
            },
        )

    def _handle_potential_code_reuse(self, code, client):
        """
        On a reuse hit, revoke the linked tokens and emit the
        ``oidc_code_reuse_detected`` audit signal.

        Token revocation goes through DOT's own ``RefreshToken.revoke``
        (which cascades to its AccessToken via ``access_token.revoke``
        → ``self.delete()``); calling DOT's API instead of mutating
        the rows directly means future schema changes (e.g. a
        ``revoked_at`` column or a soft-delete flag) take effect
        without code edits here.
        """
        import hashlib

        from django.db import transaction
        from django.utils import timezone
        from oauth2_provider.models import (
            get_access_token_model,
            get_refresh_token_model,
        )

        from .models import IssuedCodeAudit
        from .signals import oidc_code_reuse_detected

        if not code or client is None:
            return

        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        with transaction.atomic():
            audit = (
                IssuedCodeAudit.objects.select_for_update()
                .filter(code_hash=code_hash, application=client)
                .first()
            )
            if audit is None:
                # No audit row — the code is genuinely unknown to
                # this provider, not a replay. Caller will return
                # False (``invalid_grant``) on its own.
                return

            at_pk = audit.access_token_pk
            rt_pk = audit.refresh_token_pk

            # ``RefreshToken.revoke`` deletes the linked AccessToken
            # and stamps ``revoked`` on the refresh row. When no
            # refresh token was issued (e.g. a future client config
            # disabling refresh), fall through to ``AccessToken.revoke``
            # which also calls ``.delete()`` — both result in the
            # token row disappearing, so ``find_token`` at /userinfo
            # returns None → 401.
            AccessToken = get_access_token_model()
            RefreshToken = get_refresh_token_model()
            try:
                refresh_token = (
                    RefreshToken.objects.filter(pk=rt_pk).first()
                    if rt_pk
                    else None
                )
                if refresh_token is not None:
                    refresh_token.revoke()
                elif at_pk:
                    access_token = AccessToken.objects.filter(pk=at_pk).first()
                    if access_token is not None:
                        access_token.revoke()
            except Exception:
                # If revocation itself failed (e.g. the AccessToken
                # was already cleaned up by ``clear_expired_tokens``
                # mid-transaction), still emit the audit signal and
                # bump the counter — the missed revocation is itself
                # a signal worth surfacing.
                logger.exception(
                    "OIDC: token revocation failed during "
                    "code-reuse handling; emitting audit signal "
                    "anyway"
                )

            audit.reuse_count += 1
            audit.last_reuse_at = timezone.now()
            audit.save(update_fields=["reuse_count", "last_reuse_at"])

            reuse_count = audit.reuse_count

        oidc_code_reuse_detected.send(
            sender=type(self),
            application=client,
            code_hash=code_hash,
            access_token_id=at_pk,
            refresh_token_id=rt_pk,
            reuse_count=reuse_count,
        )

    def get_additional_claims(self, request):
        """Augment DOT's id_token/userinfo claims with AA-specific values."""
        # Pin the local to ``dict[str, Any]`` so the AA-specific
        # ``out.update(builder.build())`` is checked against the
        # documented dict contract — DOT's stub of this method
        # returns a plain ``dict``, but our internal usage adds
        # type-checked claim merging on top.
        out: dict[str, Any] = super().get_additional_claims(request)
        user = getattr(request, "user", None)
        if user is None:
            return out
        builder = ClaimsBuilder(
            user=user,
            settings=OIDCSettings.from_django(),
            max_groups=self.MAX_GROUPS_IN_CLAIM,
        )
        out.update(builder.build())
        return out

    @staticmethod
    def _select_requested_id_token_claims(request) -> dict[str, Any]:
        """
        Pull the ``id_token`` member of the OIDC ``claims`` request
        parameter, defensively.

        OIDC Core 1.0 §5.5 — ``claims`` is a JSON-encoded dict the
        client sends in the authorize request. DOT's request parser
        runs ``json.loads`` on it, but a malformed payload may
        survive as a quoted string or a list rather than a dict.
        ``.get`` on a non-dict raises ``AttributeError`` — which
        propagates as a 500 to the OAuth client. Returning ``{}``
        on any non-dict input keeps the override behaving as if the
        client sent no ``claims`` parameter at all.
        """
        claims_param = getattr(request, "claims", None)
        if not isinstance(claims_param, dict):
            return {}
        id_token_member = claims_param.get("id_token")
        if not isinstance(id_token_member, dict):
            return {}
        return id_token_member

    @staticmethod
    def _inject_acr_fallback(
        narrowed: dict[str, Any], request
    ) -> dict[str, Any]:
        """
        Emit ``acr=0`` (RFC 6711 "no specific level") when the client
        asked for ACR but the provider cannot satisfy a concrete
        level. OIDC §5.5.1.1 lists two equivalent ways for the client
        to ask: via the ``acr_values`` request parameter or via the
        ``claims.id_token.acr`` member (with or without
        ``essential=True``). The previous implementation only fired
        the fallback for ``acr_values``; both are spec-equivalent.

        Mutates ``narrowed`` in place and returns it so callers can
        chain.
        """
        if "acr" in narrowed:
            return narrowed
        requested = (
            AllianceAuthOAuth2Validator._select_requested_id_token_claims(
                request
            )
        )
        if getattr(request, "acr_values", None) or "acr" in requested:
            narrowed["acr"] = "0"
        return narrowed

    def get_id_token_dictionary(self, token, token_handler, request):
        """
        Restrict id_token to OIDC §5.4 reserved claims plus claims
        explicitly requested by the client via the ``claims`` request
        parameter under the ``id_token`` member.

        DOT's default mirrors id_token and userinfo through the same
        scope-filtered ``get_oidc_claims``: ``scope=email`` puts
        ``email`` into both. OIDC Core 1.0 §5.4 only obliges the
        provider to surface scope-mapped claims via /userinfo; id_token
        stays minimal unless the client explicitly opts in. The
        conformance suite (``oidcc-scope-email``) flags the leak via
        ``EnsureIdTokenDoesNotContainEmailForScopeEmail`` warnings.
        """
        claims, expiration_time = super().get_id_token_dictionary(
            token, token_handler, request
        )
        requested = self._select_requested_id_token_claims(request)
        narrowed = {
            k: v
            for k, v in claims.items()
            if k in _ID_TOKEN_RESERVED_CLAIMS or k in requested
        }
        self._inject_acr_fallback(narrowed, request)
        return narrowed, expiration_time
