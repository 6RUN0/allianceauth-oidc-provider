"""Custom DOT OAuth2Validator that enforces Alliance Auth access policy."""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from typing import Any, Final, Protocol, runtime_checkable

from django.core.exceptions import PermissionDenied
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749 import errors as oauth_errors

from .app_settings import OIDCSettings
from .security import DEFAULT_POLICY, AppLike, OAuthRequestLike, UserLike


@runtime_checkable
class ClaimsUser(Protocol):
    """
    Smallest shape ``ClaimsBuilder`` reads to assemble OIDC claims.

    Distinct from ``security.UserLike`` (security gate): claims need
    ``profile`` / ``groups`` / ``email`` / ``id``; the security gate
    needs ``is_authenticated`` / ``is_superuser`` / ``has_perm`` —
    Django's ``AnonymousUser`` carries the latter set but not the
    former. Splitting the two protocols keeps each contract minimal
    and documents which call sites depend on which attrs.

    Fields are typed ``Any`` for the same reason ``AppLike`` does:
    django-stubs renders FK descriptors as opaque types incompatible
    with Protocol invariance against ``str`` / ``int``. The runtime
    contract — ``ClaimsBuilder`` only ``getattr``-reads each field —
    is unaffected.
    """

    email: Any
    profile: Any
    groups: Any
    id: Any


logger = logging.getLogger(f"extensions.{__name__}")


# EVE-domain claim names emitted under the configured prefix/scope.
# Order matches the natural grouping (character → corp → alliance →
# faction) and is used both at scope-binding time below and inside
# ``ClaimsBuilder._eve_claims`` to assemble the payload. Each name
# is read directly off ``EveCharacter`` as ``getattr(main, name)``
# — denormalised on the main_character row so a single attribute
# chain replaces three FK joins.
_EVE_CLAIM_NAMES: Final[tuple[str, ...]] = (
    "character_id",
    "corporation_id",
    "corporation_name",
    "corporation_ticker",
    "alliance_id",
    "alliance_name",
    "alliance_ticker",
    "faction_id",
    "faction_name",
)


# Claim name emitted under the EVE prefix as an explicit "this is
# the main character" alias of ``character_id``. Carries the same
# value as ``<prefix>character_id``; exists separately because RPs
# in the EVE ecosystem commonly key off this naming when correlating
# OIDC identity with EVE-aware data (killboards, fit-sharing).
_EVE_MAIN_CHARACTER_ID_CLAIM: Final[str] = "main_character_id"


# Composite affiliation snapshot. A single dict claim that lets RPs
# read corp + alliance + faction + AA state in one shot instead of
# composing four flat claims. ``corp`` and ``state`` are always
# present (when a main exists); ``alliance`` and ``faction`` are
# omitted when not applicable, mirroring the omit-not-null
# convention of the flat claims.
_EVE_AFFILIATION_CLAIM: Final[str] = "affiliation"


# Default cap on the ``groups`` claim payload — see
# ``AllianceAuthOAuth2Validator.MAX_GROUPS_IN_CLAIM`` for rationale.
# Module-level so ``ClaimsBuilder`` can default to it without importing
# the validator class.
_DEFAULT_MAX_GROUPS_IN_CLAIM: Final[int] = 256


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

# AA-specific "groups" claim — emitted by ``ClaimsBuilder._groups``
# AND bound under the ``profile`` scope inside
# ``_build_oidc_claim_scope``. Pinned in one place so a future rename
# (e.g. ``"groups"`` → ``"roles"``) lands in a single edit; previously
# the two ends were stringly-coupled and could silently desync.
_GROUPS_CLAIM_NAME: Final[str] = "groups"
_GROUPS_CLAIM_SCOPE: Final[str] = "profile"


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


# Soft dependency on the ``aa_skip_email`` companion plugin: when it
# is installed it stamps users without a real email with a
# deterministic synthetic address (``username_42@noreply.example``).
# Such placeholders are never verified — they exist precisely
# because the user skipped the verification step — so OIDC
# ``email_verified`` MUST be ``False`` for them regardless of the
# ``REGISTRATION_VERIFY_EMAIL`` setting. The plugin's own helpers
# documentation calls out this consumer explicitly.
#
# Imported at module load and bound to a module-level name so tests
# can ``patch.object(auth_provider, "_aa_skip_email_is_placeholder", …)``
# to exercise both branches without installing the optional package.
try:  # pragma: no cover - import resolved at module load
    # ``aa_skip_email`` is an optional sibling plugin without bundled
    # type stubs; both checkers must tolerate the absent package on
    # installations that did not pull it in.
    from aa_skip_email.helpers import (  # pyright: ignore[reportMissingImports]
        is_placeholder_email as _aa_skip_email_is_placeholder,
    )
except (
    ImportError
):  # pragma: no cover - exercised in environments without the plugin
    _aa_skip_email_is_placeholder = None


def _email_is_placeholder(email: str) -> bool:
    """
    Return True if ``email`` is a synthetic ``aa_skip_email`` placeholder.

    Falls back to ``False`` when the optional plugin is not installed —
    a missing detector is interpreted as "no information", which keeps
    the ``REGISTRATION_VERIFY_EMAIL`` default authoritative for sites
    that never had placeholders to begin with.
    """
    if _aa_skip_email_is_placeholder is None:
        return False
    # ``bool(...)`` cast: ``aa_skip_email`` is a soft dependency
    # without type stubs, so mypy resolves the return value as Any.
    # Coerce to a hard ``bool`` so downstream callers get a stable
    # type rather than the upstream library's Any contagion.
    return bool(_aa_skip_email_is_placeholder(email))


@functools.lru_cache(maxsize=1)
def _build_oidc_claim_scope(settings: OIDCSettings) -> dict[str, str]:
    """
    Build the claim → scope filter map for a given settings snapshot.

    Module-level + ``lru_cache`` keyed on the (frozen, hashable)
    ``OIDCSettings`` instance so two validators built under the same
    settings share one dict. ``OIDCSettings.from_django()`` is itself
    cached with ``setting_changed`` invalidation (see
    ``app_settings._cached_snapshot``), so a settings flip swaps the
    key here and the cache misses cleanly.

    The returned dict is intended read-only by callers (DOT iterates
    it via ``.items()`` only). Mutation by a downstream consumer
    would corrupt other validators sharing the same cache entry.
    """
    scopes: dict[str, str] = OAuth2Validator.oidc_claim_scope.copy()
    scopes[_GROUPS_CLAIM_NAME] = _GROUPS_CLAIM_SCOPE
    scopes.update(
        {
            f"{settings.eve_claim_prefix}{n}": settings.eve_claim_scope
            for n in _EVE_CLAIM_NAMES
        }
    )
    # The ``main_character_id`` alias and the ``affiliation`` composite
    # ride the same scope as the flat EVE claims so RPs already
    # requesting ``profile`` receive them without negotiating a new
    # scope. Bound under the configured prefix for consistency.
    scopes[f"{settings.eve_claim_prefix}{_EVE_MAIN_CHARACTER_ID_CLAIM}"] = (
        settings.eve_claim_scope
    )
    scopes[f"{settings.eve_claim_prefix}{_EVE_AFFILIATION_CLAIM}"] = (
        settings.eve_claim_scope
    )
    return scopes


@dataclass
class ClaimsBuilder:
    """
    Build the AA-specific OIDC claim payload for a single user.

    Each ``_xxx`` method returns the claim's value (or ``None`` to omit
    it); ``build()`` composes them into the final dict. Splitting this
    way lets each branch be unit-tested on synthetic users
    (``types.SimpleNamespace``) without spinning up Alliance Auth's
    ORM stack — most edge cases (missing main, no email, broken
    portrait template, oversized groups list) reduce to a 5-line
    test.

    ``settings`` is an injected ``OIDCSettings`` snapshot rather than a
    free read of ``django.conf.settings``: tests construct a builder
    with hand-crafted settings and skip ``@override_settings``.
    """

    user: ClaimsUser
    settings: OIDCSettings
    max_groups: int = _DEFAULT_MAX_GROUPS_IN_CLAIM
    log: logging.Logger = field(default=logger)

    def build(self) -> dict[str, Any]:
        """Assemble the AA-specific claim dict (caller merges into base)."""
        out: dict[str, Any] = {}
        if (email := self._email()) is not None:
            out["email"] = email
            # OIDC Core 1.0 §5.1: ``email_verified`` is RECOMMENDED
            # alongside ``email`` and MUST honestly reflect whether
            # the address was actually verified.
            #
            # Decision tree, top to bottom:
            #
            # 1. If the operator set
            #    ``ALLIANCEAUTH_OIDC_FORCE_EMAIL_VERIFIED`` to a
            #    non-None value, that wins — escape hatch for
            #    deployments where the trust signal originates outside
            #    AA (e.g. users imported from an already-verifying
            #    external IdP, or a site that knowingly accepts the
            #    trade-off).
            # 2. Else if ``aa_skip_email`` stamped a synthetic
            #    placeholder (``username_42@noreply.example``), the
            #    user never verified anything — emit ``False``.
            # 3. Otherwise mirror AA's ``REGISTRATION_VERIFY_EMAIL``
            #    via ``OIDCSettings.email_verified_default``: when AA
            #    required confirmation at registration the address is
            #    trusted; when the operator disabled the step we
            #    cannot honestly claim verification.
            #
            # The default path keeps the trust level consistent with
            # AA-side reality; the override is opt-in and audit-worthy.
            if self.settings.force_email_verified is not None:
                out["email_verified"] = self.settings.force_email_verified
            elif _email_is_placeholder(email):
                out["email_verified"] = False
            else:
                out["email_verified"] = self.settings.email_verified_default
        if (picture := self._picture()) is not None:
            out["picture"] = picture
        if (name := self._name()) is not None:
            out["name"] = name
        if (groups := self._groups()) is not None:
            out[_GROUPS_CLAIM_NAME] = groups
        if (locale := self._locale()) is not None:
            out["locale"] = locale
        out.update(self._eve_claims())
        return out

    def _email(self) -> str | None:
        # Django sets a blank string when no email is registered;
        # only emit when there's a real value. Strip whitespace so
        # accidental "  " entries don't leak into the claim and break
        # downstream RFC 5321 contracts.
        email = getattr(self.user, "email", None)
        if isinstance(email, str):
            email = email.strip() or None
        return email or None

    def _main_character(self) -> object | None:
        profile = getattr(self.user, "profile", None)
        return getattr(profile, "main_character", None)

    def _picture(self) -> str | None:
        # A misconfigured template (missing/extra placeholders, stray
        # ``{``) would otherwise raise inside id-token signing and 500
        # the token endpoint; degrade gracefully and skip the claim.
        character_id = getattr(self._main_character(), "character_id", None)
        if not character_id:
            return None
        try:
            return self.settings.portrait_url_template.format(
                character_id=character_id,
                size=self.settings.portrait_size,
            )
        except (KeyError, IndexError, ValueError, TypeError) as exc:
            # TypeError covers the "template ended up not a str" case —
            # ``OIDCSettings`` already coerces with ``str(...)`` but a
            # future config layer could feed a non-stringable object
            # that raises on ``.format`` lookup. Belt-and-braces; cheap.
            self.log.warning(
                "OIDC: invalid ALLIANCEAUTH_OIDC_PORTRAIT_URL_TEMPLATE (%s); skipping `picture` claim",  # noqa: E501
                exc,
            )
            return None

    def _name(self) -> str | None:
        name = getattr(self._main_character(), "character_name", None)
        return name or None

    def _groups(self) -> list[str] | None:
        # Sort Django groups so the claim is deterministic across
        # calls (downstream consumers hash claim payloads for caching).
        # The state name is appended after sorting so its position in
        # the list is stable.
        groups = getattr(self.user, "groups", None)
        profile = getattr(self.user, "profile", None)
        state_name = getattr(getattr(profile, "state", None), "name", None)
        if groups is None:
            groups_list: list[str] = []
        else:
            groups_list = sorted(groups.all().values_list("name", flat=True))
        if len(groups_list) > self.max_groups:
            self.log.warning(
                "OIDC: groups claim truncated for user_id=%s (%d groups, cap=%d)",  # noqa: E501
                getattr(self.user, "id", None),
                len(groups_list),
                self.max_groups,
            )
            groups_list = groups_list[: self.max_groups]
        if state_name is not None:
            groups_list.append(state_name)
        return groups_list or None

    def _locale(self) -> str | None:
        # ``UserProfile.language`` is a CharField with default="" when
        # the user hasn't picked a language. The bare ``is not None``
        # check would leak the empty string as a claim.
        profile = getattr(self.user, "profile", None)
        locale = getattr(profile, "language", None)
        return locale or None

    def _eve_claims(self) -> dict[str, Any]:
        # All denormalised on EveCharacter, so a single getattr chain
        # replaces what would otherwise be three FK joins. Each field
        # is emitted only when it carries real data — NPC corps have
        # no alliance, alts are not always complete, etc. Empty fields
        # are OMITTED rather than emitted as ``null`` so consumers
        # that key off ``claim in payload`` behave consistently with
        # the OIDC convention.
        main = self._main_character()
        prefix = self.settings.eve_claim_prefix
        out: dict[str, Any] = {}
        for name in _EVE_CLAIM_NAMES:
            value = getattr(main, name, None)
            if value:
                out[f"{prefix}{name}"] = value
        main_character_id = getattr(main, "character_id", None)
        if main_character_id:
            out[f"{prefix}{_EVE_MAIN_CHARACTER_ID_CLAIM}"] = main_character_id
        affiliation = self._affiliation(main)
        if affiliation:
            out[f"{prefix}{_EVE_AFFILIATION_CLAIM}"] = affiliation
        return out

    def _affiliation(self, main: object | None) -> dict[str, Any] | None:
        """
        Compose the ``affiliation`` claim from the main character +
        AA state.

        Returns ``None`` when no main character exists — mirrors the
        flat-claims omit contract, so an RP that keys off
        ``"affiliation" in payload`` sees a consistent absent /
        present signal. The returned dict ALWAYS carries the
        ``state`` (a user is in some state, even if it's
        ``"Guest"`` / blank), drops ``alliance`` / ``faction`` when
        the main character lacks those fields.
        """
        if main is None:
            return None
        out: dict[str, Any] = {}
        corp_id = getattr(main, "corporation_id", None)
        if corp_id:
            out["corp"] = corp_id
        alliance_id = getattr(main, "alliance_id", None)
        if alliance_id:
            out["alliance"] = alliance_id
        faction_id = getattr(main, "faction_id", None)
        if faction_id:
            out["faction"] = faction_id
        profile = getattr(self.user, "profile", None)
        state_name = getattr(getattr(profile, "state", None), "name", None)
        if state_name:
            out["state"] = state_name
        return out or None


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
        return _build_oidc_claim_scope(OIDCSettings.from_django())

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
        self, request: OAuthRequestLike, client: AppLike | None
    ) -> bool:
        """
        Run the per-app state/groups gate against ``request.user``.

        Returns True if the policy allows the operation, False otherwise. Used
        as a post-validation hook by validate_code and validate_refresh_token
        so the same gate runs on every token-issuing path; missing it on either
        side leaves a hole.
        """
        user, resolved_client = self._resolve_user_and_client(request, client)
        if user is None or resolved_client is None:
            return True
        allowed = self.policy.is_allowed(user, resolved_client)
        if not allowed:
            # Validator path doesn't render a denied page (the OAuth
            # response is the bool → invalid_grant translation), so log
            # here for operator visibility — the policy gate itself is
            # decision-only after the M1 consolidation.
            logger.warning(
                "OIDC DENIED: validator user=%s client=%s client_id=%s",
                user,
                resolved_client,
                getattr(resolved_client, "client_id", None),
            )
        return allowed

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
        return self._enforce_policy(request, client)

    def validate_refresh_token(
        self, refresh_token, client, request, *args, **kwargs
    ):
        """Ensure app/user policy is enforced during refresh_token flow."""
        if not super().validate_refresh_token(
            refresh_token, client, request, *args, **kwargs
        ):
            return False
        return self._enforce_policy(request, client)

    def save_bearer_token(self, token, request, *args, **kwargs):
        """
        Final guard: block persistence if policy fails.

        This prevents "token issued then denied" races/500s.
        """
        user, client = self._resolve_user_and_client(request)
        if user is not None and client is not None:
            try:
                self.policy.enforce(user, client)
            except PermissionDenied:
                logger.warning(
                    "OIDC DENIED: save_bearer_token user=%s client=%s client_id=%s",  # noqa: E501
                    user,
                    client,
                    getattr(client, "client_id", None),
                )
                # Convert to OAuth error response (no 500). ``from None``
                # suppresses the PermissionDenied chain so the OAuth
                # client only sees the protocol-level error, not Django
                # internals.
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
