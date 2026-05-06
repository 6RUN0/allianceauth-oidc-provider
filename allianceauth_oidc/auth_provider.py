"""Custom DOT OAuth2Validator that enforces Alliance Auth access policy."""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from typing import Any, Final

from django.core.exceptions import PermissionDenied
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749 import errors as oauth_errors

from .app_settings import OIDCSettings
from .security import DEFAULT_POLICY, AppLike, UserLike

logger = logging.getLogger(f"extensions.{__name__}")


# EVE-domain claim names emitted under the configured prefix/scope.
# Order matches the natural grouping (character → corp → alliance) and
# is used both at scope-binding time below and inside
# `ClaimsBuilder._eve_claims` to assemble the payload.
_EVE_CLAIM_NAMES: Final[tuple[str, ...]] = (
    "character_id",
    "corporation_id",
    "corporation_name",
    "corporation_ticker",
    "alliance_id",
    "alliance_name",
    "alliance_ticker",
)


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

    user: object
    settings: OIDCSettings
    max_groups: int = _DEFAULT_MAX_GROUPS_IN_CLAIM
    log: logging.Logger = field(default=logger)

    def build(self) -> dict[str, Any]:
        """Assemble the AA-specific claim dict (caller merges into base)."""
        out: dict[str, Any] = {}
        if (email := self._email()) is not None:
            out["email"] = email
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
        return email if email else None

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
        return name if name else None

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
        return groups_list if groups_list else None

    def _locale(self) -> str | None:
        # ``UserProfile.language`` is a CharField with default="" when
        # the user hasn't picked a language. The bare ``is not None``
        # check would leak the empty string as a claim.
        profile = getattr(self.user, "profile", None)
        locale = getattr(profile, "language", None)
        return locale if locale else None

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
        return out


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
        request, client_arg: AppLike | None = None
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

    def _enforce_policy(self, request, client) -> bool:
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

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """
        Ensure app/user policy is enforced during authorization_code
        exchange (before a token is persisted).
        """
        if not super().validate_code(
            client_id, code, client, request, *args, **kwargs
        ):
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
        return super().save_bearer_token(token, request, *args, **kwargs)

    def get_additional_claims(self, request):
        """Augment DOT's id_token/userinfo claims with AA-specific values."""
        out = super().get_additional_claims(request)
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
