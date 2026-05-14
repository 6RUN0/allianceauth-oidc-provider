"""
OIDC claim-mapping helpers and ``ClaimsBuilder``.

Split off from ``auth_provider`` so the "what claims to emit" layer
(pure dict construction on a user shape) lives separately from the
"how DOT calls us" integration layer (the validator). The validator
imports ``ClaimsBuilder`` and ``build_oidc_claim_scope`` from here;
nothing in this module imports the validator, keeping the dependency
unidirectional. Unit tests for claim-mapping can construct a builder
with synthetic users and skip the Alliance Auth ORM stack entirely.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

from oauth2_provider.oauth2_validators import OAuth2Validator

if TYPE_CHECKING:
    from .app_settings import OIDCSettings


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


# AA-specific "groups" claim — emitted by ``ClaimsBuilder._groups``
# AND bound under the ``profile`` scope inside
# ``build_oidc_claim_scope``. Pinned in one place so a future rename
# (e.g. ``"groups"`` → ``"roles"``) lands in a single edit; previously
# the two ends were stringly-coupled and could silently desync.
_GROUPS_CLAIM_NAME: Final[str] = "groups"
_GROUPS_CLAIM_SCOPE: Final[str] = "profile"


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
# can ``patch.object(claims, "_aa_skip_email_is_placeholder", …)``
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
def build_oidc_claim_scope(settings: OIDCSettings) -> dict[str, str]:
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
