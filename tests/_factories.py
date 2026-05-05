"""
Factories for Alliance Auth + OIDC test data.

Replaces hand-rolled `setUpTestData` blocks with composable helpers:

    alli1 = make_alliance("TEST")
    corp_a = make_corp("ABC", alliance=alli1)
    char1 = make_character("alice", corp_a)
    user = make_user("alice", main=char1, alts=[char2], state="Member")
    app, client_id, secret = make_app(owner=user)

ID-counters start above the range commonly used in hand-written test data
(>=1000) so a test that wants a specific ID can pick a low number without
clashing.
"""

from __future__ import annotations

import itertools

from allianceauth.authentication.models import (
    CharacterOwnership,
    EveAllianceInfo,
    EveCharacter,
    EveCorporationInfo,
    State,
)
from allianceauth.tests.auth_utils import AuthUtils
from django.contrib.auth.models import Group, User
from oauth2_provider.generators import (
    generate_client_id,
    generate_client_secret,
)
from oauth2_provider.models import AbstractApplication, get_application_model

# Each model gets its own counter so logs and assertions stay readable
# (alliance 1xxx, corp 2xxx, char 3xxx, owner_hash 4xxx).
_alliance_id = itertools.count(1000)
_corp_id = itertools.count(2000)
_char_id = itertools.count(3000)
_owner_hash = itertools.count(4000)


def make_alliance(
    ticker: str = "TST",
    *,
    alliance_id: int | None = None,
    name: str | None = None,
    executor_corp_id: int = 0,
) -> EveAllianceInfo:
    """
    Create an Alliance row.

    ``ticker`` doubles as the default name.
    """
    aid = alliance_id if alliance_id is not None else next(_alliance_id)
    return EveAllianceInfo.objects.create(
        alliance_id=aid,
        alliance_name=name or f"alliance.{ticker}.{aid}",
        alliance_ticker=ticker,
        executor_corp_id=executor_corp_id,
    )


def make_corp(
    ticker: str,
    *,
    alliance: EveAllianceInfo | None = None,
    corp_id: int | None = None,
    name: str | None = None,
    member_count: int = 1,
) -> EveCorporationInfo:
    """
    Create a Corporation row, optionally inside an Alliance.

    ``alliance=None`` represents the realistic NPC/corpless case (some EVE
    corps live outside any alliance).
    """
    cid = corp_id if corp_id is not None else next(_corp_id)
    return EveCorporationInfo.objects.create(
        corporation_id=cid,
        corporation_name=name or f"corporation.{ticker}.{cid}",
        corporation_ticker=ticker,
        ceo_id=cid,
        member_count=member_count,
        alliance=alliance,
    )


def make_character(
    name: str,
    corp: EveCorporationInfo,
    *,
    char_id: int | None = None,
) -> EveCharacter:
    """Create a Character with corp/alliance fields denormalized from corp."""
    cid = char_id if char_id is not None else next(_char_id)
    return EveCharacter.objects.create(
        character_id=cid,
        character_name=name,
        corporation_id=corp.corporation_id,
        corporation_name=corp.corporation_name,
        corporation_ticker=corp.corporation_ticker,
        alliance_id=getattr(corp.alliance, "alliance_id", None),
        alliance_name=getattr(corp.alliance, "alliance_name", None),
        alliance_ticker=getattr(corp.alliance, "alliance_ticker", None),
    )


def make_user(
    username: str,
    *,
    main: EveCharacter | None = None,
    alts: list[EveCharacter] | None = None,
    state: str | None = None,
    groups: list[str] | None = None,
    email: str = "",
    is_superuser: bool = False,
) -> User:
    """
    Create a User with optional main character, alts, state, and groups.

    ``state`` adds the *main character* to ``State.member_characters`` for
    that state name (Member/Blue/Guest), which is how Alliance Auth's
    state-determination treats individual-character membership. Requires a
    ``main`` to be set.

    ``groups`` is a list of names; missing groups are created on demand.
    """
    user = AuthUtils.create_user(username)

    if email:
        user.email = email
    if is_superuser:
        user.is_superuser = True
    if email or is_superuser:
        user.save()

    if main is not None:
        user.profile.main_character = main
        user.profile.save()

    chars_to_own = [main] if main is not None else []
    chars_to_own.extend(alts or [])
    if chars_to_own:
        CharacterOwnership.objects.bulk_create(
            [
                CharacterOwnership(
                    user=user,
                    character=ch,
                    owner_hash=f"hash-{next(_owner_hash)}",
                )
                for ch in chars_to_own
            ]
        )

    if state is not None:
        if main is None:
            raise ValueError(
                f"make_user(state={state!r}): state membership is applied via "
                "the main character; pass main=... too."
            )
        State.objects.get(name=state).member_characters.add(main)

    for grp_name in groups or []:
        grp, _ = Group.objects.get_or_create(name=grp_name)
        user.groups.add(grp)

    user.refresh_from_db()
    return user


def make_app(
    *,
    owner: User,
    states: list[str] | None = None,
    groups: list[str] | None = None,
    active: bool = True,
    debug_mode: bool = False,
    redirect_uri: str = "http://localhost/redir/",
    skip_authorization: bool = False,
    algorithm: str = "RS256",
    client_type: str = "confidential",
    grant_type: str = "authorization-code",
) -> tuple[AbstractApplication, str, str]:
    """
    Create an AllianceAuthApplication owned by ``owner``.

    Returns ``(app, client_id, raw_client_secret)`` so tests can use the raw
    secret in token requests (the model hashes it on save).
    """
    client_id = generate_client_id()
    raw_secret = generate_client_secret()
    app = get_application_model().objects.create(
        user=owner,
        client_id=client_id,
        redirect_uris=redirect_uri,
        client_type=client_type,
        authorization_grant_type=grant_type,
        client_secret=raw_secret,
        name=f"TEST APP - {client_id}",
        skip_authorization=skip_authorization,
        algorithm=algorithm,
        active=active,
        debug_mode=debug_mode,
    )
    for state_name in states or []:
        app.states.add(State.objects.get(name=state_name))
    for grp_name in groups or []:
        grp, _ = Group.objects.get_or_create(name=grp_name)
        app.groups.add(grp)
    return app, client_id, raw_secret
