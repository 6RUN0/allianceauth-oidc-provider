"""
Seed deterministic test data for the conformance-suite run.

Idempotent: re-running on an existing DB updates the rows in place
without changing client_id / client_secret. This matters because the
conformance suite is configured against a fixed credential pair.

Client + user credentials are sourced from
``tests.conformance.runner.config`` (single source of truth across
seeding and the host-side runner). The two ``CONFORMANCE_REDIRECT_URI*``
env overrides are seeding-specific and stay local.

Run via Django's ``manage.py shell -c`` from the entrypoint script.
"""

from __future__ import annotations

import os
import sys

import django

django.setup()

from allianceauth.authentication.models import (  # noqa: E402
    EveAllianceInfo,
    EveCharacter,
    EveCorporationInfo,
    State,
)
from allianceauth.tests.auth_utils import AuthUtils  # noqa: E402
from django.contrib.auth.models import Permission  # noqa: E402
from django.utils import timezone  # noqa: E402
from oauth2_provider.models import (  # noqa: E402
    AbstractApplication,
    get_application_model,
)

from allianceauth_oidc.constants import (  # noqa: E402
    PERM_ACCESS_OIDC_CODENAME,
)
from tests.conformance.runner.config import (  # noqa: E402
    CLIENT2_ID,
    CLIENT2_SECRET,
    CLIENT_ID,
    CLIENT_SECRET,
    PASSWORD,
    USERNAME,
)

# Each client gets its own callback path on the suite — the suite
# routes by ``alias`` segment. Seeding-specific (the runner does not
# need them), so they stay here rather than in ``runner.config``.
REDIRECT_URI = os.environ.get(
    "CONFORMANCE_REDIRECT_URI",
    "https://localhost.emobix.co.uk:8443/test/a/conformance/callback",
)
REDIRECT_URI_2 = os.environ.get(
    "CONFORMANCE_REDIRECT_URI_2",
    "https://localhost.emobix.co.uk:8443/test/a/conformance/callback2",
)


def _ensure_alliance_chain() -> EveCharacter:
    """Create an Alliance/Corp/Character so EVE claims emit values."""
    alli, _ = EveAllianceInfo.objects.update_or_create(
        alliance_id=9001,
        defaults={
            "alliance_name": "ConformanceAlliance",
            "alliance_ticker": "CONF",
            "executor_corp_id": 9101,
        },
    )
    corp, _ = EveCorporationInfo.objects.update_or_create(
        corporation_id=9101,
        defaults={
            "corporation_name": "ConformanceCorp",
            "corporation_ticker": "CCRP",
            "ceo_id": 9101,
            "member_count": 1,
            "alliance": alli,
        },
    )
    char, _ = EveCharacter.objects.update_or_create(
        character_id=9201,
        defaults={
            "character_name": "ConformanceMain",
            "corporation_id": corp.corporation_id,
            "corporation_name": corp.corporation_name,
            "corporation_ticker": corp.corporation_ticker,
            "alliance_id": alli.alliance_id,
            "alliance_name": alli.alliance_name,
            "alliance_ticker": alli.alliance_ticker,
        },
    )
    return char


def _ensure_user(main_char: EveCharacter):
    """Create the conformance user and grant ``access_oidc``."""
    from django.contrib.auth import get_user_model

    User = get_user_model()
    try:
        user = AuthUtils.create_user(USERNAME)
    except Exception as exc:  # noqa: BLE001
        # Create-or-fetch: ``AuthUtils.create_user`` (Alliance Auth)
        # raises a variety of exceptions on duplicate
        # (``IntegrityError`` typically, but the precise type is not
        # part of the AA public contract and has shifted across
        # versions). We accept any failure and fall through to the
        # ``get`` — if the user genuinely cannot be resolved, the
        # ``get`` itself raises ``DoesNotExist`` and the fixture
        # setup aborts loudly. The warning makes the silent-fallback
        # path visible so a regression at AA-create time is not
        # mistaken for an idempotency hit.
        sys.stderr.write(
            f"AuthUtils.create_user({USERNAME!r}) raised "
            f"{type(exc).__name__}: {exc}; falling back to "
            f"User.objects.get()\n"
        )
        user = User.objects.get(username=USERNAME)
    user.set_password(PASSWORD)
    user.email = "conformance@example.test"
    # Conformance suite drives login through Django admin's view (AA's
    # stock /account/login/ is EVE-SSO-only with no fillable form).
    # Admin-login requires ``is_staff=True`` to accept the credentials,
    # so flag the user accordingly. Production AA would never want
    # this — the conformance container runs in isolation, never seen
    # by real users.
    user.is_staff = True
    if user.last_login is None:
        user.last_login = timezone.now()
    user.save()

    user.profile.main_character = main_char
    user.profile.save()

    perm = Permission.objects.get_by_natural_key(
        PERM_ACCESS_OIDC_CODENAME,
        "allianceauth_oidc",
        "allianceauthapplication",
    )
    user.user_permissions.add(perm)

    # Drop the user into the Member state so any state-restricted apps
    # we add later inherit a sensible default.
    State.objects.get(name="Member").member_characters.add(main_char)
    return user


def _ensure_app(
    owner,
    *,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    name: str,
) -> None:
    """Create or update an OIDC application with the given credentials."""
    Application = get_application_model()
    # ``skip_authorization`` removes the consent screen so the
    # suite's Selenium driver only has to fill the login form.
    # ``pkce_required=False`` because the OIDC basic-certification
    # plan runs MOST modules without PKCE (the suite sends authorize
    # requests without ``code_challenge`` for non-PKCE plans). The
    # model default is ``True`` per RFC 9700 — appropriate for real
    # apps but blocks every basic-cert module that does not opt into
    # PKCE. The suite has its own dedicated ``oidcc-pkce-*`` plans
    # for verifying PKCE behaviour.
    Application.objects.update_or_create(
        client_id=client_id,
        defaults={
            "client_secret": client_secret,
            "user": owner,
            "name": name,
            "client_type": AbstractApplication.CLIENT_CONFIDENTIAL,
            "authorization_grant_type": (
                AbstractApplication.GRANT_AUTHORIZATION_CODE
            ),
            "redirect_uris": redirect_uri,
            "algorithm": "RS256",
            "skip_authorization": True,
            "active": True,
            "pkce_required": False,
        },
    )


def main() -> None:
    main_char = _ensure_alliance_chain()
    user = _ensure_user(main_char)
    _ensure_app(
        user,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        name="Conformance Test Client",
    )
    _ensure_app(
        user,
        client_id=CLIENT2_ID,
        client_secret=CLIENT2_SECRET,
        redirect_uri=REDIRECT_URI_2,
        name="Conformance Test Client (secondary)",
    )
    sys.stdout.write(
        f"OK seeded client_ids=[{CLIENT_ID}, {CLIENT2_ID}] "
        f"username={USERNAME}\n"
    )


if __name__ == "__main__":
    main()
