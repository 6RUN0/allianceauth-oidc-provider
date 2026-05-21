"""``oidc_show_effective_policy`` — explain a (user, app) decision."""

from __future__ import annotations

from typing import Any, cast

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import gettext as _
from oauth2_provider.models import get_application_model
from typing_extensions import override

from allianceauth_oidc.security import (
    DEFAULT_POLICY,
    AllowedDecision,
    AppDeny,
    GlobalDeny,
)

from ._format import FORMAT_CHOICES, render_rows


class Command(BaseCommand):
    """
    Explain ``AccessPolicy.decide(user, app)`` plain-text.

    The three-layer access policy (global ``access_oidc`` permission +
    per-app state/group whitelist + per-app ``active`` flag) is the
    single most common cause of "why does X not get into Y?" operator
    questions. Today the answer is "read ``security.py``"; this
    command exposes the decision machinery as a CLI surface.

    Output reports the full structured outcome — the discriminated
    union from ``AccessPolicy.decide`` — and, on a deny, the
    diagnostic deltas an operator needs:

    * The application's whitelisted states / groups.
    * The user's state / groups.
    * The exact set of missing states / groups (set-difference) so
      the operator sees "user needs to be in groups {X, Y} OR have
      state Z" without computing the intersection by hand.
    """

    help = _(
        "Show the AccessPolicy decision for a user against an OIDC "
        "application. Operator debugging tool."
    )

    @override
    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "client_id",
            help=_("client_id of the OIDC application to evaluate"),
        )
        parser.add_argument(
            "--username",
            required=True,
            help=_("username (exact match) to evaluate"),
        )
        parser.add_argument(
            "--format",
            default="table",
            choices=FORMAT_CHOICES,
        )

    @override
    def handle(self, *args: Any, **options: Any) -> None:
        client_id = options["client_id"]
        username = options["username"]

        Application = get_application_model()
        try:
            # No ``active=True`` filter — the command is a diagnostic
            # surface, and "is the app deactivated?" is part of the
            # answer the operator is asking. Surface the row even when
            # ``app.active is False``; the row's column shows that
            # status, and decide() would have already short-circuited
            # at the AccessDecision layer in the live request path.
            app = Application.objects.prefetch_related("states", "groups").get(
                client_id=client_id
            )
        except Application.DoesNotExist as exc:
            raise CommandError(f"client_id={client_id!r} not found") from exc

        User = get_user_model()
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist as exc:
            raise CommandError(f"username={username!r} not found") from exc

        # Django's ``User`` satisfies the ``UserLike`` Protocol at
        # runtime via duck typing (``is_authenticated`` / ``is_superuser``
        # / ``has_perm`` all present) but django-stubs renders
        # ``is_authenticated`` as a read-only property whereas the
        # Protocol declares it as a settable ``bool``. Protocol member
        # invariance fails both mypy and basedpyright. ``cast(Any, ...)``
        # is the minimal-syntax cross-checker bypass — mypy-only
        # ``# type: ignore`` is silently dropped by basedpyright,
        # ``cast("UserLike", ...)`` is rejected by basedpyright as
        # ``reportInvalidCast``.
        decision = DEFAULT_POLICY.decide(cast("Any", user), app)
        row = self._build_row(user, app, decision)
        self.stdout.write(
            render_rows(
                [row],
                columns=(
                    "username",
                    "client_id",
                    "app_name",
                    "app_active",
                    "decision",
                    "deny_reason",
                    "user_state",
                    "user_groups",
                    "app_states",
                    "app_groups",
                    "missing_states",
                    "missing_groups",
                ),
                fmt=options["format"],
            )
        )

    @staticmethod
    def _build_row(
        user: Any,
        app: Any,
        decision: AllowedDecision | GlobalDeny | AppDeny,
    ) -> dict[str, Any]:
        """
        Compose the report row for a single (user, app) pair.

        The user / app context (state lists, group lists) is always
        included regardless of the decision outcome: the row's whole
        purpose is "show me what the policy saw". A pure
        ``allowed=true`` row without the context would still leave
        the operator wondering whether the allow was via state, via
        group, or because no whitelist is configured at all.
        """
        # if/elif/else rather than ``match``: the discriminated
        # :data:`AccessDecision` union is exhaustively narrowed by
        # two isinstance checks (the trailing ``else`` is the only
        # remaining variant — ``AppDeny`` — by construction); mypy /
        # basedpyright read the chain as definitely-assigning both
        # locals, whereas ``match`` without ``case _:`` flagged
        # ``possibly-undefined`` and adding ``case _:`` flagged
        # ``reportUnreachable``. A future fourth variant of
        # ``AccessDecision`` would land in this ``else`` and be
        # caught by the existing dedicated test for ``AppDeny``
        # diagnostics misrendering.
        decision_str: str
        deny_reason: str | None
        if isinstance(decision, AllowedDecision):
            decision_str = "allowed"
            deny_reason = None
        elif isinstance(decision, GlobalDeny):
            decision_str = "denied"
            deny_reason = "global"
        else:
            # AppDeny — the only remaining variant.
            decision_str = "denied"
            deny_reason = "app"
            # ``decision`` is unused below in this branch; the
            # ``AppDeny.app`` payload is rebuilt from ``app`` /
            # ``user`` to keep ``missing_states`` / ``missing_groups``
            # computation uniform across all three branches.
            _ = decision

        user_state = getattr(getattr(user, "profile", None), "state", None)
        user_state_name = (
            getattr(user_state, "name", None) if user_state else None
        )
        user_group_names = sorted(g.name for g in user.groups.all())
        app_state_names = sorted(s.name for s in app.states.all())
        app_group_names = sorted(g.name for g in app.groups.all())

        # ``missing_states`` is the set of states the app whitelists
        # that the user does NOT currently hold (empty set means the
        # user's state IS whitelisted or the app has no state filter).
        # Same shape for ``missing_groups``. Joined as a comma-string
        # for table / csv output; JSON rendering keeps it as the list.
        missing_states_list = sorted(
            s for s in app_state_names if s != user_state_name
        )
        missing_groups_list = sorted(
            set(app_group_names) - set(user_group_names)
        )

        return {
            "username": user.get_username(),
            "client_id": getattr(app, "client_id", None),
            "app_name": getattr(app, "name", None),
            "app_active": getattr(app, "active", None),
            "decision": decision_str,
            "deny_reason": deny_reason or "",
            "user_state": user_state_name or "",
            "user_groups": ",".join(user_group_names) or "",
            "app_states": ",".join(app_state_names) or "",
            "app_groups": ",".join(app_group_names) or "",
            "missing_states": ",".join(missing_states_list) or "",
            "missing_groups": ",".join(missing_groups_list) or "",
        }
