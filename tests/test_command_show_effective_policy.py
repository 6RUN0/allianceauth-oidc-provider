"""
Tests for ``manage.py oidc_show_effective_policy``.

The command exposes ``AccessPolicy.decide(user, app)`` as a CLI
surface for operator debugging. Three coverage branches mirror the
discriminated union returned by ``decide``:

1. ``AllowedDecision`` — user passes both global and app gates.
2. ``GlobalDeny`` — user lacks the global ``access_oidc`` permission.
3. ``AppDeny`` — user is not in the app's state/group whitelist.

Plus two operator-facing edge cases:

* Unknown ``client_id`` raises ``CommandError`` (not a stack
  trace) — operators paste freeform IDs from logs.
* Deactivated app surfaces its status in the output row even
  when the policy itself returns ``AllowedDecision`` — the
  diagnostic is the user's view, not the runtime gate.
"""

from __future__ import annotations

import json
from io import StringIO
from typing import Any

from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError

from ._oidc_testcase import GrantedOIDCTestCase


class TestOIDCShowEffectivePolicyCommand(GrantedOIDCTestCase):
    def _run(self, **opts: Any) -> dict[str, Any]:
        """Invoke the command with ``--format=json`` and return the row."""
        out = StringIO()
        call_command(
            "oidc_show_effective_policy",
            opts.pop("client_id", self.oauth_id),
            f"--username={opts.pop('username', self.user1.username)}",
            "--format=json",
            stdout=out,
            **opts,
        )
        rows = json.loads(out.getvalue())
        self.assertEqual(1, len(rows), out.getvalue())
        return rows[0]

    def test_allowed_user_renders_allowed_decision(self) -> None:
        """
        User1 with the global ``access_oidc`` permission and no
        per-app whitelist hits ``AllowedDecision``.
        """
        row = self._run()
        self.assertEqual("allowed", row["decision"])
        self.assertEqual("", row["deny_reason"])
        self.assertEqual(self.user1.username, row["username"])
        self.assertEqual(self.oauth_id, row["client_id"])

    def test_user_without_global_perm_renders_global_deny(self) -> None:
        """
        Without ``access_oidc``, ``decide`` returns ``GlobalDeny`` —
        the row carries ``deny_reason="global"``. Note the user-level
        context (state, group names) is still rendered: the operator
        sees what the policy saw on its way to the deny.
        """
        # user2 has no perms by default
        row = self._run(username=self.user2.username)
        self.assertEqual("denied", row["decision"])
        self.assertEqual("global", row["deny_reason"])

    def test_app_whitelist_miss_renders_app_deny_with_diagnostics(
        self,
    ) -> None:
        """
        Configure a per-app group whitelist that user1 is not in;
        the row carries ``deny_reason="app"`` AND lists the missing
        group(s) so the operator can act on the output.
        """
        # ``self.oauth_app`` is the fixture app; gate it on a fresh
        # group that user1 is NOT a member of.
        gate_group = Group.objects.create(name="oidc-policy-gate-grp")
        self.oauth_app.groups.add(gate_group)
        try:
            row = self._run()
        finally:
            self.oauth_app.groups.remove(gate_group)
            gate_group.delete()
        self.assertEqual("denied", row["decision"])
        self.assertEqual("app", row["deny_reason"])
        # ``missing_groups`` is the diagnostic payload — the gate
        # group is in the whitelist but the user is not in it.
        self.assertIn("oidc-policy-gate-grp", row["missing_groups"])

    def test_unknown_client_id_raises_command_error(self) -> None:
        """
        Operators paste client_ids from logs; an unknown one must
        produce a clear ``CommandError`` rather than a stack trace.
        """
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_show_effective_policy",
                "no-such-client-id-anywhere",
                f"--username={self.user1.username}",
                stdout=StringIO(),
            )
        self.assertIn("no-such-client-id-anywhere", str(ctx.exception))

    def test_unknown_username_raises_command_error(self) -> None:
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_show_effective_policy",
                self.oauth_id,
                "--username=ghost-user-nonexistent",
                stdout=StringIO(),
            )
        self.assertIn("ghost-user-nonexistent", str(ctx.exception))

    def test_deactivated_app_surfaces_active_false(self) -> None:
        """
        ``AccessPolicy.decide`` doesn't consult ``app.active`` (that
        gate lives in ``validate_bearer_token.is_usable``); but the
        row's ``app_active`` column must surface the status so the
        operator sees deactivation as part of the diagnostic — they
        otherwise wouldn't know why a policy-allowed user still 401s.
        """
        self.oauth_app.active = False
        self.oauth_app.save(update_fields=["active"])
        try:
            row = self._run()
        finally:
            self.oauth_app.active = True
            self.oauth_app.save(update_fields=["active"])
        self.assertIs(False, row["app_active"])
