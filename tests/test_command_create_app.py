"""
Tests for ``manage.py oidc_*`` operator commands.

The commands are thin wrappers around the ORM; tests verify the
contract operators rely on:

* Where applicable, ``--dry-run`` on destructive commands does not
  write.
* ``--format=json`` produces parseable output.
* Destructive commands are idempotent (re-running on a cleaned-up
  subject is a no-op); read-only commands return stable output.
"""

from __future__ import annotations

import json
from io import StringIO

from allianceauth.authentication.models import State
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import CommandError
from oauth2_provider.models import (
    get_application_model,
)

from ._oidc_testcase import REDIRECT_URI, OIDCTestCase


class TestOIDCCreateAppCommand(OIDCTestCase):
    def test_creates_app_and_emits_credentials(self) -> None:
        out = StringIO()
        call_command(
            "oidc_create_app",
            "--name=Test New App",
            f"--user-id={self.user1.pk}",
            f"--redirect-uri={REDIRECT_URI}",
            "--format=json",
            stdout=out,
        )
        result = json.loads(out.getvalue())
        self.assertEqual(1, len(result))
        row = result[0]
        # Raw client_secret is shown ONCE — operator must capture it.
        self.assertTrue(row["client_secret"])
        self.assertEqual("Test New App", row["name"])
        # App actually exists in the DB with the rendered client_id.
        Application = get_application_model()
        self.assertTrue(
            Application.objects.filter(client_id=row["client_id"]).exists()
        )

    def test_unknown_user_id_fails_loudly(self) -> None:
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=x",
                "--user-id=999999",
                stdout=StringIO(),
            )
        self.assertIn("999999", str(ctx.exception))

    def test_unknown_state_fails_before_app_is_created(self) -> None:
        Application = get_application_model()
        before = Application.objects.count()
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=will-not-exist",
                f"--user-id={self.user1.pk}",
                "--state=NoSuchState",
                stdout=StringIO(),
            )
        self.assertIn("NoSuchState", str(ctx.exception))
        # Atomic: failed validation must not leave a partial app.
        self.assertEqual(before, Application.objects.count())

    def test_unknown_group_fails_before_app_is_created(self) -> None:
        """
        Symmetric with ``test_unknown_state_fails_before_app_is_created``:
        an unknown ``--group`` must raise ``CommandError`` before the
        app is persisted, not silently drop the group reference.
        """
        Application = get_application_model()
        before = Application.objects.count()
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=will-not-exist-grp",
                f"--user-id={self.user1.pk}",
                "--group=NoSuchGroup",
                stdout=StringIO(),
            )
        self.assertIn("NoSuchGroup", str(ctx.exception))
        self.assertEqual(before, Application.objects.count())

    def test_state_and_group_links_are_persisted(self) -> None:
        State.objects.get_or_create(name="Member")
        grp, _ = Group.objects.get_or_create(name="cmd-grp")
        out = StringIO()
        call_command(
            "oidc_create_app",
            "--name=With Restrictions",
            f"--user-id={self.user1.pk}",
            "--state=Member",
            "--group=cmd-grp",
            "--format=json",
            stdout=out,
        )
        client_id = json.loads(out.getvalue())[0]["client_id"]
        Application = get_application_model()
        app = Application.objects.get(client_id=client_id)
        self.assertIn("Member", app.states.values_list("name", flat=True))
        self.assertIn(grp, app.groups.all())

    def test_default_pkce_required_is_true(self) -> None:
        """
        No flag → app.pkce_required matches the model default (True,
        per RFC 9700 secure-by-default). The rendered row also shows
        the flag so the operator sees what was created.
        """
        out = StringIO()
        call_command(
            "oidc_create_app",
            "--name=Default PKCE",
            f"--user-id={self.user1.pk}",
            "--format=json",
            stdout=out,
        )
        row = json.loads(out.getvalue())[0]
        self.assertTrue(row["pkce_required"])
        Application = get_application_model()
        app = Application.objects.get(client_id=row["client_id"])
        self.assertTrue(app.pkce_required)

    def test_no_pkce_required_flag_disables(self) -> None:
        """
        ``--no-pkce-required`` (BooleanOptionalAction) is the documented
        opt-out for legacy clients. The created row must persist with
        ``pkce_required=False``.
        """
        out = StringIO()
        call_command(
            "oidc_create_app",
            "--name=Legacy Client",
            f"--user-id={self.user1.pk}",
            "--no-pkce-required",
            "--format=json",
            stdout=out,
        )
        row = json.loads(out.getvalue())[0]
        self.assertFalse(row["pkce_required"])
        Application = get_application_model()
        app = Application.objects.get(client_id=row["client_id"])
        self.assertFalse(app.pkce_required)

    def test_missing_name_argument_is_rejected(self) -> None:
        # Pin ``required=True`` on ``--name``. ``ReplaceTrueWithFalse``
        # would make the argument optional and let argparse pass an
        # empty / missing name through to the model layer, where it
        # would silently create an app with an empty name field.
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                f"--user-id={self.user1.pk}",
                stdout=StringIO(),
            )
        self.assertIn("name", str(ctx.exception).lower())

    def test_missing_user_id_argument_is_rejected(self) -> None:
        # Symmetric: pin ``required=True`` on ``--user-id``.
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=No User",
                stdout=StringIO(),
            )
        self.assertIn("user-id", str(ctx.exception).lower())

    def test_mixed_valid_and_invalid_state_lists_only_invalid(self) -> None:
        # Pin ``missing = set(options[...]) - {s.name for s in states}``
        # against the ``Sub_BitOr`` mutant. The OR mutation would
        # collapse subtraction into set union, leaking VALID state
        # names into the error message alongside the invalid ones.
        # The XOR mutation happens to agree with subtraction on the
        # "all-missing" input the existing test uses, so the
        # discriminator requires a mix of valid + invalid.
        # Priority is unique; pick a high value unlikely to collide
        # with the fixture-bootstrapped states (Member=10, Blue=20,
        # Guest=0 etc.).
        State.objects.get_or_create(
            name="MixedGood",
            defaults={"priority": 9001},
        )
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=mix-state",
                f"--user-id={self.user1.pk}",
                "--state=MixedGood",
                "--state=MixedBad",
                stdout=StringIO(),
            )
        msg = str(ctx.exception)
        self.assertIn("MixedBad", msg)
        # The valid state name MUST NOT appear in the error —
        # ``Sub_BitOr`` mutation would surface it.
        self.assertNotIn("MixedGood", msg)

    def test_mixed_valid_and_invalid_group_lists_only_invalid(self) -> None:
        # Symmetric: same ``Sub_BitOr`` mutant on the group lookup.
        Group.objects.get_or_create(name="MixedGoodGroup")
        with self.assertRaises(CommandError) as ctx:
            call_command(
                "oidc_create_app",
                "--name=mix-group",
                f"--user-id={self.user1.pk}",
                "--group=MixedGoodGroup",
                "--group=MixedBadGroup",
                stdout=StringIO(),
            )
        msg = str(ctx.exception)
        self.assertIn("MixedBadGroup", msg)
        self.assertNotIn("MixedGoodGroup", msg)

    def test_logentry_write_failure_does_not_undo_creation(self) -> None:
        # Pin ``except Exception`` on the LogEntry write.
        # ``ExceptionReplacer`` narrowing the catch (e.g. to
        # ``OSError``) would let a real DB failure during audit
        # propagate, breaking the creation flow that already
        # committed the app. The contract documented in-source:
        # "LogEntry is best-effort; failing to record audit must
        # not undo the creation."
        from unittest import mock

        Application = get_application_model()
        before = Application.objects.count()
        with mock.patch(
            "django.contrib.admin.models.LogEntry.objects.log_action",
            side_effect=RuntimeError("admin log table on fire"),
        ):
            out = StringIO()
            call_command(
                "oidc_create_app",
                "--name=Audit Failure Recovery",
                f"--user-id={self.user1.pk}",
                "--format=json",
                stdout=out,
            )
        # App was created and rendered despite the audit failure.
        result = json.loads(out.getvalue())
        self.assertEqual(1, len(result))
        self.assertEqual("Audit Failure Recovery", result[0]["name"])
        self.assertEqual(before + 1, Application.objects.count())
