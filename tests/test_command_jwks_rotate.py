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

from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError

from ._oidc_testcase import OIDCTestCase


class TestOIDCJwksRotateCommand(OIDCTestCase):
    """
    ``manage.py oidc_jwks_rotate`` mints a fresh RSA private key and
    prints its RFC 7638 thumbprint so operators can plan the JWKS
    overlap window. Read-only by design — the command never touches
    Django settings or the database; the operator wires the new PEM
    into ``OAUTH2_PROVIDER`` themselves.

    JWT-mode operators reach this command on the canonical rotation
    paths: scheduled compliance rotation, leaked-key incident, or
    the initial flip from opaque-only to JWT.
    """

    PEM_BEGIN = "-----BEGIN PRIVATE KEY-----"
    PEM_END = "-----END PRIVATE KEY-----"

    def _extract_pem(self, blob: str) -> str:
        """Slice the PEM substring out of mixed stdout/file content."""
        start = blob.index(self.PEM_BEGIN)
        end = blob.index(self.PEM_END) + len(self.PEM_END)
        return blob[start:end]

    def test_default_emits_2048bit_pkcs8_pem(self) -> None:
        """
        Stdout carries a parseable RSA-2048 PEM. 2048 is the
        deployment-wide default to match
        ``django-oauth-toolkit``'s recommendation and keep generation
        cheap on container restart.
        """
        from cryptography.hazmat.primitives import serialization

        out = StringIO()
        call_command("oidc_jwks_rotate", stdout=out)
        text = out.getvalue()
        self.assertIn(self.PEM_BEGIN, text)
        self.assertIn(self.PEM_END, text)
        key = serialization.load_pem_private_key(
            self._extract_pem(text).encode(), password=None
        )
        # ``RSAPrivateKey`` is the only path through ``load_pem_private_key``
        # that exposes ``.key_size``; mypy/basedpyright narrow this via the
        # ``key_size`` access itself.
        self.assertEqual(2048, key.key_size)  # type: ignore[union-attr]

    def test_kid_line_matches_rfc7638_thumbprint(self) -> None:
        """
        The printed ``kid: <thumbprint>`` matches what
        ``oauth2_provider.utils.jwk_from_pem(...).thumbprint()``
        produces — the same call the JWT generator
        (``allianceauth_oidc/tokens.py:_build_jwt``) uses to populate
        the JWT header. Operators can therefore eyeball-correlate
        log lines, JWKS responses, and rotated keys without
        recomputing the thumbprint by hand.
        """
        from oauth2_provider.utils import jwk_from_pem

        out = StringIO()
        call_command("oidc_jwks_rotate", stdout=out)
        text = out.getvalue()
        pem = self._extract_pem(text)
        expected_kid = str(jwk_from_pem(pem).thumbprint())
        self.assertIn(f"kid: {expected_kid}", text)

    def test_out_path_writes_clean_pem_only(self) -> None:
        """
        ``--out PATH`` writes a bare PEM ready to drop into
        ``OAUTH2_PROVIDER["OIDC_RSA_PRIVATE_KEY"]`` (or a
        ``Path.read_text()`` call from settings.py). Stdout in this
        mode still carries the kid + recipe so operators see the
        thumbprint, but it must NOT also contain the PEM (the file
        is the canonical artifact; printing it twice invites
        copy-paste of the wrong copy).
        """
        import os
        import tempfile
        from pathlib import Path

        from cryptography.hazmat.primitives import serialization

        # The command opens ``--out`` with ``O_EXCL`` to close the
        # create-then-chmod race; the path must NOT exist when the
        # call starts. ``mkstemp`` returns a unique path; close +
        # unlink immediately so the next ``os.open(..., O_EXCL)``
        # succeeds. ``Path.unlink(missing_ok=True)`` is the
        # ruff-PTH-friendly idiom for "remove if it still exists".
        fd, path_str = tempfile.mkstemp(suffix=".pem")
        os.close(fd)
        out_path = Path(path_str)
        out_path.unlink()
        self.addCleanup(lambda: out_path.unlink(missing_ok=True))
        path = path_str

        out = StringIO()
        call_command("oidc_jwks_rotate", "--out", path, stdout=out)

        stdout_text = out.getvalue()
        self.assertNotIn(self.PEM_BEGIN, stdout_text)
        # kid still surfaces in stdout so the operator sees what was
        # generated even when the PEM lands in a file.
        self.assertIn("kid:", stdout_text)

        from pathlib import Path as _Path

        file_text = _Path(path).read_text()
        self.assertTrue(file_text.startswith(self.PEM_BEGIN))
        # Trailing newline is fine; no recipe / kid in the file.
        self.assertNotIn("kid:", file_text)
        # Sanity: cryptography accepts the file's content.
        serialization.load_pem_private_key(file_text.encode(), password=None)

    def test_keysize_arg_honoured(self) -> None:
        """
        ``--key-size`` lets operators upgrade to compliance-grade
        sizes (FIPS 186-4 recommends >= 3072 for >= 128-bit
        security). 3072 chosen over 4096 to keep the test under
        one second on the lower-end CI runners.
        """
        from cryptography.hazmat.primitives import serialization

        out = StringIO()
        call_command("oidc_jwks_rotate", "--key-size", "3072", stdout=out)
        text = out.getvalue()
        key = serialization.load_pem_private_key(
            self._extract_pem(text).encode(), password=None
        )
        self.assertEqual(3072, key.key_size)  # type: ignore[union-attr]

    def test_rejects_below_minimum_keysize(self) -> None:
        """
        Sub-2048 RSA is broken by modern factoring research and
        explicitly disallowed by FIPS 186-4 / NIST SP 800-131A. The
        command refuses to generate one rather than letting an
        operator type ``--key-size 1024`` and silently produce a key
        no JWT consumer should accept. The regex pin ensures the
        rejection comes from our policy, not from a stray "Unknown
        command" or "Unknown argument" CommandError that would
        false-positive a missing implementation.
        """
        with self.assertRaisesRegex(
            CommandError, r"(?i)key.?size|2048|minimum"
        ):
            call_command(
                "oidc_jwks_rotate",
                "--key-size",
                "1024",
                stdout=StringIO(),
            )

    def test_min_key_size_constant_is_exactly_2048(self) -> None:
        # Pin ``_MIN_KEY_SIZE = 2048``. ``NumberReplacer`` flipping
        # the literal to neighbours (2047 / 2049) would silently
        # shift the FIPS 186-4 floor — a regression that
        # ``test_rejects_below_minimum_keysize`` does not catch
        # because 1024 < 2049 still fails. Only the exact literal
        # assertion pins it.
        from allianceauth_oidc.management.commands.oidc_jwks_rotate import (
            _MIN_KEY_SIZE,
        )

        self.assertEqual(2048, _MIN_KEY_SIZE)

    def test_outfile_written_with_mode_0o600(self) -> None:
        # Pin ``0o600`` (owner read+write only) on the ``os.open``
        # call. ``NumberReplacer`` flipping to 0o601 would silently
        # grant world-execute on a secret file. The existing
        # ``--out`` test verifies the bytes land in the file but
        # never inspects POSIX permissions.
        import os
        import stat
        import tempfile
        from pathlib import Path

        fd, path_str = tempfile.mkstemp(suffix=".pem")
        os.close(fd)
        out_path = Path(path_str)
        out_path.unlink()
        self.addCleanup(lambda: out_path.unlink(missing_ok=True))

        call_command("oidc_jwks_rotate", "--out", path_str, stdout=StringIO())
        mode = stat.S_IMODE(out_path.stat().st_mode)
        # Apply the standard umask the OS may impose; the command
        # opens with mode 0o600 which on a sensible umask (022 or
        # narrower) produces exactly 0o600. Any wider mode would
        # signal a regression on the literal.
        self.assertEqual(
            0o600,
            mode,
            f"file mode {oct(mode)} differs from expected 0o600; "
            "NumberReplacer on the literal?",
        )
