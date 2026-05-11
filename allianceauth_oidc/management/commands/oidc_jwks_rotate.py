"""``manage.py oidc_jwks_rotate`` — mint a fresh RSA key + kid for JWKS rotation."""  # noqa: E501

from __future__ import annotations

import os
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.core.management.base import BaseCommand, CommandError
from django.utils.translation import gettext as _
from oauth2_provider.utils import jwk_from_pem
from typing_extensions import override

# FIPS 186-4 / NIST SP 800-131A: 2048 is the floor for RSA in modern
# transitions; sub-2048 keys are explicitly disallowed. We refuse below
# this rather than letting an operator silently mint an unusable key.
_MIN_KEY_SIZE = 2048

# RFC 4055 / common cryptographic guidance: 65537 (0x10001) is the
# canonical RSA public exponent. Hard-coded rather than exposed because
# any other choice is either equivalent or a known-bad footgun.
_PUBLIC_EXPONENT = 65537


class Command(BaseCommand):
    """
    Generate a fresh RSA private key for the OIDC JWKS rotation flow.

    Read-only with respect to project state — the command never touches
    Django settings or the database. The operator wires the new PEM
    into ``OAUTH2_PROVIDER`` themselves and decides when to retire the
    previous key from ``OIDC_RSA_PRIVATE_KEYS_INACTIVE``.

    Output shape:

    * Default (no ``--out``): the PEM is printed to stdout, followed
      by the RFC 7638 thumbprint (``kid``) and a four-step rotation
      recipe. Pipe to a file or copy-paste into ``settings.py``.
    * ``--out PATH``: the bare PEM is written to ``PATH`` (mode
      ``0600``); stdout carries the ``kid`` and the recipe so the
      operator still sees what was generated.

    The ``kid`` matches what
    :func:`allianceauth_oidc.tokens._build_jwt` would emit in the
    JWT header for tokens signed with this key — operators can
    eyeball-correlate log lines and JWKS responses without
    recomputing the thumbprint.
    """

    help = _(
        "Mint a fresh RSA private key for JWKS rotation; print PEM and RFC 7638 thumbprint."  # noqa: E501
    )

    @override
    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--out",
            help=_(
                "Write the bare PEM to this path (mode 0600) instead of printing it to stdout. The kid and rotation recipe still go to stdout."  # noqa: E501
            ),
        )
        parser.add_argument(
            "--key-size",
            type=int,
            default=_MIN_KEY_SIZE,
            help=_(
                "RSA key size in bits. Default and floor 2048 (FIPS 186-4); compliance regimes targeting 128-bit security strength typically request 3072+."  # noqa: E501
            ),
        )

    @override
    def handle(self, *args: Any, **options: Any) -> None:
        key_size: int = options["key_size"]
        if key_size < _MIN_KEY_SIZE:
            raise CommandError(
                f"--key-size {key_size} is below the {_MIN_KEY_SIZE}-bit minimum (FIPS 186-4). Refusing to mint a weak key."  # noqa: E501
            )

        private_key = rsa.generate_private_key(
            public_exponent=_PUBLIC_EXPONENT,
            key_size=key_size,
        )
        # PKCS8 + NoEncryption matches what DOT expects to read out of
        # ``OIDC_RSA_PRIVATE_KEY``; the operator is responsible for
        # protecting the PEM at rest (file mode + secret store).
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pem_text = pem_bytes.decode("ascii")
        kid = str(jwk_from_pem(pem_text).thumbprint())

        out_path: str | None = options["out"]
        if out_path:
            # ``os.open`` with ``O_CREAT | O_EXCL`` + mode ``0o600``
            # closes the previous ``write_bytes`` + ``chmod`` race —
            # the file is created with the restrictive mode in one
            # syscall before any bytes hit disk. ``O_EXCL`` also
            # refuses to overwrite an existing file at the target
            # path, so an operator pointing the command at a
            # populated location gets a clear error instead of a
            # silent clobber of a key still in use.
            fd = os.open(
                out_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                os.write(fd, pem_bytes)
            finally:
                os.close(fd)
            self.stdout.write(self._stdout_when_outfile(out_path, kid))
        else:
            self.stdout.write(self._stdout_inline(pem_text, kid))

    @staticmethod
    def _stdout_inline(pem_text: str, kid: str) -> str:
        """PEM + kid + recipe — used when no ``--out`` was given."""
        return f"{pem_text}\nkid: {kid}\n\n{_RECIPE}\n"

    @staticmethod
    def _stdout_when_outfile(out_path: str, kid: str) -> str:
        """Kid + recipe only — PEM is in the file, not stdout."""
        return (
            f"PEM written to {out_path} (mode 0600)\nkid: {kid}\n\n{_RECIPE}\n"
        )


# The recipe is deliberately operator-facing prose, not a Django log
# line — it's the concrete rollout sequence documented at
# ``docs/JWT_ACCESS_TOKENS.md`` § 5 (key rotation), inlined here so
# operators never have to leave their terminal to perform a routine
# rotation. Kept short on purpose; the doc has the long form.
_RECIPE = _(
    """Rotation recipe (overlap window prevents in-flight JWT invalidation):
  1. Move current OIDC_RSA_PRIVATE_KEY into
     OIDC_RSA_PRIVATE_KEYS_INACTIVE.
  2. Set OIDC_RSA_PRIVATE_KEY to the PEM above.
  3. Restart Auth. JWKS now publishes both kids; existing JWTs validate.
  4. After your access-token TTL x 2, drop the old PEM from
     OIDC_RSA_PRIVATE_KEYS_INACTIVE."""
)
