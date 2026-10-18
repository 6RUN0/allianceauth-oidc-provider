"""
OpenID Conformance Suite session.

Brings up a MongoDB + conformance-suite + provider stack via
``docker compose``, runs the default plan via ``run_plan.py``, and
tears the stack down regardless of outcome. Pulled out of
``noxfile.py`` because the Docker orchestration + TLS bootstrap is
domain-specific enough that it crowded the main file. Excluded from
default sessions because it pulls Docker images and takes 10-15
minutes — see ``tests/conformance/README.md`` for context.

Imported from ``noxfile.py`` for session registration side effects.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess  # nosec B404

import nox

# Acknowledged-result ledger shared with ``run_per_module.sh``. Without
# it the suite-side SKIPs listed there turn every run red, so a real
# regression would be indistinguishable from the baseline.
EXPECTED_FAILURES = "tests/conformance/expected_failures.json"


def with_default_expected_failures(posargs: list[str]) -> list[str]:
    """
    Return runner args with the shipped ledger unless one is given.

    An operator-supplied ``--expected-failures`` (``FILE`` or
    ``=FILE`` form) wins, matching the auto-injection in
    ``run_per_module.sh``; the runner rejects abbreviated flags.
    """
    if any(
        arg == "--expected-failures" or arg.startswith("--expected-failures=")
        for arg in posargs
    ):
        return list(posargs)
    return [*posargs, "--expected-failures", EXPECTED_FAILURES]


# Regenerate a month ahead of expiry so a run never starts on a cert
# that lapses mid-plan.
_TLS_MIN_VALIDITY_S = 30 * 24 * 3600
_TLS_FILES = ("ca.crt", "ca.key", "provider.crt", "provider.key")


def tls_certs_need_generation(tls_dir: pathlib.Path) -> bool:
    """
    Return True unless every TLS file exists and both certs stay valid.

    A partially failed generation (``ca.crt`` without ``provider.key``)
    or an expired ``provider.crt`` (825-day lifetime) would otherwise
    surface as a failed image ``COPY`` or a healthcheck that never
    passes, with no hint at the cause.
    """
    if not all((tls_dir / name).is_file() for name in _TLS_FILES):
        return True
    openssl = shutil.which("openssl")
    if openssl is None:
        return True
    return any(
        subprocess.run(  # nosec B603
            [
                openssl,
                "x509",
                "-checkend",
                str(_TLS_MIN_VALIDITY_S),
                "-noout",
                "-in",
                str(tls_dir / cert),
            ],
            capture_output=True,
            check=False,
        ).returncode
        != 0
        for cert in ("ca.crt", "provider.crt")
    )


@nox.session
def conformance(session: nox.Session) -> None:
    """
    Run the OpenID Conformance Suite against a Docker-Compose-built
    provider stack.

    Brings up MongoDB + the conformance suite + our provider, runs the
    default plan via ``run_plan.py``, and tears the stack down
    regardless of outcome. ``--`` args after the session name are
    forwarded to the runner — e.g.::

        uv run nox -s conformance -- --plan oidcc-basic-certification-test-plan
        uv run nox -s conformance -- --strict-warnings

    The shipped ``tests/conformance/expected_failures.json`` ledger is
    applied unless the posargs carry their own ``--expected-failures``.

    ``conformance_basic`` is a convenience session that wraps this
    one with the Basic Certification plan pre-selected (~35 modules,
    20-30 min wall-clock). FAPI profiles (``fapi1-advanced-final``,
    ``fapi2-baseline``) are intentionally NOT exposed: they require
    mTLS client auth, Pushed Authorization Requests (PAR), and JARM
    response signing, none of which the upstream django-oauth-toolkit
    stack implements; running the suite against them would surface
    ~80% spurious failures with no actionable signal. Track FAPI
    support in the README roadmap once DOT or a shim layer
    provides the missing pieces.

    Excluded from default sessions because it pulls Docker images and
    takes 10-15 minutes; see tests/conformance/README.md for context.
    """
    compose_file = "tests/conformance/docker-compose.yml"
    tls_dir = pathlib.Path("tests/conformance/tls")
    # Generate the self-signed CA + provider cert if missing, partial
    # or close to expiry. The conformance suite enforces ``https://``
    # for OIDC discovery, so
    # the provider container serves TLS via ``runsslserver`` and the
    # suite container imports the CA cert into its Java truststore on
    # startup. Certs are gitignored — re-running is safe (overwrites).
    # See ``tests/conformance/tls/`` for details.
    if tls_certs_need_generation(tls_dir):
        _generate_tls_certs(session, tls_dir)
    try:
        # ``--build`` forces a rebuild on every invocation so a stale
        # provider image does not silently mask code edits between
        # iterations. Cheap when nothing changed (Docker reuses the
        # cached layers).
        session.run(
            "docker",
            "compose",
            "-f",
            compose_file,
            "up",
            "-d",
            "--wait",
            "--build",
            external=True,
        )
        # ``run_plan.py`` runs under the project venv (it imports
        # ``requests``/``urllib3``). Dropping ``external=True`` here
        # means nox enforces "this command lives in the session's
        # python" — running ``nox -s conformance`` from a system
        # interpreter without those deps fails cleanly at this line
        # instead of with an opaque ImportError inside the script.
        session.run(
            "python",
            "tests/conformance/run_plan.py",
            *with_default_expected_failures(list(session.posargs)),
        )
    finally:
        # ``-v`` wipes the named MongoDB volume so the next run starts
        # from a clean suite-state. Runs unconditionally (try/finally)
        # so an interrupted plan still tears the stack down. Exit code
        # 0 is the only success — historically the session also
        # accepted ``1`` to absorb "project not running", but the same
        # exit code covers genuine teardown failures (volume removal,
        # kill-timeout) which then silently leaked dangling state into
        # the next run.
        session.run(
            "docker",
            "compose",
            "-f",
            compose_file,
            "down",
            "-v",
            external=True,
        )


@nox.session
def conformance_basic(session: nox.Session) -> None:
    """
    Convenience wrapper around the Basic Certification test plan.

    Equivalent to::

        conformance -- --plan oidcc-basic-certification-test-plan

    The Basic Certification profile (~35 modules) is the standard
    "is this a working OIDC provider" target — covers code flow,
    discovery, JWKS, scope handling, the standard claims. Default
    ``conformance`` session runs the much smaller Config plan (1
    module) for quick smoke checks; this shortcut is for the deeper
    pre-release pass.

    Posargs after ``--`` are appended to the underlying call, so
    flags like ``--strict-warnings`` or ``--include <pattern>`` still
    work::

        uv run nox -s conformance_basic
        uv run nox -s conformance_basic -- --strict-warnings
    """
    session.posargs[:] = [
        "--plan",
        "oidcc-basic-certification-test-plan",
        *session.posargs,
    ]
    conformance(session)


def _generate_tls_certs(session: nox.Session, tls_dir: pathlib.Path) -> None:
    """
    Generate the self-signed CA + provider cert via ``openssl``.

    Pure Python orchestration — no shell — over the system
    ``openssl`` binary, in three steps:

    1. Root CA (10-year lifetime), signs the provider cert.
    2. Provider key + CSR (subject ``/CN=provider``).
    3. CA-signed provider cert with the SAN list the suite needs:
       ``DNS:provider`` for docker-network access plus
       ``DNS:localhost`` + ``IP:127.0.0.1`` so the operator can
       ``curl`` from the host.

    Transient artefacts (CSR, extension file, CA serial) are
    deleted at the end so the directory only carries the four
    files the compose stack mounts (``ca.{crt,key}``,
    ``provider.{crt,key}``).
    """
    ca_key = tls_dir / "ca.key"
    ca_crt = tls_dir / "ca.crt"
    provider_key = tls_dir / "provider.key"
    provider_csr = tls_dir / "provider.csr"
    provider_crt = tls_dir / "provider.crt"
    provider_ext = tls_dir / "provider.ext"
    ca_srl = tls_dir / "ca.srl"

    session.run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca_crt),
        "-days",
        "3650",
        "-subj",
        "/CN=allianceauth-oidc-conformance-CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        external=True,
    )

    session.run(
        "openssl",
        "req",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(provider_key),
        "-out",
        str(provider_csr),
        "-subj",
        "/CN=provider",
        external=True,
    )

    # SAN extension file — drives the third openssl call below.
    # Written as plain ASCII so the file is portable and reviewable
    # without locale assumptions.
    provider_ext.write_text(
        "subjectAltName = DNS:provider, DNS:localhost, "
        "IP:127.0.0.1\n"
        "extendedKeyUsage = serverAuth\n",
        encoding="ascii",
    )

    session.run(
        "openssl",
        "x509",
        "-req",
        "-in",
        str(provider_csr),
        "-CA",
        str(ca_crt),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-out",
        str(provider_crt),
        "-days",
        "825",
        "-extfile",
        str(provider_ext),
        external=True,
    )

    for path in (provider_csr, provider_ext, ca_srl):
        path.unlink(missing_ok=True)
