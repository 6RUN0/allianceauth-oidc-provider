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

import nox


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

    Excluded from default sessions because it pulls Docker images and
    takes 10-15 minutes; see tests/conformance/README.md for context.
    """
    compose_file = "tests/conformance/docker-compose.yml"
    cert_path = "tests/conformance/tls/ca.crt"
    # Generate the self-signed CA + provider cert if missing. The
    # conformance suite enforces ``https://`` for OIDC discovery, so
    # the provider container serves TLS via ``runsslserver`` and the
    # suite container imports the CA cert into its Java truststore on
    # startup. Certs are gitignored — re-running ``gen.sh`` is safe
    # (it overwrites). See ``tests/conformance/tls/`` for details.
    if not pathlib.Path(cert_path).is_file():
        session.run("sh", "tests/conformance/tls/gen.sh", external=True)
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
        session.run(
            "python",
            "tests/conformance/run_plan.py",
            *session.posargs,
            external=True,
        )
    finally:
        # ``-v`` wipes the named MongoDB volume so the next run starts
        # from a clean suite-state. Runs unconditionally (try/finally)
        # so an interrupted plan still tears the stack down.
        session.run(
            "docker",
            "compose",
            "-f",
            compose_file,
            "down",
            "-v",
            external=True,
            success_codes=[0, 1],
        )
