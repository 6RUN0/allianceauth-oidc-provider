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
    gen_script = pathlib.Path("tests/conformance/tls/gen.sh")
    # Generate the self-signed CA + provider cert if missing. The
    # conformance suite enforces ``https://`` for OIDC discovery, so
    # the provider container serves TLS via ``runsslserver`` and the
    # suite container imports the CA cert into its Java truststore on
    # startup. Certs are gitignored — re-running ``gen.sh`` is safe
    # (it overwrites). See ``tests/conformance/tls/`` for details.
    if not pathlib.Path(cert_path).is_file():
        if not gen_script.is_file():
            session.error(
                f"TLS bootstrap script {gen_script} missing; cannot "
                "generate the CA / provider cert. Restore it from git "
                "or skip the conformance session."
            )
        session.run("sh", str(gen_script), external=True)
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
            *session.posargs,
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
