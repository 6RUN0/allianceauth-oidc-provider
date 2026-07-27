"""
Drift gate: compose-provided ``CONFORMANCE_*`` env vs runner defaults.

The conformance credentials live in ``tests/conformance/runner/config.py``
and are consumed from two different processes:

* ``seed.py`` runs **inside** the provider container and sees the
  ``environment:`` block of the ``provider`` service in
  ``docker-compose.yml``;
* ``run_plan.py`` runs on the **host**, where those variables are
  normally unset, so it uses the ``config.py`` defaults.

Any compose value that diverges from the code default therefore splits
the two sides: the app is seeded with one secret while the suite
authenticates with another, and every module that reaches ``/o/token/``
fails with ``401 invalid_client``. That is exactly what happened when
the runner default grew the >=32-byte padding (suite HS256 preflight)
while compose kept shipping the original short secret.

This gate asserts every ``CONFORMANCE_<suffix>`` key on the provider
service whose ``<suffix>`` is a ``runner.config`` constant carries the
default value, so compose can pin/document a variable but can never
silently fork it.

ORM-free unit tier: file parsing plus an import of the stdlib-only
``runner.config``; no Django, no docker.
"""

from __future__ import annotations

import importlib
import os
import pathlib
import unittest
from unittest import mock

try:
    import yaml
except ModuleNotFoundError:  # off-lock matrix venvs may lack PyYAML
    yaml = None  # type: ignore[assignment]

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_COMPOSE = _REPO_ROOT / "tests" / "conformance" / "docker-compose.yml"
_PREFIX = "CONFORMANCE_"


def _runner_config_defaults() -> dict[str, str]:
    """Import ``runner.config`` with all ``CONFORMANCE_*`` env stripped."""
    clean_env = {
        k: v for k, v in os.environ.items() if not k.startswith(_PREFIX)
    }
    with mock.patch.dict(os.environ, clean_env, clear=True):
        from tests.conformance.runner import config

        module = importlib.reload(config)
    return {
        name: value
        for name, value in vars(module).items()
        if name.isupper() and isinstance(value, str)
    }


@unittest.skipIf(yaml is None, "PyYAML not installed in this venv")
class ComposeEnvMatchesRunnerDefaultsTests(unittest.TestCase):
    """Provider-service env must never fork the runner credentials."""

    def test_provider_env_matches_runner_config_defaults(self) -> None:
        with _COMPOSE.open(encoding="utf-8") as fh:
            compose = yaml.safe_load(fh)
        environment = compose["services"]["provider"]["environment"]
        defaults = _runner_config_defaults()

        mismatched = {
            key: (str(value), defaults[key[len(_PREFIX) :]])
            for key, value in environment.items()
            if key.startswith(_PREFIX)
            and key[len(_PREFIX) :] in defaults
            and str(value) != defaults[key[len(_PREFIX) :]]
        }
        self.assertEqual(
            {},
            mismatched,
            "docker-compose.yml overrides runner-config defaults for the "
            "provider container; seed.py (container) and run_plan.py "
            "(host) would use different credentials "
            "(key: (compose value, config default)): "
            f"{mismatched}",
        )

    def test_gate_sees_the_credential_defaults(self) -> None:
        # Vacuity guard: were ``runner.config`` renamed or the constant
        # scrape broken, the gate above would compare nothing and pass
        # forever. Pin the constants the invariant is really about.
        defaults = _runner_config_defaults()
        for name in ("CLIENT_ID", "CLIENT_SECRET", "USERNAME", "PASSWORD"):
            self.assertIn(name, defaults)


if __name__ == "__main__":
    unittest.main()
