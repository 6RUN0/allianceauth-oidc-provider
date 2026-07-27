"""
Settings-override helpers shared across test modules.

Kept apart from ``tests._oidc_testcase`` so settings-only test
modules (``test_apps_defaults``, ``test_checks``) do not import the
Alliance Auth model fixtures and the whole factory stack just to
borrow a context manager.
"""

import contextlib
from typing import Any

from django.core.signals import setting_changed
from django.test import override_settings
from oauth2_provider.settings import reload_oauth2_settings


@contextlib.contextmanager
def override_settings_no_dot_reload(**overrides: Any):
    """
    ``override_settings`` with DOT's ``setting_changed`` receiver muted.

    DOT 3.4 connects ``reload_oauth2_settings`` to ``setting_changed``;
    its ``reload()`` iterates ``OAUTH2_PROVIDER`` via
    ``_warn_deprecated_settings``. A degraded override such as
    ``OAUTH2_PROVIDER=None`` — used to exercise our own defensive
    "not a dict / missing" handling — makes that receiver raise
    ``TypeError: argument of type 'NoneType' is not iterable`` on
    ``__enter__``, before the test body runs. Disconnecting the
    receiver for the duration lets the override reach our code without
    DOT's global reload amplifying the degraded shape. Because the
    receiver never fires while disconnected, ``oauth2_settings`` keeps
    its pre-override values throughout and needs no restore.

    The reconnect is guarded on ``disconnect()``'s return value so the
    helper never ADDS a receiver that was not connected to begin with
    (nested use, or a future DOT that stops auto-connecting it).
    """
    was_connected = setting_changed.disconnect(reload_oauth2_settings)
    try:
        with override_settings(**overrides):
            yield
    finally:
        if was_connected:
            setting_changed.connect(reload_oauth2_settings)
