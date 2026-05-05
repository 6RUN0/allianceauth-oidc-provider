"""
Optional test-time monkey-patch that replaces ``django_redis.get_redis_connection``
with a fakeredis-backed shim.

Alliance Auth's startup probes Redis via ``info()`` for feature
detection; without a live server (or this patch) the test process
fails to boot. ``install_if_enabled()`` is invoked from the test
settings module so it runs before ``INSTALLED_APPS`` are imported,
which is earlier than any AppConfig.ready() that talks to Redis.

Disable explicitly with ``AA_USE_FAKE_REDIS=0`` to point tests at a
real Redis instance.
"""

import os
from unittest.mock import patch

import fakeredis

_server = fakeredis.FakeServer()


class _AACompatFakeRedis(fakeredis.FakeRedis):
    # AA queries server INFO at startup and feature-detects on
    # redis_version; report a recent enough value so its modern path
    # is taken.
    def info(self, *args, **kwargs):
        return {"redis_version": "7.4.0"}


def _fake_get_redis_connection(alias="default", write=True, *args, **kwargs):
    return _AACompatFakeRedis(server=_server)


def install_if_enabled() -> None:
    """
    Activate the patch unless ``AA_USE_FAKE_REDIS=0``. Idempotent — calling
    twice keeps the same fake server.

    The patch is started without a matching ``stop()`` because this runs
    at module-import time of the test settings: there is no enclosing
    test/context to register cleanup against, and the process is
    short-lived (one test run).
    """
    if os.getenv("AA_USE_FAKE_REDIS", "1") == "0":
        return
    patch(
        "django_redis.get_redis_connection",
        new=_fake_get_redis_connection,
    ).start()
