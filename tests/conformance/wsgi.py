"""
WSGI module for the conformance provider container.

Exists solely so ``gunicorn`` (used by the conformance entrypoint to
serve TLS, since Django's stock ``runserver`` cannot) has a stable
``module:application`` import path. ``DJANGO_SETTINGS_MODULE`` is set
on the container's environment, so all Django needs is the standard
WSGI callable.
"""

from __future__ import annotations

from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
