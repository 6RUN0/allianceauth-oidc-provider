"""
Shared helpers for JWT-mode access-token tests.

Lives at module level (not on ``OIDCTestCase``) so the
``@override_settings`` decorators on each test class can pick up
the JWT-mode dict at class-definition time and so external test
files (``test_logging.py``, ``test_back_channel_logout.py``) can
import ``split_jwt`` / ``_jwt_mode_oauth2_provider`` without
reaching into a sibling test module.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from django.conf import settings as django_settings


def _jwt_mode_oauth2_provider() -> dict:
    """
    Return ``OAUTH2_PROVIDER`` test dict with JWT mode enabled.

    Snapshot evaluated at call time so per-class
    ``override_settings`` overlays compose cleanly.
    """
    base = dict(django_settings.OAUTH2_PROVIDER)
    base["ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT"] = "jwt"
    return base


def _opaque_mode_oauth2_provider() -> dict:
    """Return ``OAUTH2_PROVIDER`` test dict with explicit opaque mode."""
    base = dict(django_settings.OAUTH2_PROVIDER)
    base["ALLIANCEAUTH_OIDC_DEFAULT_ACCESS_TOKEN_FORMAT"] = "opaque"
    return base


def _b64url_decode(seg: str) -> bytes:
    """Padding-safe URL-safe base64 decode."""
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def split_jwt(token: str) -> tuple[dict, dict]:
    """Return ``(header, payload)`` from a compact JWT (no signature check)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise AssertionError(
            f"Token does not look like a JWT (got {len(parts)} segments): "
            f"{token[:32]!r}..."
        )
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload


def _b64url_encode_nopad(raw: bytes) -> str:
    """URL-safe base64 encode without ``=`` padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def forge_unsigned_jwt(
    payload: dict, header: dict[str, Any] | None = None
) -> str:
    """
    Build an ``alg=none`` JWT (``header.payload.`` with empty signature).

    Negative-test helper: every spot in the suite that needed an
    unsigned JWT to drive an alg-confusion / hint-confusion test
    used to roll its own base64-encoder. Centralising the form
    guarantees those tests all hit the same attack shape and that
    a hardening change (e.g. trailing ``.`` policy) is exercised
    once, not per-copy.
    """
    head = header if header is not None else {"alg": "none", "typ": "JWT"}
    head_seg = _b64url_encode_nopad(
        json.dumps(head, separators=(",", ":")).encode("utf-8")
    )
    payload_seg = _b64url_encode_nopad(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    return f"{head_seg}.{payload_seg}."


def lookalike_access_token_generator(request: Any) -> str:
    """
    Decoy generator used by the startup-wiring regression test.

    ``__module__`` and ``__qualname__`` are rewritten below so the
    formatted ``f"{module}.{qualname}"`` happens to contain the
    canonical dispatcher path as substring — a substring-based
    wiring check would incorrectly stay silent. Identity-based
    detection must still flag the mismatch because
    ``actual is dispatcher`` short-circuits before any name
    introspection.
    """
    del request
    return "lookalike-not-a-real-token"


# DOT resolves ``ACCESS_TOKEN_GENERATOR`` via ``importlib`` against
# the real dotted path. The introspected ``__module__`` /
# ``__qualname__`` below are pure attribute writes — they do not
# affect import — and exist solely to fool the substring formatter.
lookalike_access_token_generator.__module__ = "allianceauth_oidc.tokens"
lookalike_access_token_generator.__qualname__ = (
    "dispatching_access_token_generator"
)
