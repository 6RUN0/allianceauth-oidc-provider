"""Utility helpers: per-app logging and secret-safe debug-meta builders."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NewType, TypedDict

from typing_extensions import Self

from .app_settings import OIDCSettings

__all__ = [
    "OIDCDebugMeta",
    "RedactedSecret",
    "SecretRedactor",
    "app_log",
    "build_oidc_debug_meta",
    "mask_secret",
    "redact_secret",
]


# A string that has passed through ``redact_secret``. Runtime no-op
# (NewType is erased), but the type-checker now refuses to accept a raw
# ``str`` from ``request.POST.get("client_secret")`` in any field that
# is annotated as ``RedactedSecret``. Catches "forgot to call
# redact_secret" at edit time.
RedactedSecret = NewType("RedactedSecret", str)


class OIDCDebugMeta(TypedDict):
    """
    Curated payload for ``debug_mode`` token-endpoint logging.

    The schema is fixed (every field always present, ``None`` for
    "not in this request"). Secret-shaped fields are typed
    ``RedactedSecret | None`` so the type-checker fails any future
    code that tries to put raw ``request.POST.get("client_secret")``
    here without going through ``redact_secret``.
    """

    grant_type: str | None
    scope: str | None
    client_id: str | None
    redirect_uri: str | None
    code: RedactedSecret | None
    refresh_token_req: RedactedSecret | None
    client_secret: RedactedSecret | None
    assertion: RedactedSecret | None
    token_type: str | None
    expires_in: int | None
    scope_resp: str | None
    access_token: RedactedSecret | None
    refresh_token: RedactedSecret | None
    id_token: RedactedSecret | None


def app_log(
    logger: logging.Logger,
    app: object,
    msg: str,
    *args: object,
    **kwargs: Any,
) -> None:
    """
    Log at INFO level if application in debug_mode, else at DEBUG level.

    Rationale:
    - debug_mode is enabled per OAuth application so admins can diagnose issues
      safely without adding noise to production logs.
    - `.isEnabledFor()` avoids unnecessary `.log()` calls (and kwargs handling)
      when the level is disabled.
    - note: `*args` are evaluated BEFORE calling this function. If you pass
      expensive-to-compute arguments, guard them with
      `if logger.isEnabledFor(level):` at the call site. This helper preserves
      lazy message formatting.

    Args:
        logger: The logger instance to use.
        app: The application instance with a 'debug_mode' attribute.
        msg: The log message format string.
        args: Arguments to be formatted into the log message.
        kwargs: Passed to logger (e.g. extra=..., exc_info=True).
    """
    level = (
        logging.INFO if getattr(app, "debug_mode", False) else logging.DEBUG
    )
    if logger.isEnabledFor(level):
        logger.log(level, msg, *args, **kwargs)


def mask_secret(
    value: object, *, head: int = 2, tail: int = 2
) -> RedactedSecret | None:
    """
    Mask a secret value, exposing only ``head``/``tail`` characters.

    Why masking exists: in debug scenarios you may need to confirm a secret
    is present/non-empty (or changing), but you must never log the full value.

    Args:
        value: The secret value to mask.
        head: Number of characters to show at the start.
        tail: Number of characters to show at the end.

    Returns:
        The masked secret string, or None if the input was None.
    """
    if value is None:
        return None
    if isinstance(value, bytes):
        s = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        s = value
    else:
        return RedactedSecret(f"<non-string:{type(value).__name__}>")
    if not s:
        return RedactedSecret("")
    head = max(0, head)
    tail = max(0, tail)
    if head + tail == 0:
        return RedactedSecret("...")
    if len(s) <= head + tail:
        return RedactedSecret("*" * len(s))
    return RedactedSecret(f"{s[:head]}…{s[-tail:]}")


@dataclass(frozen=True, slots=True)
class SecretRedactor:
    """
    Stateful redactor that turns secret-shaped values into
    ``RedactedSecret``.

    Same semantics as the free ``redact_secret`` function, but with
    its three settings (``enabled``, ``head``, ``tail``) captured in
    the instance instead of read from ``django.conf.settings`` on
    every call. Tests can construct one inline
    (``SecretRedactor(enabled=True, head=4, tail=4)``) without
    ``@override_settings`` boilerplate, and request-scoped code can
    reuse the same instance across many fields without re-reading
    settings each time.
    """

    enabled: bool = False
    head: int = 2
    tail: int = 2

    def __call__(self, value: object) -> RedactedSecret | None:
        """Redact ``value`` according to the captured settings."""
        if value is None:
            return None
        if not self.enabled:
            return RedactedSecret("<redacted>")
        return mask_secret(value, head=self.head, tail=self.tail)

    @classmethod
    def from_settings(cls, settings: OIDCSettings) -> Self:
        """Build a redactor from a resolved ``OIDCSettings`` snapshot."""
        return cls(
            enabled=settings.log_masked_secrets,
            head=settings.log_mask_head,
            tail=settings.log_mask_tail,
        )

    @classmethod
    def from_django(cls) -> Self:
        """Convenience for the legacy ``app_settings`` accessors."""
        return cls.from_settings(OIDCSettings.from_django())


def redact_secret(value: object) -> RedactedSecret | None:
    """
    Return a redacted version of the secret value for logging.

    Backward-compat wrapper that constructs a fresh ``SecretRedactor``
    from current Django settings on every call. Production code paths
    that issue many redactions in a single request should build a
    ``SecretRedactor`` instance once and reuse it instead — that's what
    ``build_oidc_debug_meta`` does now.

    Args:
        value: The secret value to redact.

    Returns:
        Redacted secret string, or None if the input was None.
    """
    return SecretRedactor.from_django()(value)


def build_oidc_debug_meta(
    request: object,
    payload: Mapping[str, Any] | None,
    *,
    redactor: SecretRedactor | None = None,
) -> OIDCDebugMeta:
    """
    Build a dict safe for logging in debug_mode.

    Never returns raw token strings or secrets.

    Why we return a curated "meta" instead of logging request/response as-is:
    - the token endpoint can contain access_token/refresh_token/id_token;
      logging them would be a serious credential leak.
    - for diagnostics, grant_type/scope/client_id/redirect_uri
      plus "secret present" (redacted) is usually sufficient.
    - this helper must be "safe by construction": it always returns
      sanitized data.

    .. warning::
       This builds the dict **eagerly** and runs the redactor on every
       secret-shaped field. Always guard the call with
       ``if logger.isEnabledFor(level)`` AND the per-app
       ``debug_mode`` flag, or you will pay the construction cost on every
       request whether or not the log line is actually emitted. The
       ``%s``-style placeholder in ``logger.log(...)`` does not save you —
       function arguments are evaluated before ``log()`` decides to suppress.

    Args:
        request: The HTTP request object.
        payload: The response payload mapping.
        redactor: Optional ``SecretRedactor`` — pass one to reuse a
            single instance across many calls (avoids re-reading
            settings) or to inject test-controlled masking. Defaults
            to ``SecretRedactor.from_django()``.

    Returns:
        Safe dict for logging.
    """
    redact = redactor or SecretRedactor.from_django()
    post = getattr(request, "POST", None)

    def post_get(key: str) -> Any:
        # request.POST may not be a QueryDict in some edge setups,
        # so we defensively check for a callable `.get()`.
        if post is None:
            return None
        getter = getattr(post, "get", None)
        return getter(key) if callable(getter) else None

    payload_dict: Mapping[str, Any] = payload or {}

    return {
        # request-side (safe)
        "grant_type": post_get("grant_type"),
        "scope": post_get("scope"),
        "client_id": post_get("client_id"),
        "redirect_uri": post_get("redirect_uri"),
        "code": redact(post_get("code")),
        "refresh_token_req": redact(post_get("refresh_token")),
        "client_secret": redact(post_get("client_secret")),
        "assertion": redact(post_get("assertion")),
        # response-side (NEVER raw)
        "token_type": payload_dict.get("token_type"),
        "expires_in": payload_dict.get("expires_in"),
        "scope_resp": payload_dict.get("scope"),
        "access_token": redact(payload_dict.get("access_token")),
        "refresh_token": redact(payload_dict.get("refresh_token")),
        "id_token": redact(payload_dict.get("id_token")),
    }
