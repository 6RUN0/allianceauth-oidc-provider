"""
Build the JSON config the conformance suite stores against a plan.

The suite's plan registry persists this dict and re-uses it for
every module the plan kicks off — so the structure has to match what
the suite expects exactly. The shape is documented inline in
``build_plan_config``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .config import (
    CLIENT2_ID,
    CLIENT2_SECRET,
    CLIENT_ID,
    CLIENT_SECRET,
    PASSWORD,
    PUBLIC_URL,
    SUITE_URL,
    USERNAME,
)


def _login_task(host_root: str) -> dict[str, Any]:
    """
    Build the suite-browser task that submits AA's admin login form.

    Two top-level browser entries (``*/callback/*`` and
    ``/o/authorize*``) both need an identical login task to drive
    AA's Django admin form — anonymous users land on
    ``/admin/login/`` before the OIDC happy-path resumes. Marked
    ``optional: true`` so a session that arrives already
    authenticated does not stall waiting for a form that never
    renders. Selectors track admin's template:
    ``id_username`` / ``id_password`` are the field IDs Django ships,
    and ``[type=submit]`` matches both ``<input>`` and ``<button>``
    submit elements across AA versions.
    """
    return {
        "task": "Login",
        "match": f"{host_root}/admin/login*",
        "optional": True,
        "commands": [
            ["text", "id", "id_username", USERNAME],
            ["text", "id", "id_password", PASSWORD],
            ["click", "css", "[type=submit]"],
        ],
    }


def _login_snapshot_task(host_root: str) -> dict[str, Any]:
    """
    Snapshot the login form into the visit's image placeholder.

    Re-auth modules (``oidcc-prompt-login``, ``oidcc-max-age-1``)
    bind an ``ExpectSecondLoginPage`` placeholder to their second
    authorization visit ("a screenshot of this must be uploaded") and
    never finish until it is filled; the login page is exactly the
    right page to snapshot. The suite scopes the fill per *visit*
    (``WebRunner.placeholder`` is set by ``goToUrl``), so on visits
    that bind no placeholder — every first login, both visits of
    ``oidcc-max-age-10000`` — the ``-optional`` action variant is a
    no-op.

    The task is safe only inside the browser entry for *positive*
    authorization flows. Negative modules bind an **error-page**
    placeholder (``ExpectRedirectUriErrorPage`` and friends) to the
    same visit; snapshotting their login page consumes that
    placeholder, the suite's ``waitForPlaceholders`` poller then
    finishes the test while the browser is still mid-flow, and the
    module flips to FAILED (regression seen on
    ``oidcc-response-type-missing`` and
    ``oidcc-ensure-registered-redirect-uri``). Those flows are routed
    to snapshot-free entries by the top-level ``match`` patterns in
    ``build_plan_config`` — keep that routing in mind before moving
    this task around.
    """
    return {
        "task": "Snapshot login page for re-auth placeholder",
        "match": f"{host_root}/admin/login*",
        "optional": True,
        "commands": [
            [
                "wait",
                "id",
                "id_username",
                5,
                ".*",
                "update-image-placeholder-optional",
            ],
        ],
    }


def _wait_for_implicit_submission_task() -> dict[str, Any]:
    """
    Keep the browser window alive until the suite's callback page has
    delivered the authorization response back to the suite.

    The suite's ``implicitCallback.html`` posts the browser URL (the
    fragment; empty for ``response_mode=query``) to
    ``/test/a/conformance/implicit/<random>`` via an **async** XHR on
    ``DOMContentLoaded``. HtmlUnit runs async XHR as a background job,
    so the POST races WebRunner teardown: when the WebRunner finishes
    its task list first, the job dies, the suite never receives the
    submission, and the module sits in WAITING until our runner's poll
    timeout — the "HtmlUnit lottery". The page marks completion by
    inserting ``span#submission_complete`` (either on ``xhr.onload``
    or via the suite's own 5s ``assumeComplete`` fallback for upstream
    issue 766), so waiting for that element pins the window open long
    enough for the background job to run — deterministically, not by
    luck. ``optional: true`` skips the task whenever the flow ends
    anywhere other than the suite callback page (provider error pages,
    negative tests).

    The ``match`` is anchored to the suite origin on purpose. The
    suite builds authorize URLs with the redirect_uri embedded RAW
    (no percent-encoding), so an unanchored
    ``*/test/a/conformance/callback*`` also matches the provider's
    own authorize/error page whenever ``redirect_uri=…/callback…``
    sits in its query string — the wait then runs on the error page,
    times out, and the ``TestFailureException`` interrupts the module
    before ``waitForPlaceholders`` can finish it off the
    already-filled placeholder (seen on
    ``oidcc-ensure-request-object-with-redirect-uri``). Anchoring on
    ``https://<suite-host>/…`` makes the provider-origin URL
    unmatchable.
    """
    return {
        "task": "Wait for implicit submission",
        "match": f"{SUITE_URL}/test/a/conformance/callback*",
        "optional": True,
        "commands": [
            ["wait", "id", "submission_complete", 10],
        ],
    }


def _authorize_flow_tasks(
    host_root: str, *, snapshot_login: bool
) -> list[dict[str, Any]]:
    """
    Task list driving one authorization visit end to end.

    ``snapshot_login=True`` prepends :func:`_login_snapshot_task` —
    only ever set for the positive-flow browser entry (see the
    routing rationale on that function).
    """
    tasks: list[dict[str, Any]] = []
    if snapshot_login:
        # Must precede Login: it captures the still-unfilled form
        # and does not navigate, so Login still matches afterwards.
        tasks.append(_login_snapshot_task(host_root))
    tasks += [
        _login_task(host_root),
        {
            # ``optional`` on the click: after a rejected
            # authorization the browser stays on ``/o/authorize*``
            # showing our error template (no ``allow`` button), and
            # a hard NoSuchElementException would abort the whole
            # WebRunner before the error-page task below can run.
            "task": "Authorize",
            "match": f"{host_root}/o/authorize*",
            "optional": True,
            "commands": [
                ["click", "name", "allow", "optional"],
            ],
        },
        {
            # Negative modules expect the provider to reject the
            # request and bind an ExpectRedirectUriErrorPage-style
            # placeholder; snapshotting the rendered
            # ``<h2>Error: …</h2>`` fills it so the module can
            # finish instead of waiting forever.
            "task": "Verify authorization error page",
            "match": f"{host_root}/o/authorize*",
            "optional": True,
            "commands": [
                [
                    "wait",
                    "css",
                    "h2",
                    5,
                    "Error: .+",
                    "update-image-placeholder-optional",
                ],
            ],
        },
        _wait_for_implicit_submission_task(),
    ]
    return tasks


def _host_root(public_url: str) -> str:
    """
    Strip the OIDC path prefix from ``public_url`` to recover the
    Django host root.

    AA's login and consent templates live on the host root (no
    ``/o/`` prefix); the suite's headless browser hits both during
    automation, so we need a clean base URL — not the
    ``rstrip('/o')`` character-set strip, which silently removes
    every trailing ``/`` and ``o`` and breaks on any host whose path
    happens to share those characters.
    """
    parsed = urlparse(public_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def build_plan_config() -> dict[str, Any]:
    """
    Build the JSON config the suite stores against a plan.

    Mirrors the shape suite plans expect: ``server.discoveryUrl`` plus
    a ``client`` block with our pre-registered credentials. Login
    credentials go under ``resource`` so the suite's browser driver
    can submit AA's standard Django login form.
    """
    host_root = _host_root(PUBLIC_URL)
    return {
        "alias": "conformance",
        "description": "allianceauth-oidc-provider conformance run",
        "server": {
            # OIDC Discovery 1.0 §4: discoveryUrl is the issuer URL
            # plus exactly ``/.well-known/openid-configuration`` — no
            # trailing slash. The suite's CheckDiscEndpointDiscoveryUrl
            # validates this strictly.
            "discoveryUrl": (f"{PUBLIC_URL}/.well-known/openid-configuration"),
        },
        # The basic-cert plan drives two pre-registered clients
        # through some modules. Both must be created on the provider
        # side (see seed.py).
        "client": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        # ``oidcc-server-client-secret-post`` runs
        # ``OIDCCServerTestClientSecretPost.configureClient()`` which
        # copies ``config.client_secret_post`` into ``config.client``
        # before the happy-path starts. The suite assumes "many/most
        # servers restrict each client to using only one auth method"
        # and lets the operator point each variant at a separate
        # pre-registered client; DOT/oauthlib accepts both
        # ``client_secret_basic`` and ``client_secret_post`` on the
        # same client_id, so we mirror the regular block. Without
        # this entry the swap nulls out ``client`` and the module
        # interrupts at GetStaticClientConfiguration.
        "client_secret_post": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        "client2": {
            "client_id": CLIENT2_ID,
            "client_secret": CLIENT2_SECRET,
        },
        "resource": {
            "resourceUrl": f"{PUBLIC_URL}/userinfo/",
        },
        # ``browser`` drives the suite's headless HtmlUnit. The suite
        # selects a TOP-LEVEL entry by matching the ``goToUrl`` URL it
        # tells the browser to visit. Inside the entry, each TASK has
        # its own ``match`` field that fires against the browser's
        # CURRENT URL after navigation.
        #
        # Flow:
        # 1. Suite ``goToUrl(/o/authorize/...)`` — matches the entry
        #    below.
        # 2. AA middleware 302's an unauthenticated user to
        #    ``LOGIN_URL`` (= ``/admin/login/`` in conformance
        #    settings; AA's stock ``/account/login/`` is EVE-SSO-only
        #    with no fillable form).
        # 3. Login task fires against the admin-login URL — fills
        #    ``id_username`` / ``id_password`` and submits. Django
        #    admin's form uses exactly those IDs.
        # 4. On success, admin redirects to the ``next`` URL
        #    (``/o/authorize/...``).
        # 5. If the seeded app has ``skip_authorization=False``, DOT
        #    renders our consent template; the Authorize task clicks
        #    ``name=allow``. Apps seeded with
        #    ``skip_authorization=True`` (the default in
        #    ``seed.py``) skip the consent screen — DOT 302's
        #    directly to the RP callback. Both tasks are
        #    ``optional: true`` so a single configuration handles
        #    both flows.
        # 6. ``[type=submit]`` (CSS selector) matches both
        #    ``<input type="submit">`` (admin login) and
        #    ``<button type="submit">`` (other forms) — the
        #    previous ``button[type=submit]`` selector missed the
        #    admin form's input element.
        "browser": [
            {
                # ``oidcc-ensure-registered-redirect-uri`` appends a
                # random suffix to the registered callback path; the
                # resulting redirect_uri ends in ``/callback/<random>``.
                # Spring's ``simpleMatch("*/callback/*", url)``
                # consequently distinguishes this test from the
                # happy-path flow (whose redirect_uri ends in plain
                # ``/callback``, with no trailing slash). Order matters
                # — most-specific match first; the generic
                # ``/o/authorize*`` entry below would otherwise win.
                "match": "*/callback/*",
                "tasks": [
                    _login_task(host_root),
                    {
                        # Provider rejects the unregistered
                        # redirect_uri and renders
                        # ``allianceauth_oidc/authorize.html`` with
                        # the DOT ``error`` context, surfacing
                        # ``<h2>Error: invalid_request</h2>``. The
                        # ``wait`` command finds that ``h2`` and
                        # triggers ``update-image-placeholder``,
                        # filling the ``redirect_uri_error``
                        # placeholder the test created via
                        # ``ExpectRedirectUriErrorPage`` so
                        # ``waitForPlaceholders`` can transition the
                        # test from ``WAITING`` to ``FINISHED``
                        # without invoking ``processCallback`` (which
                        # would throw ``TestFailureException``
                        # because the bad URI must never be called).
                        "task": "Verify redirect_uri error page",
                        "match": f"{host_root}/o/authorize*",
                        "commands": [
                            [
                                "wait",
                                "css",
                                "h2",
                                20,
                                "Error: invalid_request",
                                "update-image-placeholder",
                            ],
                        ],
                    },
                ],
            },
            {
                # JAR modules (``oidcc-ensure-request-object-with-
                # redirect-uri``, ``oidcc-unsigned-request-object-…``)
                # carry a literal ``request=`` query parameter and
                # bind error-page placeholders to their visit — the
                # login snapshot must not run for them (it would
                # consume the placeholder; see _login_snapshot_task).
                # No other basic-cert authorize URL contains
                # ``request=`` (``request_uri=`` would not match
                # either — different literal).
                "match": f"{host_root}/o/authorize*request=*",
                "tasks": _authorize_flow_tasks(
                    host_root, snapshot_login=False
                ),
            },
            {
                # Positive flows: every well-formed authorize URL
                # carries ``response_type=``. Re-auth modules
                # (prompt-login / max-age-1) land here and get their
                # second-login-page screenshot.
                "match": f"{host_root}/o/authorize*response_type=*",
                "tasks": _authorize_flow_tasks(host_root, snapshot_login=True),
            },
            {
                # Fallback for malformed-request negatives —
                # ``oidcc-response-type-missing`` is the only
                # basic-cert module whose authorize URL lacks
                # ``response_type=``. Same flow, no login snapshot:
                # its visit binds ExpectResponseTypeMissingErrorPage
                # and the provider answers with an error *redirect*,
                # so the module finishes via the suite callback.
                "match": f"{host_root}/o/authorize*",
                "tasks": _authorize_flow_tasks(
                    host_root, snapshot_login=False
                ),
            },
        ],
    }
