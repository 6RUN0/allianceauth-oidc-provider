"""
Localisation sessions — the single owner of the locale toolchain.

Three sessions live here so every ``.po`` / ``.pot`` / ``.mo`` touch
point has one home rather than being split between ``noxfile.py`` and a
separate gate module:

* ``makemessages`` — extract translatable strings into the locale tree.
* ``compilemessages`` — compile shipped ``.po`` catalogues to ``.mo``.
* ``messages_check`` — integrity gate over the shipped catalogues.

``messages_check`` is deliberately scoped to *correctness* invariants
that hold today, not *completeness*. The catalogues are translated
incrementally through Transifex, so ``ru`` / ``uk`` carry untranslated
and fuzzy entries by design; a gate that demanded a fully-translated,
fuzzy-free catalogue would block every PR. The three hard checks below
each pass on the current tree and each guards a real failure mode:

1. ``msgfmt --check-format`` — a translation whose ``%(name)s`` /
   ``{0}`` placeholders diverge from the source string raises at render
   time. msgfmt validates only *translated* entries, so incomplete
   catalogues pass.
2. structural parity (``msgcomm --unique`` vs the ``.pot``) — every
   locale ``.po`` must carry exactly the ``.pot``'s message set, so a
   ``.pot`` regenerated without ``msgmerge``-ing a locale is caught.
   Compares by ``msgid`` only, ignoring translation status.
3. ``.mo`` freshness — each shipped ``.mo`` must recompile identically
   from its ``.po`` (compared through ``msgunfmt`` canonical form, which
   is stable across msgfmt binary-layout differences), catching a
   hand-edited ``.po`` whose binary was never recompiled.

Per-locale translation statistics are emitted as an advisory warning,
never a failure.

GNU gettext is an optional system toolchain: absent locally the gate
``skip``s (same opt-in shape as ``markdown_lint`` / ``actions_lint``);
in CI it hard-fails, because the workflow provisions gettext in a step
before this session runs.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import tempfile

import nox

from _nox.shared import LOCALES, PACKAGE_DIR, is_ci, test_env

# gettext binaries the integrity gate shells out to. Detected up front
# so a missing toolchain degrades cleanly rather than erroring mid-check.
_GETTEXT_TOOLS = ("msgfmt", "msgcomm", "msgunfmt")

_LOCALE_DIR = PACKAGE_DIR / "locale"
_POT_PATH = _LOCALE_DIR / "django.pot"


def _po_path(locale: str) -> str:
    """Return the ``.po`` catalogue path for ``locale`` as a string."""
    return str(_LOCALE_DIR / locale / "LC_MESSAGES" / "django.po")


def _mo_path(locale: str) -> str:
    """Return the compiled ``.mo`` path for ``locale`` as a string."""
    return str(_LOCALE_DIR / locale / "LC_MESSAGES" / "django.mo")


def _run(*argv: str) -> subprocess.CompletedProcess[str]:
    """Run a gettext tool, capturing output without raising."""
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        check=False,
    )


def _check_format(locale: str) -> str | None:
    """Return a failure note if ``locale`` has bad format strings."""
    result = _run(
        "msgfmt", "--check-format", "-o", os.devnull, _po_path(locale)
    )
    if result.returncode == 0:
        return None
    detail = (result.stderr or result.stdout).strip()
    return f"  {locale}: msgfmt --check-format failed:\n    {detail}"


def _check_structural_parity(locale: str) -> str | None:
    """Return a failure note if ``locale`` drifts from the ``.pot``."""
    result = _run(
        "msgcomm", "--unique", "--no-wrap", _po_path(locale), str(_POT_PATH)
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return f"  {locale}: msgcomm failed: {detail}"
    # ``--unique`` prints messages present in exactly one input. The
    # shared header (``msgid ""``) is common to both files and never
    # appears here; any other ``msgid`` line means the locale and the
    # template disagree on the message set.
    drifted = [
        line
        for line in result.stdout.splitlines()
        if line.startswith("msgid ") and line.strip() != 'msgid ""'
    ]
    if drifted:
        return (
            f"  {locale}: {len(drifted)} message(s) out of sync with "
            f"django.pot — run ``nox -s makemessages``"
        )
    return None


def _check_mo_freshness(locale: str) -> str | None:
    """Return a failure note if the shipped ``.mo`` is stale."""
    with tempfile.NamedTemporaryFile(suffix=".mo", delete=False) as handle:
        tmp_mo = handle.name
    try:
        compiled = _run("msgfmt", "-o", tmp_mo, _po_path(locale))
        if compiled.returncode != 0:
            detail = (compiled.stderr or compiled.stdout).strip()
            return f"  {locale}: msgfmt compile failed: {detail}"
        # Compare through ``msgunfmt`` canonical text rather than raw
        # bytes: msgfmt versions differ in hash-table layout, so a byte
        # diff would raise false positives across environments.
        recompiled = _run("msgunfmt", tmp_mo)
        shipped = _run("msgunfmt", _mo_path(locale))
        if recompiled.returncode != 0 or shipped.returncode != 0:
            return f"  {locale}: msgunfmt failed while checking .mo"
        if recompiled.stdout != shipped.stdout:
            return (
                f"  {locale}: shipped django.mo is stale — run "
                f"``nox -s compilemessages``"
            )
        return None
    finally:
        pathlib.Path(tmp_mo).unlink()


@nox.session
def messages_check(session: nox.Session) -> None:
    """
    Verify shipped message catalogues are correct and in sync.

    Runs three hard checks per locale (format-string safety, structural
    parity with ``django.pot``, ``.mo`` freshness) and emits translation
    coverage as an advisory warning. See the module docstring for why
    completeness is intentionally *not* gated.

    Requires GNU gettext (``msgfmt`` / ``msgcomm`` / ``msgunfmt``). When
    the toolchain is missing the session ``skip``s locally and ``error``s
    in CI, where an earlier workflow step installs it.
    """
    missing = [tool for tool in _GETTEXT_TOOLS if not shutil.which(tool)]
    if missing:
        note = f"GNU gettext tools missing: {', '.join(missing)}"
        if is_ci():
            session.error(f"{note} — required in CI; install gettext first")
        session.skip(f"{note} — skipping locale integrity gate")

    failures: list[str] = []
    for locale in LOCALES:
        for check in (
            _check_format,
            _check_structural_parity,
            _check_mo_freshness,
        ):
            note = check(locale)
            if note is not None:
                failures.append(note)
        # Advisory only: coverage is Transifex-driven and never gates.
        stats = _run(
            "msgfmt", "--statistics", "-o", os.devnull, _po_path(locale)
        )
        summary = (stats.stderr or stats.stdout).strip()
        if summary:
            session.log(f"{locale}: {summary}")

    if failures:
        session.error(
            "Message catalogue integrity check failed:\n" + "\n".join(failures)
        )
    session.log(f"messages_check OK: {len(LOCALES)} locale(s) verified")


@nox.session
def makemessages(session: nox.Session) -> None:
    """
    Extract translatable strings into the locale tree.

    Runs Django's ``makemessages`` once per locale, writing
    ``locale/<locale>/LC_MESSAGES/django.po`` plus a top-level
    ``django.pot`` template. ``--no-location`` keeps the .po diffs
    stable (no ``source.py:42`` refs that churn on every refactor);
    ``--keep-pot`` retains the template alongside the locale
    catalogues for translation-platform workflows. Invoked from
    inside ``allianceauth_oidc/`` so the catalogues land next to the
    package source, not in the host AA project's ``LOCALE_PATHS``.
    """
    _LOCALE_DIR.mkdir(exist_ok=True)
    with session.chdir(PACKAGE_DIR):
        for locale in LOCALES:
            session.run(
                "django-admin",
                "makemessages",
                "--locale",
                locale,
                "--no-location",
                "--keep-pot",
                env=test_env(session),
            )


@nox.session
def compilemessages(session: nox.Session) -> None:
    """Compile shipped ``.po`` catalogues into ``.mo`` binaries."""
    with session.chdir(PACKAGE_DIR):
        session.run(
            "django-admin",
            "compilemessages",
            env=test_env(session),
        )
