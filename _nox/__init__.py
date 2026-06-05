"""
Nox session modules split out of the root ``noxfile.py``.

Sessions imported from submodules of this package register with nox
exactly as if they were defined inline in the root file. Splitting
heavy / domain-specific sessions out keeps the main noxfile readable.

Session modules (each registers one or more ``@nox.session`` callables
on import):

* ``_nox.conformance`` — OpenID Conformance Suite (``conformance``,
  ``conformance_basic``) driven by ``docker compose`` + the
  ``run_plan.py`` helper.
* ``_nox.dist`` — release-artefact gates (``verify_wheel``: audit the
  built wheel's file inventory against pinned must-have /
  must-not-have patterns).
* ``_nox.i18n`` — the locale toolchain (``makemessages``,
  ``compilemessages``, and the ``messages_check`` integrity gate over
  the shipped ``.po`` / ``.pot`` / ``.mo`` catalogues).
* ``_nox.matrix`` — cross-version test matrices (``tests_matrix``,
  ``tests_aa4``, ``tests_compat``).
* ``_nox.mutation`` — cosmic-ray mutation-testing lifecycle
  (``mutation``, ``mutation_parallel``, ``mutation_html``,
  ``mutation_check``).

Helper modules (not registered as sessions; invoked from sessions
above as standalone scripts or imported as plain Python):

* ``_nox.shared`` — constants and helpers shared across noxfile.py
  and the session submodules (test settings, base argv, interpreter
  matrices, env builder, ``resolve_test_labels``).
* ``_nox._testing`` — pure argv builder (``TestPlan`` ->
  ``build_django_test_argv`` / ``build_canary_argv``) backing the
  ``tests_matrix`` / ``tests_aa4`` / ``tests_compat`` sessions.
  Dependency-free of the nox runtime, so its token-order contract is
  unit-tested in ``tests/unit/test_nox_testing.py``.
* ``_nox.cr_filter_annotations`` — AST-based ``# pragma: no mutate``
  filter for cosmic-ray configs; invoked from ``mutation`` /
  ``mutation_parallel`` reinit branches.
* ``_nox._canary_imports`` — import-canary helper run before the
  Django test loader in off-lock matrix sessions; sweeps the top-level
  suite plus the ``tests/unit/`` tier and catches missing-dependency
  drift cheaply.
"""
