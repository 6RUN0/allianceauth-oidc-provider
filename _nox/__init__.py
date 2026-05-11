"""
Nox session modules split out of the root ``noxfile.py``.

Sessions imported from submodules of this package register with nox
exactly as if they were defined inline in the root file. Splitting
heavy / domain-specific sessions out keeps the main noxfile readable.

Currently houses:

* ``_nox.shared`` — constants and helpers shared across noxfile.py
  and the session submodules below (test settings, base argv,
  interpreter matrices, env builder).
* ``_nox.conformance`` — OpenID Conformance Suite (``conformance``)
  driven by ``docker compose`` + the ``run_plan.py`` helper.
* ``_nox.matrix`` — cross-version test matrices (``tests_matrix``,
  ``tests_aa4``).
* ``_nox.mutation`` — cosmic-ray mutation-testing sessions
  (``mutation``, ``mutation_parallel``, ``mutation_html``).
"""
