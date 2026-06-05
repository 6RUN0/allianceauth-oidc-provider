"""
ORM-free unit tier.

Tests here import plain Python helpers (e.g. the ``_nox._testing`` argv
builder) and must NOT depend on Django models, the app registry, or a
booted Alliance Auth. They run under the standard ``tests`` label like
the rest of the suite, but stay importable in the lightweight off-lock
matrix venvs as well (the import canary sweeps this package).
"""
