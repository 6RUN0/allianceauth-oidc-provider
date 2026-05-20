# Mutation testing

Mutation testing is a *test-suite quality* gate, not a code-correctness
gate. It measures whether the existing tests would actually catch
regressions, by mutating the source in small semantic ways ("mutants")
and observing whether any test fails. A surviving mutant is a hole in
the test suite, not a bug in the code.

This module uses [cosmic-ray](https://cosmic-ray.readthedocs.io/).
We initially evaluated mutmut 2.x, but its Pony-ORM result cache is
incompatible with Python 3.13's tightened iterator protocol and the
upstream fix has not landed; mutmut 3.x is pytest-only and would
force a parallel `pytest-django` toolchain. cosmic-ray supports the
Django test runner directly through a `test-command` config field
and stores its work-queue in plain sqlite.

---

## When to run

**Run before a release cut.** A full sweep over `allianceauth_oidc/`
takes multiple hours wall-clock (thousands of mutants × ~7-10 s
baseline test suite). It is **not** a per-commit gate, and it is
**not** part of CI.

Targeted sweeps over a single file or feature area are reasonable
per-feature: when you add a new safety guard (e.g. a fresh policy
check in `security.py`, a logout-token claim invariant, or a
dead-letter recorder branch), narrow `cosmic-ray.toml::module-path`
to that file temporarily and run cosmic-ray against just it to
confirm the new tests actually pin the new invariant.

---

## How to run

Full sweep (multi-hour):

```sh
make mutation
```

Internally this:

1. `cosmic-ray init cosmic-ray.toml mutation.sqlite` — seeds the
   work-queue with one mutant per AST mutation site.
2. `python _nox/cr_filter_annotations.py mutation.sqlite` —
   marks `BinOp(BitOr)` mutants inside PEP 604 type annotations
   (`int | None`, `def f() -> bool | None:` etc.) as `SKIPPED`.
   Under `from __future__ import annotations` the union is stored
   as a string and never evaluated, so `int | None` → `int + None`
   produces equivalent code; counting these as survivors drops
   the effective score from ~76% to a misleading ~52% and masks
   real test gaps. See *Annotation filter* below for the
   correctness argument.
3. `cosmic-ray exec cosmic-ray.toml mutation.sqlite` — drains the
   queue, runs the test command for each mutant, and records the
   verdict.
4. `cr-report mutation.sqlite` — prints the killed / survived /
   timed-out tally.

Render the HTML survivor browser:

```sh
make mutation-html
xdg-open html/mutation-report.html
```

Resuming a partial run is automatic: re-invoking `cosmic-ray exec`
on the same session file picks up where the queue stood. To force a
fresh sweep, `rm mutation.sqlite`.

> **Caveat.** `make mutation` calls `cosmic-ray init` first, which
> overwrites the queue. To *resume* a prior partial run, invoke
> `uv run cosmic-ray exec cosmic-ray.toml mutation.sqlite` directly,
> or use the parallel runner below.

---

## Parallel sweep

The default `local` distributor runs mutants one at a time on a
single CPU. A full sweep at ~7-10 s per mutant × ~thousands of
mutants is multi-hour. cosmic-ray supports an `http` distributor
where the coordinator forwards mutate-and-test requests to worker
HTTP processes, each running in its own directory; this lets us
spread the work across N CPUs.

The wrinkle is that each worker mutates source files **on disk**
in its working directory
(`cosmic_ray/mutating.py::apply_mutation`). Running N workers in
the project root would race on the same files. The
`mutation_parallel` nox session solves this by materialising N
isolated copies of the source tree under `mktemp`, sharing one
`.venv` via symlink, and pointing the coordinator at the resulting
worker URLs.

```sh
make mutation-parallel              # N=4 workers (default)
make mutation-parallel N=8          # N=8 workers
uv run nox -s mutation_parallel -- 2          # direct invocation
CR_BASE_PORT=10000 uv run nox -s mutation_parallel -- 4
```

The session:

- requires an existing `mutation.sqlite` (run
  `uv run cosmic-ray init cosmic-ray.toml mutation.sqlite` first,
  or kill `make mutation` after its `init` phase finishes);
- resumes the queue — it never overwrites results;
- runs the configured `test-command` once in worker-1's tree as a
  baseline gate before spawning workers; a failure here aborts
  cleanly instead of producing thousands of fake `KILLED` verdicts
  (the failure mode if PATH lacks the project venv and `python` in
  the test-command resolves to system Python without Django);
- cleans up the temp tree and kills every worker's process group
  on exit (including SIGINT / SIGTERM);
- shares `.venv` via symlink — disk overhead is ~5 MB per worker.

Pick N based on memory and IO bandwidth, not CPU count: each
worker boots a full Django test process per mutant. On a 16-core
/ 32 GB laptop, N=4-6 is typically the sweet spot before disk and
GIL contention eat the gain.

> **Do not** run `make mutation-parallel` concurrently with
> `make mutation` or another parallel invocation against the same
> `mutation.sqlite`. The coordinator is the single writer; two
> coordinators on one session file is undefined behaviour.

---

## Narrowing the scope

cosmic-ray's CLI accepts one `module-path` per config file. The
fastest way to scope a run to a single file is to edit
`cosmic-ray.toml::module-path` directly:

```toml
[cosmic-ray]
module-path = "allianceauth_oidc/security.py"
```

Revert the edit before committing. For repeated narrow sweeps,
maintain a per-scope variant of the config (e.g.
`cosmic-ray-security.toml`) and invoke it explicitly:

```sh
uv run cosmic-ray init cosmic-ray-security.toml mutation.sqlite
uv run cosmic-ray exec cosmic-ray-security.toml mutation.sqlite
uv run cr-report mutation.sqlite
```

The default `cosmic-ray.toml` excludes `migrations/`, `admin.py`,
`apps.py`, `__init__.py`, and `urls.py` from the global sweep —
see the inline comments in `cosmic-ray.toml` for the rationale.

---

## Reading the report

`cr-report mutation.sqlite` prints a line per mutant with its
verdict:

- **killed** — at least one test failed when the mutation was
  active. This is the goal: the test suite caught the change.
- **survived** — every test passed despite the mutation. This is a
  hole in the suite.
- **incompetent** — the mutation produced syntactically or
  semantically invalid code (e.g. a name error). Not a test
  problem; cosmic-ray skips it.
- **timeout** — the test command exceeded
  `cosmic-ray.toml::timeout`. Usually means the mutation
  introduced an infinite loop (e.g. removing a sentinel guard in a
  retry helper). Treated as killed.

Each survivor is one of three categories to triage:

1. **Real test gap.** A behaviour the tests don't actually pin.
   Example pattern from this codebase: a test that asserts
   `redact_secret(secret) == "<redacted>"` while importing the
   same `<redacted>` literal as a constant from `utils.py` —
   both sides resolve to the same name in source, so blanking
   the constant would pass the test. **Action: write or
   strengthen a test.**

2. **Equivalent mutant.** The mutation changes the source but
   not the observable behaviour, so no test ever could kill it.
   Example: replacing `if x is None: return` with
   `if x is None: pass` inside a one-statement body. **Action:
   mark the line with a `# pragma: no mutate` comment** so
   cosmic-ray's `cr-filter-pragma` excludes it on subsequent
   runs.

3. **Edge case the project consciously declines to test.**
   Example: a logging-only branch whose only effect is a
   `logger.warning(...)` call we don't assert on. **Action:
   leave it, but consider whether the branch should have an
   observable effect that is testable.**

A score of 80-90% killed mutants is normal for well-tested
Python code. Below 70% is a real signal. Above 95% is suspicious
— it often means the tests are characterising the implementation
rather than specifying the contract.

---

## Adding a new module to the scope

Edit `cosmic-ray.toml::module-path` to widen the root, or trim
`excluded-modules` if the file is currently denylisted. Avoid:

- `migrations/` — generated, no logic.
- `admin.py` — Django ModelAdmin shell; most mutations are
  equivalent because the framework hides the difference.
- `apps.py` / `__init__.py` — module-loader scaffolding.
- `urls.py` — URL routing table; few testable mutations.
- `tests/` — never mutate the tests themselves.

---

## Annotation filter

Cosmic-ray's AST-based mutators treat PEP 604 type unions
(`int | None`, `def f(x: User | None) -> bool | None:`) as ordinary
`BinOp(BitOr())` nodes and emit one mutation per variant
(`BitOr→Add`, `BitOr→Sub`, …) — eleven mutants per `|`. Under
`from __future__ import annotations` (in use across every module),
annotations are stored as strings at runtime and never evaluated;
the mutation has no observable effect and the mutant always
survives. With ~50 annotated signatures in the package, this
single class of mutants accounts for roughly 65% of the survivor
population and shifts the reported mutation score from a truthful
~76% to a misleading ~52%.

`_nox/cr_filter_annotations.py` is invoked between `cosmic-ray
init` and `cosmic-ray exec`. It parses each mutated module's AST,
collects the `(lineno, column)` of every `BinOp` lying inside an
annotation context (`FunctionDef.returns`, arg annotations,
`AnnAssign.annotation`, including nested forms like
`list[int | None]`), and marks matching pending mutants as
`WorkerOutcome.SKIPPED`. They are listed under `skipped` in
`cr-report` and excluded from the kill/survive ratio.

Correctness boundaries the filter respects:

- **Expression-level `|` is *not* filtered.** Real bitwise OR like
  `os.O_WRONLY | os.O_CREAT | os.O_EXCL` in `oidc_jwks_rotate` is
  outside any annotation context. Its `BitOr→Add`, `BitOr→Mod`,
  etc. mutants remain in the queue and must still be killed by
  tests. Equivalent mutants on POSIX-flag composition
  (`O_WRONLY + O_CREAT == O_WRONLY | O_CREAT` because the flags
  are bit-disjoint) are reported as plain survivors; that is the
  signal that the test should assert flag *behaviour* (e.g.
  attempting to overwrite an existing file fails because `O_EXCL`
  is set) rather than the mask value.
- **Operator-centric coordinates.** Cosmic-ray records mutation
  positions at the column of the operator token (`|`), not the
  start of the BinOp expression. The filter recovers the operator
  column by locating `|` in the source between
  `left.end_col_offset` and `right.col_offset`, which is robust to
  any surrounding whitespace.
- **No-op on a completed session.** `pending_work_items` is empty
  after `exec`, so re-running the filter never alters recorded
  verdicts.

If `from __future__ import annotations` is ever removed from a
module, the assumption breaks: PEP 604 unions on assignments
(`x: int | None = None` at module scope, function default values
with annotated parameters) get evaluated at import / call time,
and a mutated `int + None` raises `TypeError` — which an import
test *would* kill. Drop the future-import only when you have
confirmed that test coverage exercises the import path.

The filter has unit-test coverage in
`tests/test_cr_filter_annotations.py`. The critical regression to
guard against is a column-off-by-N — symptom: filter reports
"Skipped 0 / N" on a fresh session, leaving the queue full of
noise.

---

## Background: why we have this

Coverage tells you *which lines were executed*. Mutation testing
tells you *which lines, when changed, would surface in a failing
test*. The two are complementary:

- 100% line coverage + 0% mutation kill rate = tests call the code
  but assert nothing meaningful (the classic "tautological
  assertion" smell — both sides of `assertEqual` resolve to the
  same symbol).
- 100% mutation kill rate (impossible in practice) would mean
  every semantic change is observable as a test failure.

The realistic target is "no surviving mutants in the
security-critical paths" — `security.py`, `auth_provider.py`'s
`validate_*` methods, `tokens.py`'s JWT builder, and the BCL
fan-out in `logout.py` / `tasks.py`. A surviving mutant in those
files is a real signal that an attacker-relevant code path is
under-tested.
