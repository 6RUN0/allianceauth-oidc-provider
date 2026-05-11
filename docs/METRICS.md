# Prometheus metrics

This document records the conventions every AA module in this
ecosystem follows when it adds Prometheus instrumentation. It is
both the contract for this module (`allianceauth-oidc-provider`)
and the template for sibling modules — a single set of names,
labels, and bucket layouts means one Grafana dashboard works
across all of them.

## Integration model

Modules **cooperate with** `django-prometheus`; they do not
**depend on** it. Concretely:

* `django-prometheus` lives in `[project.optional-dependencies]`
  under the `metrics` extra. Operators opt in via
  `pip install <module>[metrics]`, or pick it up transitively
  when another AA module's `metrics` extra is already installed.
* The module's `_metrics.py` does `try: import django_prometheus`
  once at import time. On success, real `Counter` / `Histogram` /
  `Gauge` objects from `prometheus_client` register into the
  shared default `REGISTRY`. On failure, every metric resolves to
  a no-op stub that satisfies the same API surface (see
  [No-op stub contract](#no-op-stub-contract) below).
* The module never mounts a `/metrics` view of its own and
  never adds middleware. Exposing the registry is
  `django-prometheus`'s job — the operator controls when and
  where `/metrics` becomes reachable.

The receiver chain wires unconditionally: a no-op receiver runs
on every signal so the startup path is identical with or without
the extra installed. This keeps the integration testable without
conditional fixtures and avoids "metrics enabled in dev but not
in prod" config drift.

Because every AA module emits into the same default
`prometheus_client.REGISTRY`, modules MUST own a unique
`aa_<module>_*` namespace and MUST NOT define metrics that would
collide with another module's namespace. Two modules registering
the same metric name raise `ValueError: Duplicated timeseries in
CollectorRegistry` at Django app load, breaking *every* module's
startup — not just the second one to register.

## Metric naming

```
aa_<module>_<noun>[_unit][_total]
```

* `aa_` — fixed prefix. A Grafana panel filtering
  `{__name__=~"aa_.*"}` pulls metrics from every AA module that
  adopts this convention. `django_*` is reserved for
  `django-prometheus`' own series; never reuse that prefix.
* `<module>` — the AA module's short name. For this module it
  is `oidc`. Pick a single snake_case identifier matching the
  Python package short name; this is also the namespace lock
  that prevents the cross-module collision above.
* `<noun>` — the thing being counted or measured. Multi-token
  snake_case is fine and frequently necessary
  (`tokens_issued`, `bcl_delivery_seconds`,
  `authorize_denied`); avoid verbs and tenses
  (`issuing_tokens`, `delivering_bcl_seconds` are wrong).
* `<unit>` — required for any non-counter measuring a physical
  quantity: `seconds`, `bytes`. Counters measuring counts
  (events, occurrences) omit the unit segment.
* `_total` — appended by `prometheus_client` at sample emission
  for any `Counter`. **Constructor**: pass the name without
  `_total` (e.g. `Counter("aa_oidc_tokens_issued", ...)`); the
  library appends `_total` when emitting samples. **Tests and
  Grafana queries**: read the metric as
  `aa_oidc_tokens_issued_total`. Passing a name that already
  ends in `_total` is silently allowed today but is deprecated
  and may raise in a future `prometheus_client` release.

Examples:

| Name                              | Type      | Why this shape                  |
|-----------------------------------|-----------|---------------------------------|
| `aa_oidc_tokens_issued_total`     | Counter   | Cumulative integer, no unit.    |
| `aa_oidc_bcl_delivery_seconds`    | Histogram | Latency in seconds — units required. |
| `aa_oidc_bcl_dispatches_total`    | Counter   | Multi-token noun, no unit.      |

## Closed value-sets

Every label whose value space is a finite set MUST be declared
as a module-level `Final[frozenset[str]]` constant in
`constants.py`, then imported everywhere the value space is
referenced (emitter, receiver, tests, documentation). Inline
string literals scattered across modules are forbidden: every
example of three-place drift in this module's history started
that way.

For `allianceauth_oidc`, the canonical sets live in
[`allianceauth_oidc/constants.py`](../allianceauth_oidc/constants.py):

* `BCL_HISTOGRAM_OUTCOMES` — per-attempt outcomes for
  `aa_oidc_bcl_delivery_seconds`.
* `BCL_DISPATCH_OUTCOMES` — terminal outcomes for
  `aa_oidc_bcl_dispatches_total`.
* `BCL_DEAD_LETTER_OUTCOMES` — subset of the dispatch set
  classified as terminal failure for alerting.
* `AUTHORIZE_DENY_REASONS` — values for `aa_oidc_authorize_denied_total`.

When a new failure mode appears, add it to the canonical set
*first*, then update emitters and tests. The `Final` annotation
plus type checking flags any emitter that hard-codes a string
that has drifted out of the set.

## Label vocabulary

Stable label names across modules — pick from this table first
before inventing a new one.

| Label        | Values                                                                | Notes |
|--------------|-----------------------------------------------------------------------|-------|
| `client_id`  | An OAuth `client_id` string                                           | Per registered app. Cardinality = `#apps × #values_of_other_labels`. Large alliances run 30-60 RPs; budget headroom accordingly. Closed set (Application admins, not end users). |
| `grant_type` | `authorization_code` / `refresh_token` / `client_credentials` / `password` (DOT-supported subset; RFC 6749 also defines `implicit`, RFC 8628 adds `urn:ietf:params:oauth:grant-type:device_code`) | Mirror RFC 6749 names exactly. |
| `outcome`    | Module-specific, drawn from a `constants.py` `frozenset`              | Histograms use a per-attempt vocabulary; terminal counters use a richer set. Never invent values inline. |
| `reason`     | Module-specific, drawn from a `constants.py` `frozenset`              | Used on denial / outcome-classification counters. Values must come from a documented closed set; never user-controlled strings. |
| `kid`        | A JWK thumbprint                                                      | Active signing key identifier. Cardinality bounded by rotation policy (typically 1-3 active). |

### Forbidden labels

* **`user_id` / `user_pk` / `username` / `email` / `character_id`
  / `character_name` / `main_character_id` / `alt_character_id`** —
  cardinality unbounded over the AA install lifetime. Each new
  user, character, or alt inflates the series count and the
  in-memory metric storage. Use audit logs for per-identity
  investigation, never metrics.
* **`corporation_id` / `alliance_id` when used as a per-user
  proxy** — AA installs span entire alliances (tens of corps,
  hundreds of users); using these labels is fine *aggregated*
  (e.g. `aa_oidc_active_corps`) but lethal when used as a
  per-event proxy for "which user".
* **IP address, session id, JWT `jti`** — same reason. Useful
  in audit, fatal in metrics.
* **`url` / `path`** — when the value is request-derived,
  attackers can blow up cardinality by varying it. If you need
  per-endpoint metrics, label by view name (a closed set the
  application controls), not by URL.
* **AA `state` when free-form** — fine when the AA install runs
  the default closed `Member` / `Blue` / `Guest` set; once an
  operator adds a custom state, the source becomes
  admin-controlled but unbounded. Document explicitly when a
  metric is safe to label by `state`.

## Histogram buckets

The library default `prometheus_client.Histogram.DEFAULT_BUCKETS`
(`(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0,
2.5, 5.0, 7.5, 10.0)`) is tuned for in-process latencies and
over-represents the sub-50ms range. Cross-network OIDC
operations are typically slower; pick buckets that match the
operation's expected range.

* **HTTP outbound** (BCL delivery, ESI calls, RP webhooks):
  `(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0)` — covers
  warm (50ms) to timeout-ceiling (15s) with reasonable
  granularity at the typical RP response time (~250ms-1s).
* **Internal Django request paths**: leave to
  `django-prometheus` middleware (which has its own tuned
  buckets — they are not the `prometheus_client` defaults).
* **Long-running background tasks** (token cleanup, JWKS
  rotation): `(1, 5, 15, 60, 300, 1800)` — bucketed in seconds
  but expecting full-second to minute-scale values.

`+Inf` is appended automatically; never add it explicitly.

## Cardinality rule of thumb

A single metric stores one in-memory record per *unique label
combination*. Combinations are multiplicative.

* **Counters and Gauges**: `slots = product of cardinalities of
  each label`. Example: `client_id` (30 apps) × `outcome`
  (7 values) = 210 slots per metric.
* **Histograms**: each label combination produces `N+3`
  Prometheus time-series — one per bucket plus `_count`, `_sum`,
  and a `+Inf` bucket. A histogram with the 9 BCL buckets and
  30 × 4 label combos thus produces `30 × 4 × (9 + 3) = 1440`
  time-series, not 120. Histograms dominate cardinality budgets.

Hard limits to watch:

* Single metric exceeding ~10 000 time-series — operator gets
  warnings and slow scrapes; consider dropping a label.
* `client_id × user_id` — instant cardinality bomb; forbidden
  by the table above.

Aim for the entire module to keep its in-memory metric storage
below 10 000 unique series. Rule of thumb, not a hard limit —
specific deployments may go higher with the multiprocess
collector, but the operator pays in scrape time and RAM.

## Multi-process under gunicorn

Real AA deployments run several gunicorn workers, each its own
Python process with its own `prometheus_client.REGISTRY`.
A single Prometheus scrape lands on a random worker and sees
*only that worker's metrics*. The default behaviour is therefore
unstable: counters appear to decrease as scrapes rotate across
workers.

The canonical fix is `prometheus_client`'s native multiprocess
collector mode — `django-prometheus` provides the Django view
adapter but does not own the multiprocess machinery itself.
Operator setup:

1. Set the env var `prometheus_multiproc_dir` (`PROMETHEUS_MULTIPROC_DIR`
   also accepted; lower-case is the canonical form) to a writable
   directory, typically a `tmpfs` mount so files vanish on host
   reboot.
2. In the gunicorn config, hook `child_exit(server, worker)` to
   call `prometheus_client.multiprocess.mark_process_dead(worker.pid)`
   so per-process files are cleaned when a worker exits.
3. Mount `django_prometheus.exports.ExportToDjangoView` (or any
   custom view) backed by a `CollectorRegistry` constructed via
   `prometheus_client.multiprocess.MultiProcessCollector(registry)`.

Canonical references:

* [`prometheus_client` multiprocess documentation](https://prometheus.github.io/client_python/multiprocess/) — the authoritative spec.
* [`django-commons/django-prometheus`](https://github.com/django-commons/django-prometheus) — the maintained fork (the older `korfuri/django-prometheus` URL still resolves but the project moved).

This module emits ordinary metrics into the default registry;
multiprocess plumbing is an operator concern handled once per
AA deployment, not per module.

### Caveat — `Gauge.set_function` and multiprocess

`Gauge.set_function(...)` is **incompatible** with the
multiprocess collector: every worker computes its own value and
the collector cannot meaningfully aggregate them. If you need a
"current count" semantic, prefer one of:

* **Lifecycle counters** — increment on the event that
  introduces the thing being counted, increment a second counter
  on the event that removes it. Derive the difference via PromQL
  (`sum(rate(issued[5m])) - sum(rate(cleaned[5m]))`). Works in
  every mode; this is what `aa_oidc_tokens_cleaned_total` does.
* **Periodic-task gauge** — schedule a Celery task that
  `set(...)` the gauge with an explicit `multiprocess_mode` of
  `livesum` / `liveall` / `max`. More complex; only justified
  when the operator must see an exact instantaneous value.

The convention for `allianceauth_oidc` is "lifecycle counters
first, periodic-task gauges only on demand."

## Instrumentation pattern

Choose the call site based on how many emitters the underlying
event has:

* **Direct instrumentation** — call
  `metric.labels(...).observe(...)` / `.inc()` in the code path
  itself. Use this when the measurement is intrinsic to *exactly
  one* source — e.g. `bcl_delivery_seconds.observe(...)` is
  inline in `tasks.send_logout_token` because the
  `requests.post` round-trip has exactly one call site.
* **Signal-driven** — wire a receiver on the relevant
  `django.dispatch.Signal` in `connect_metrics_receivers()` and
  increment from inside the receiver. Use this when the event
  has, or might gain, ≥2 emitters — e.g.
  `bcl_dispatches_total` is signal-driven because both
  `tasks.send_logout_token` and
  `logout.dispatch_backchannel_logout` fire
  `oidc_logout_dispatched`, and a future custom dispatcher could
  fire the same signal.

The rule is "instrument signal-driven by default; switch to
direct only when the call site is provably unique." Signal
receivers can outlive their original call sites; direct
instrumentation locks the metric to the call site that wrote it.

## No-op stub contract

When `django_prometheus` is unavailable, `_metrics.py` exposes
`_NoOpMetric` objects in place of the real ones. Every AA module
following this convention MUST honour this contract on its
stub:

* `.labels(*args, **kwargs)` — returns `self` so chained calls
  work transparently.
* `.inc(amount: float = 1.0)` — returns `None`, side-effect-free.
* `.observe(amount: float)` — returns `None`, side-effect-free.
* `.set(value: float)` — returns `None`, side-effect-free.
* `.set_function(fn: Callable[[], float])` — returns `None`,
  side-effect-free. The function is never called.
* No other public methods. Modules that want richer semantics
  (e.g. `inc_exemplar`) MUST gate the call site behind an
  enabled check rather than relying on the stub to swallow the
  call.

This contract is enforceable by tests — see
[`tests/test_metrics.py`](../tests/test_metrics.py) for the
delta-pattern fixtures, and the planned smoke test that patches
`sys.modules` to exercise the stub path explicitly.

## Adding a new metric — checklist

Before adding a `Counter` / `Histogram` / `Gauge`:

* [ ] Name follows `aa_<module>_<noun>[_unit][_total]` with
      multi-token snake_case where needed?
* [ ] All labels are in the vocabulary table — or, if new, in a
      `Final[frozenset]` in `constants.py`?
* [ ] Every label is from a bounded source? (No user-controlled
      strings without a sanitiser; cross-checked against the
      forbidden-labels list.)
* [ ] If a histogram: are the buckets justified for the
      operation's expected range, and is the bucket count
      reflected in the cardinality budget?
* [ ] If a gauge with `set_function`: documented as
      multiprocess-incompatible, or replaced with a lifecycle
      counter?
* [ ] Direct-vs-signal instrumentation choice matches the rule
      above?
* [ ] Metric landed in the inventory table below with name,
      type, labels, file, and source?
* [ ] Test asserts the *increment delta* around the action
      under test (never the absolute value)?

## Extraction triggers — when to refactor the convention

This module is the first adopter. The convention plus the
`_metrics.py` stub harness live as ~80 lines of boilerplate per
module. That is acceptable for two adopters and a clear refactor
trigger for three:

* **Module #2 adopting the convention** — copy `_metrics.py`
  wholesale. Add a comment to both copies citing the other so
  drift is visible at PR review.
* **Module #3 adopting the convention** — extract
  `_NoOpMetric`, the `_counter` / `_histogram` factories, and
  the try-import gate into an `aa-metrics-base` package; each
  AA module then declares `aa-metrics-base` as a non-optional
  dependency (it is tiny and pure-Python) and imports the
  shared stub harness. The first two modules migrate as part of
  the extraction PR.
* **`setup_multiprocess()` helper** — when the operator-side
  multiprocess setup recipe survives ≥2 deployments unchanged,
  lift steps 1-3 above into a function exposed by
  `aa-metrics-base`. Until then, keep the recipe operator-side
  to avoid baking a fork of `django-prometheus`'s setup
  conventions.

The triggers are intentionally conservative: shared packages
versioning is more expensive than 50 lines of duplicated
boilerplate, and the abstraction shape is only obvious after
three real adopters.

## Current inventory — `allianceauth_oidc`

| Metric                                 | Type      | Labels                  | File                  | Source                                  |
|----------------------------------------|-----------|-------------------------|-----------------------|-----------------------------------------|
| `aa_oidc_tokens_issued_total`          | Counter   | `grant_type`, `client_id` | `_metrics.py`         | `oidc_token_issued` signal receiver.    |
| `aa_oidc_tokens_cleaned_total`         | Counter   | (none)                  | `tasks.py`            | `clear_expired_tokens` Celery task — increments by per-run cleanup delta. |
| `aa_oidc_authorize_denied_total`       | Counter   | `reason` (`global`/`app`) | `views.py`            | `AuthAuthorizationView.dispatch`.       |
| `aa_oidc_bcl_delivery_seconds`         | Histogram | `client_id`, `outcome`  | `tasks.py`            | `send_logout_token` — observed around `requests.post`. |
| `aa_oidc_bcl_dispatches_total`         | Counter   | `client_id`, `outcome`  | `_metrics.py`         | `oidc_logout_dispatched` signal receiver — fires on every terminal event. |

Anonymous authorize requests do not contribute to
`aa_oidc_authorize_denied_total` — they redirect to `LOGIN_URL`
rather than being denied. Operators tracking the login-required
case query `django_http_responses_total_by_status` (provided by
`django-prometheus` middleware) against the authorize view.

There is no `aa_oidc_active_tokens` Gauge. Active-token
approximation is the operator's responsibility via PromQL:

```promql
sum(increase(aa_oidc_tokens_issued_total[1h]))
  -
sum(increase(aa_oidc_tokens_cleaned_total[1h]))
```

Adjust the time range to the access-token TTL. The recipe stays
correct under multiprocess scraping because both counters are
multiprocess-safe; a `Gauge.set_function` over
`AccessToken.objects.filter(...).count()` would not.

Dead-letter alerting recipe — sum the dispatch counter over the
canonical failure subset (`BCL_DEAD_LETTER_OUTCOMES`):

```promql
sum(rate(
  aa_oidc_bcl_dispatches_total{
    outcome=~"retries_exhausted|signing_kid_retired|signing_kid_resolve_failed|broker_unavailable|redirect_blocked|rp_client_error"
  }[5m]
))
```
