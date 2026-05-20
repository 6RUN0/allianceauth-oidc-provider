"""
SSRF DNS safety helpers shared between admin-form and worker paths.

The helpers were previously tucked into :mod:`allianceauth_oidc.models`
as ``_``-prefixed names; they are public by use (the Celery worker
re-imports them through ``# pyright: ignore`` annotations), so this
module lifts them into a clearly-named home and drops the leading
underscores. Behaviour is unchanged: ``models.py`` and ``tasks.py``
both delegate here.

The two callsites — :meth:`AllianceAuthApplication._validate_uri_target_safety`
(admin save) and :func:`tasks._request_time_ssrf_gate_passes` (worker
dispatch) — run on different ``getaddrinfo`` calls, so the live
answer may have rotated between the two. Both must run for the DNS
rebinding TOCTOU defence to be complete; see ``CLAUDE.md`` "Three-
layer policy enforcement" for the architectural rationale.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket

# Per plan v5 §4.5: ``socket.setdefaulttimeout`` does NOT bound
# ``getaddrinfo`` (a libc resolver call, not a Python socket
# operation). A per-call ``ThreadPoolExecutor`` is the only correct
# way to enforce a wall-clock timeout on the resolver.
DNS_BOUND_SECONDS = 3


# RFC 6598 carrier-grade NAT space - not flagged by
# ``ipaddress.IPv4Address.is_private`` (which only covers RFC 1918)
# nor by ``is_reserved`` (which doesn't include 100.64.0.0/10 on the
# 3.10-3.13 standard library). Deployments behind CGNAT - k8s overlay
# networks using the range, some ISP-managed appliances - would
# otherwise be reachable by an attacker-controlled RP whose hostname
# resolves into the range, leaking a signed ``logout_token`` JWT
# (``iss``/``aud``/``sub``/``jti``) into internal infrastructure.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def resolve_host_bounded(
    host: str, deadline_seconds: int = DNS_BOUND_SECONDS
) -> list[tuple]:
    """
    Resolve ``host`` with a real wall-clock bound.

    Returns the raw ``socket.getaddrinfo`` result list. Callers must
    extract address strings via ``addr[4][0]``.

    ``max_workers=1`` because exactly one resolver thread is needed
    per call; the executor is GC'd at context-manager exit. Trades
    one thread-creation per admin form save for module-level pool
    lifecycle management — negligible vs the DNS round-trip itself.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(
            socket.getaddrinfo,
            host,
            None,
            type=socket.SOCK_STREAM,
        )
        return fut.result(timeout=deadline_seconds)


def is_unsafe_address(addr_str: str) -> bool:
    """
    Return True when ``addr_str`` resolves to an IP unsafe for outbound
    HTTP from the worker.

    Unsafe = the original five rejected predicates
    (``is_private | is_loopback | is_link_local | is_multicast |
    is_reserved``) plus ``is_unspecified`` (catches ``0.0.0.0`` and
    ``::`` — both treated by the kernel as "this host"; ``0.0.0.0``
    fell through every one of the five original predicates).

    IPv4-encoded-in-IPv6 wrappers are unmapped before predicate
    evaluation:

    * ``::ffff:X.Y.Z.W`` — IPv4-mapped IPv6 (RFC 4291 §2.5.5.2). Some
      kernels return this form when an IPv4 host is reachable through
      a dual-stack resolver; without unmap, ``IPv4Address``-only
      predicates (``is_private`` on RFC 1918) miss the address.
    * ``2002:XXYY:ZZWW::`` — 6to4 (RFC 3056). Wraps an IPv4 address
      in the upper 32 bits of a /16 prefix. ``2002:7f00:0001::``
      wraps ``127.0.0.1`` — the IPv6 form is not loopback on its
      own but the embedded IPv4 is.

    Unparseable addresses return True (fail-closed). The
    :func:`addresses_have_unsafe` aggregator uses ``any`` semantics, so
    a resolver returning only garbage tuples would otherwise leave the
    gate at False and allow ``requests.post`` to fall through to its
    own (libc) resolver — a TOCTOU window between two resolvers that
    may disagree. Garbage in, deny out (N-5).
    """
    try:
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address = (
            ipaddress.ip_address(addr_str)
        )
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        elif addr.sixtofour is not None:
            addr = addr.sixtofour
    return (
        addr.is_unspecified
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or (isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NETWORK)
    )


def addresses_have_unsafe(infos: list[tuple]) -> bool:
    """
    Return True if any address in a ``getaddrinfo`` result tuple list
    is unsafe per :func:`is_unsafe_address`.

    Shared by :meth:`AllianceAuthApplication._validate_uri_target_safety`
    (admin-form gate) and ``tasks.send_logout_token`` (request-time
    re-validation defending against DNS rebinding TOCTOU between
    admin save and worker dispatch).
    """
    return any(is_unsafe_address(info[4][0]) for info in infos)
