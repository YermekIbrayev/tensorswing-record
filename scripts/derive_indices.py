"""Beacon-driven random audit index derivation (protocol v1.0.1 §9.3).

STDLIB-ONLY. IMPORT-FREE OF THE `tensorswing_ml` PACKAGE (and of every
other project package): only `hashlib`, `hmac`, and `math` may be
imported here.

This exact file is copied VERBATIM into the public `tensorswing-record`
repo as `scripts/derive_indices.py`. Its SHA-256 is pinned in every
weekly manifest's `derive_script_sha256` field (protocol §6.2/§9.3), so
every byte of this file is consensus-relevant: anyone auditing a sealed
week recomputes the same file's SHA-256 and re-derives the same audit
indices from the public beacon value, and both MUST match the pinned
hash and the manifest's published indices exactly. A test
(`test_proofs_derive_indices.py`) reads this module's AST and asserts
its imports are a subset of `{hashlib, hmac, math}`, pinning this
constraint in CI -- importing anything from `tensorswing_ml` (or any
other in-repo package) here would make the file uncopyable into the
public repo without modification, silently breaking that pin.

Do not import this module's functions expecting object identity or
project types: `derive_indices` takes and returns plain `str`/`int`
values only, precisely so this file has zero coupling to the rest of
the codebase.
"""

import hashlib
import hmac
import math


def audit_k(leaf_count: int, fraction: float = 0.05, minimum: int = 20) -> int:
    """protocol §9.3: K = max(minimum, ceil(fraction * leaf_count)).

    If that K would be >= leaf_count, K = leaf_count instead (full
    reveal -- every leaf is audited when the leaf count is small enough
    that `minimum` alone already covers it).
    """
    k = max(minimum, math.ceil(fraction * leaf_count))
    return min(k, leaf_count)


def derive_indices(beacon_signature_hex: str, week: str, leaf_count: int, k: int) -> list[int]:
    """protocol §9.3, implemented verbatim.

    For counter = 0, 1, 2, ...:

        v = HMAC-SHA256(key = beacon signature bytes,
                         msg = UTF-8(f"{week}|{counter}"))

    `v` is interpreted as a 256-bit big-endian integer. Rejection-sample:
    accept iff `v < floor(2**256 / leaf_count) * leaf_count` (a rejected
    counter is consumed and skipped, eliminating modulo bias); on
    accept, `index = v mod leaf_count`; an index already drawn consumes
    its counter and is discarded (skip duplicates); stop once `k`
    distinct indices are drawn.

    Returns the drawn indices in DERIVATION (acceptance) order -- NOT
    sorted. protocol §9.3: "The drawn indices, in acceptance order, are
    the sampled set." §9.6 confirms the per-week audit record's
    `indices` field (this function's direct output) is "the K sampled
    indices in acceptance order", distinct from that same record's
    `audit_set` field, which IS sorted ascending -- callers that need a
    sorted, deduplicated audit set (protocol §9.4) build it themselves
    (see `tensorswing_ml.proofs.audit.select_audit_indices`); this
    function never re-sorts its own output.
    """
    if leaf_count < 1:
        raise ValueError("leaf_count must be >= 1")
    if k < 0 or k > leaf_count:
        raise ValueError("k must be between 0 and leaf_count, inclusive")

    signature = bytes.fromhex(beacon_signature_hex)
    bound = (2**256 // leaf_count) * leaf_count

    indices: list[int] = []
    seen: set[int] = set()
    counter = 0
    while len(indices) < k:
        message = f"{week}|{counter}".encode()  # UTF-8, per protocol §9.3
        digest = hmac.new(signature, message, hashlib.sha256).digest()
        v = int.from_bytes(digest, "big")
        counter += 1
        if v >= bound:
            continue
        index = v % leaf_count
        if index in seen:
            continue
        seen.add(index)
        indices.append(index)
    return indices
