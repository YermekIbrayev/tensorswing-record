"""Synthetic golden-week fixture generator for the verify.py test suite.

This module is an INDEPENDENT §-by-§ implementation of the protocol's
producer side (canonical serialization §3, HKDF salts §4.2, commitments
§4.3, Merkle tree and inclusion proofs §5, manifest §6, labels §8, audit
§9): the fixtures it emits were derived from the protocol text, not from
the sealed pipeline, so verify.py passing them is two independent
implementations agreeing. Its HKDF and Merkle outputs are pinned against
`protocol/test-vectors/v1/` by the test suite.

The one shared artifact is scripts/derive_indices.py (§9.3), which is BY
DESIGN the same file the pipeline runs; the generator executes it to
compute the sampled indices, exactly as a verifier does.

Fixture weeks are synthetic (tiny N = 6 leaves, fixed seed). The golden
week is 2026-W20 — its deadlines are all in the past, so every artifact
must exist and PASS. The bootstrap fixture uses the current and next ISO
weeks so that its PENDING semantics stay young no matter when the tests
run.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ET = ZoneInfo("America/New_York")
REPO_ROOT = Path(__file__).resolve().parent.parent

QUICKNET_CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
QUICKNET_GENESIS = 1692803367
PRICE_SOURCE = (
    "Yahoo Finance daily closes, auto-adjusted, via the sealed pipeline's pinned fetcher"
)
ARCHIVE_POLICY = "tlock+manual; missed-manual-when-tlock-dead = incident"

WEEK = "2026-W20"
WEEK_SEED = bytes(range(32))
BEACON_SIG_HEX = "ab" * 48  # synthetic 48-byte "signature"

# ------------------------------------------------------------ §3 canonical


def canonical(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------- §4.2 HKDF


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 with empty salt (== 32 zero bytes under HMAC padding)."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def leaf_salt(week_seed: bytes, leaf_id: str) -> bytes:
    return hkdf_sha256(week_seed, leaf_id.encode())


# --------------------------------------------------------------- §5 merkle


def _leaf_node(c: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + c).digest()


def _interior(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()


def build_levels(commitments: list[bytes]) -> list[list[bytes]]:
    levels = [[_leaf_node(c) for c in commitments]]
    while len(levels[-1]) > 1:
        cur, nxt = levels[-1], []
        for i in range(0, len(cur) - 1, 2):
            nxt.append(_interior(cur[i], cur[i + 1]))
        if len(cur) % 2:
            nxt.append(cur[-1])
        levels.append(nxt)
    return levels


def proof_for(levels: list[list[bytes]], index: int) -> list[list[str]]:
    proof, pos = [], index
    for level in levels[:-1]:
        if pos % 2 == 1:
            proof.append(["L", level[pos - 1].hex()])
        elif pos + 1 < len(level):
            proof.append(["R", level[pos + 1].hex()])
        pos //= 2
    return proof


# ----------------------------------------------------- §9.2 beacon timing


def week_monday(week: str) -> datetime:
    return datetime.strptime(week + "-1", "%G-W%V-%u")


def beacon_target(week: str) -> datetime:
    d = week_monday(week) + timedelta(days=5)  # ISO day 6 = Saturday
    return datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=ET)


def drand_round_for(instant: datetime) -> int:
    return (int(instant.timestamp()) - QUICKNET_GENESIS) // 3 + 1


# ------------------------------------------------- minimal OpenTimestamps


OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BTC_TAG = bytes.fromhex("0588960d73d71901")
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")


def _varuint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _varbytes(b: bytes) -> bytes:
    return _varuint(len(b)) + b


def minimal_ots(digest: bytes, *, height: int | None = None,
                pending_uri: str | None = None) -> bytes:
    """A structurally valid detached .ots: sha256 file-hash op, no tree ops,
    one attestation (Bitcoin height, or a pending calendar URI)."""
    if height is not None:
        att = BTC_TAG + _varbytes(_varuint(height))
    else:
        att = PENDING_TAG + _varbytes(_varbytes(pending_uri.encode()))
    return OTS_MAGIC + _varuint(1) + b"\x08" + digest + b"\x00" + att


# ---------------------------------------------------------- the fixture


def _load_derive(script: Path):
    spec = importlib.util.spec_from_file_location("derive_indices_fixture", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _grade(direction: str, predicted: float, reference: float,
           final_close: float) -> dict:
    actual = round((final_close / reference - 1) * 100, 2)  # §8.3, verbatim
    if actual == 0.0:
        outcome = "scratch"
    elif (direction == "LONG") == (actual > 0):
        outcome = "win"
    else:
        outcome = "loss"
    return {
        "outcome": outcome, "actual": actual, "reference": reference,
        "final_close": final_close, "error": round(predicted - actual, 1),
    }


LEAF_SPECS = {
    # leaf_id -> (direction, predicted, reference, final_close, extra_fields)
    "alpha/AAA": ("LONG", 2.5, 100.0, 103.07, {}),
    "alpha/BBB": ("LONG", 1.0, 50.0, 49.0, {}),
    "alpha/CCC": None,  # abstain
    "beta/AAA": ("SHORT", -1.5, 200.0, 200.0, {}),  # scratch
    "beta/BBB": ("SHORT", -3.0, 80.0, 76.0, {"horizon_days": 5}),  # §8.4 MAY
    "beta/CCC": ("LONG", 0.5, 120.0, 121.23, {}),
}


def build_week(dst: Path, week: str, *, sequence: int, prev_manifest_sha256: str,
               sealed_at: datetime, prev_incident_sha256: str,
               record_status: str = "intact", young: bool = False) -> dict:
    """Write one full week into the fixture repo; returns the manifest doc."""
    leaf_ids = sorted(LEAF_SPECS, key=str.encode)
    leaves: dict[str, bytes] = {}
    for lid in leaf_ids:
        slug, _, ticker = lid.partition("/")
        spec = LEAF_SPECS[lid]
        if spec is None:
            doc = {"kind": "abstain", "model": slug, "ticker": ticker, "week": week}
        else:
            direction, predicted, reference, _, extra = spec
            doc = {"week": week, "model": slug, "ticker": ticker,
                   "direction": direction, "predicted": predicted,
                   "reference": reference, **extra}
        leaves[lid] = canonical(doc)

    salts = {lid: leaf_salt(WEEK_SEED, lid) for lid in leaf_ids}
    commitments = [
        hashlib.sha256(leaves[lid] + salts[lid]).digest() for lid in leaf_ids
    ]
    for lid, c in zip(leaf_ids, commitments):
        slug, _, ticker = lid.partition("/")
        _write(dst / "hashes" / slug / week / f"{ticker}.sha256",
               c.hex().encode() + b"\n")
    levels = build_levels(commitments)
    root_hex = levels[-1][0].hex()

    target = beacon_target(week)
    seed_tle = (
        b"-----BEGIN TLE-----\nsynthetic fixture, not a real tlock blob\n"
        b"-----END TLE-----\n"
    )
    _write(dst / "release" / f"{week}.seed.tle", seed_tle)

    protocol_file = dst / "protocol" / "v1.0.1.md"
    script = dst / "scripts" / "derive_indices.py"
    manifest = {
        "week": week,
        "sequence": sequence,
        "protocol_version": "1.0.1",
        "protocol_sha256": sha256_hex(protocol_file.read_bytes()),
        "prev_manifest_sha256": prev_manifest_sha256,
        "roster_sha256": sha256_hex((dst / "roster.json").read_bytes()),
        "universe_sha256": sha256_hex((dst / "universe.json").read_bytes()),
        "merkle_root": root_hex,
        "leaf_count": len(leaf_ids),
        "leaf_ids": leaf_ids,
        "week_seed_hash": sha256_hex(WEEK_SEED),
        "cycle_manifest": sha256_hex(b"synthetic cycle payload " + week.encode()),
        "grading_sha256": sha256_hex(b"synthetic grading source"),
        "derive_script_sha256": sha256_hex(script.read_bytes()),
        "drand": {
            "chain_hash": QUICKNET_CHAIN_HASH,
            "round": drand_round_for(target),
            "target_time_utc": target.astimezone(timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "price_source": PRICE_SOURCE,
        "repo_git_sha": None,
        "prev_incident_sha256": prev_incident_sha256,
        "sealed_at": sealed_at.isoformat(),
        "record_status": record_status,
        "archive_sha256": sha256_hex(b"synthetic ciphertext " + week.encode()),
        "archive_size": 21 + len(week),
        "archive_cipher": "aes-256-gcm",
        "archive_release": {
            "embargo_weeks": 104,
            "tlock_chain": QUICKNET_CHAIN_HASH,
            "tlock_round": drand_round_for(
                sealed_at + timedelta(seconds=104 * 604800)),
            "policy": ARCHIVE_POLICY,
        },
        "seed_tle_sha256": sha256_hex(seed_tle),
    }
    mbytes = canonical(manifest)
    _write(dst / "manifests" / f"{week}.manifest.json", mbytes)
    _write(dst / f"{week}.manifest.ots",
           minimal_ots(hashlib.sha256(mbytes).digest(),
                       **({"pending_uri": "https://alice.btc.calendar."
                                          "opentimestamps.org"} if young
                          else {"height": 900123})))
    for tsa in ("sectigo", "digicert"):
        _write(dst / "stamps" / week / f"manifest.{tsa}.tsq",
               b"synthetic tsq (no tsa/ chains in fixtures -> SKIPPED)\n")
        _write(dst / "stamps" / week / f"manifest.{tsa}.tsr",
               b"synthetic tsr (no tsa/ chains in fixtures -> SKIPPED)\n")
    if young:
        return manifest

    # ------ Friday artifacts: labels + label stamps
    entries = []
    for i, lid in enumerate(leaf_ids):
        slug, _, ticker = lid.partition("/")
        spec = LEAF_SPECS[lid]
        if spec is None:
            e = {"outcome": "abstain", "actual": None, "reference": None,
                 "final_close": None, "error": None}
        else:
            direction, predicted, reference, final_close, _ = spec
            e = _grade(direction, predicted, reference, final_close)
        entries.append({"index": i, "model": slug, "ticker": ticker, **e})
    labels = {"week": week, "entries": entries}
    _write(dst / "labels" / f"{week}.json", canonical(labels))
    for tsa in ("sectigo", "digicert"):
        _write(dst / "stamps" / week / f"labels.{tsa}.tsq",
               b"synthetic tsq (no tsa/ chains in fixtures -> SKIPPED)\n")
        _write(dst / "stamps" / week / f"labels.{tsa}.tsr",
               b"synthetic tsr (no tsa/ chains in fixtures -> SKIPPED)\n")

    # ------ Saturday artifacts: audit record + reveals (§9)
    d = _load_derive(script)
    k = d.audit_k(len(leaf_ids))
    indices = d.derive_indices(BEACON_SIG_HEX, week, len(leaf_ids), k)
    special = [e["index"] for e in entries if e["outcome"] in ("scratch", "abstain")]
    audit_set = sorted(set(indices) | set(special))
    beacon = {
        "week": week, "source": "drand", "round": drand_round_for(target),
        "signature_hex": BEACON_SIG_HEX, "block_height": None,
        "block_hash": None, "k": k, "indices": indices, "audit_set": audit_set,
    }
    _write(dst / "audits" / week / "beacon.json", canonical(beacon))
    sampled = set(indices)
    for i in audit_set:
        lid = leaf_ids[i]
        slug, _, ticker = lid.partition("/")
        if i in sampled:
            kind = "sampled"
        else:
            kind = entries[i]["outcome"]  # scratch or abstain
        reveal = {
            "week": week, "index": i, "model": slug, "ticker": ticker,
            "kind": kind,
            "payload_b64": __import__("base64").b64encode(leaves[lid]).decode(),
            "salt_hex": salts[lid].hex(),
            "proof": proof_for(levels, i),
            "merkle_root": root_hex,
        }
        _write(dst / "audits" / week / slug / f"{ticker}.json", canonical(reveal))
    return manifest


def _write_incident(dst: Path, number: int, kind: str, week, detail: str,
                    prev_sha: str, recorded_at: str) -> str:
    doc = {"number": number, "kind": kind, "week": week, "detail": detail,
           "prev_incident_sha256": prev_sha, "recorded_at": recorded_at}
    raw = canonical(doc)
    _write(dst / "incidents" / f"{number:03d}.json", raw)
    return sha256_hex(raw)


def _base_repo(dst: Path):
    """Protocol files, roster/universe, derive script, incident genesis."""
    for p in (REPO_ROOT / "protocol").glob("v*.md"):
        _write(dst / "protocol" / p.name, p.read_bytes())
    _write(dst / "PROTOCOL.md", (REPO_ROOT / "PROTOCOL.md").read_bytes())
    shutil.copytree(REPO_ROOT / "protocol" / "test-vectors",
                    dst / "protocol" / "test-vectors", dirs_exist_ok=True)
    _write(dst / "scripts" / "derive_indices.py",
           (REPO_ROOT / "scripts" / "derive_indices.py").read_bytes())
    _write(dst / "roster.json", canonical({"models": ["alpha", "beta"]}) + b"\n")
    _write(dst / "universe.json",
           canonical({"tickers": ["AAA", "BBB", "CCC"]}) + b"\n")
    return _write_incident(
        dst, 0, "genesis", None, "synthetic fixture genesis", "0" * 64,
        "2026-01-04T12:00:00-05:00",
    )


def build_golden(dst: Path) -> Path:
    """The golden week: 2026-W20, all deadlines past, everything present."""
    g = _base_repo(dst)
    h001 = _write_incident(
        dst, 1, "other", None,
        "synthetic: a single quiet incident; no second within 52 weeks, "
        "so the record stays intact",
        g, "2026-02-01T09:00:00-05:00",
    )
    sealed = datetime(2026, 5, 10, 18, 0, 0, tzinfo=ET)  # Sunday before W20 Monday
    build_week(dst, WEEK, sequence=1, prev_manifest_sha256="0" * 64,
               sealed_at=sealed, prev_incident_sha256=h001)
    return dst


def build_bootstrap(dst: Path, now: datetime | None = None) -> tuple[str, str]:
    """Bootstrap fixture: reduced-schema manifest for the CURRENT ISO week
    (chain head, §13.3) + a full manifest for the NEXT ISO week, which is
    younger than all its Friday/Saturday deadlines -> PENDING everywhere."""
    g = _base_repo(dst)
    now = now or datetime.now(timezone.utc)
    iso = now.isocalendar()
    boot_week = f"{iso.year}-W{iso.week:02d}"
    d = week_monday(boot_week) + timedelta(days=7)
    iso2 = d.isocalendar()
    young_week = f"{iso2.year}-W{iso2.week:02d}"

    boot = {
        "week": boot_week,
        "cycle_sha256": sha256_hex(b"synthetic bootstrap cycle"),
        "note": "synthetic bootstrap fixture (schema of §13.3)",
        "stamped_at": now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    }
    braw = canonical(boot)
    _write(dst / "manifests" / f"{boot_week}.manifest.json", braw)
    _write(dst / f"{boot_week}.manifest.ots",
           minimal_ots(hashlib.sha256(braw).digest(),
                       pending_uri="https://alice.btc.calendar.opentimestamps.org"))
    build_week(dst, young_week, sequence=2,
               prev_manifest_sha256=sha256_hex(braw),
               sealed_at=now, prev_incident_sha256=g, young=True)
    return boot_week, young_week


# ------------------------------------------------------------- mutations


def rewrite_manifest(dst: Path, week: str, mutate):
    path = dst / "manifests" / f"{week}.manifest.json"
    doc = json.loads(path.read_bytes())
    mutate(doc)
    raw = canonical(doc)
    path.write_bytes(raw)
    # keep the OTS stamp consistent so the mutation trips exactly one check
    _write(dst / f"{week}.manifest.ots",
           minimal_ots(hashlib.sha256(raw).digest(), height=900123))


def rewrite_json(path: Path, mutate):
    doc = json.loads(path.read_bytes())
    mutate(doc)
    path.write_bytes(canonical(doc))
