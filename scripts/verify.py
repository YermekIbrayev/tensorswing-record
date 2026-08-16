#!/usr/bin/env python3
"""tensorswing-record verifier — an independent implementation of protocol §13.

Written from the protocol TEXT (protocol/v1.0.1.md) alone. The one shared
artifact with the sealed pipeline is scripts/derive_indices.py, whose
SHA-256 every weekly manifest pins (§9.3): this verifier runs that script,
it does not reimplement it.

Usage:
    python scripts/verify.py                 # verify every week in the repo
    python scripts/verify.py 2026-W35        # verify one week
    python scripts/verify.py --all           # also fetch + check the release archive
    python scripts/verify.py --verify-beacon # also cross-check drand mirrors
    python scripts/verify.py --offline       # never touch the network

Statuses:
    PASS      the check held.
    FAIL      a hash mismatch, broken proof, violated MUST, or an artifact
              still missing after its own deadline (§13.2). Exit code is
              non-zero iff at least one FAIL was reported.
    PENDING   the week is younger than that artifact's deadline (§13.2);
              absence is expected, not a failure.
    SKIPPED   this run cannot perform the check (missing tool, or the check
              needs the network and --offline was given); the exact command
              to run it yourself is printed.
    BOOTSTRAP week 2026-W34 (§13.3): reduced manifest, checked only for
              presence and its OpenTimestamps stamp.

WHAT THIS TOOL DOES NOT DO — read this before trusting a PASS:

  * drand BLS signature verification is NOT performed. Checking that the
    beacon signature is a valid BLS signature over the round requires
    pairing cryptography outside the Python standard library. With
    --verify-beacon this tool fetches the round from independent drand
    mirrors and byte-compares them, which defends against a fabricated
    signature unless every queried mirror colludes. For full assurance run
    a drand client (e.g. `drand-client --chain-hash <hash> --round <n>`).
  * OpenTimestamps Bitcoin verification is NOT performed here. If the
    `opentimestamps` package is importable the proof is parsed and its
    claimed Bitcoin block height reported; confirming the attestation
    against the Bitcoin chain needs `ots verify` with a Bitcoin node (or
    a public calendar): the exact command is printed.
  * Price plausibility (§13.1 step 7, SHOULD) is not automated: compare
    `reference`/`final_close` against an independent daily-close source
    yourself; the protocol's informative tolerance is 1%.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

# ---------------------------------------------------------------- constants

PROTOCOL_IMPLEMENTED = ("1.0.1", "1.0.2")  # §13 of these versions is what this file implements

QUICKNET_CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
QUICKNET_GENESIS = 1692803367  # unix seconds (§9.2)
QUICKNET_PERIOD = 3  # seconds (§9.2)
DRAND_MIRRORS = (  # v1 relay path: <mirror>/<chain-hash>/public/<round>
    "https://api.drand.sh",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
)

BOOTSTRAP_WEEK = "2026-W34"  # §13.3
BOOTSTRAP_FIELDS = {"week", "cycle_sha256", "note", "stamped_at"}

PRICE_SOURCE = (
    "Yahoo Finance daily closes, auto-adjusted, via the sealed pipeline's pinned fetcher"
)
ARCHIVE_CIPHER = "aes-256-gcm"
ARCHIVE_POLICY = "tlock+manual; missed-manual-when-tlock-dead = incident"
EMBARGO_WEEKS = 104
WEEK_SECONDS = 604800

ET = ZoneInfo("America/New_York")

MANIFEST_FIELDS = {
    "week", "sequence", "protocol_version", "protocol_sha256",
    "prev_manifest_sha256", "roster_sha256", "universe_sha256", "merkle_root",
    "leaf_count", "leaf_ids", "week_seed_hash", "cycle_manifest",
    "grading_sha256", "derive_script_sha256", "drand", "price_source",
    "repo_git_sha", "prev_incident_sha256", "sealed_at", "record_status",
    "archive_sha256", "archive_size", "archive_cipher", "archive_release",
    "seed_tle_sha256",
}
LABEL_ENTRY_FIELDS = {
    "index", "model", "ticker", "outcome", "actual", "reference",
    "final_close", "error",
}
OUTCOMES = {"win", "loss", "scratch", "abstain"}
REVEAL_FIELDS = {
    "week", "index", "model", "ticker", "kind", "payload_b64", "salt_hex",
    "proof", "merkle_root",
}
BEACON_FIELDS = {
    "week", "source", "round", "signature_hex", "block_height", "block_hash",
    "k", "indices", "audit_set",
}
INCIDENT_FIELDS = {
    "number", "kind", "week", "detail", "prev_incident_sha256", "recorded_at",
}
INCIDENT_KINDS = {
    "late-seal", "late-labels", "label-after-beacon", "missed-audit",
    "unopenable-leaf", "commitment-mismatch", "seed-loss", "missed-release",
    "history-rewrite", "grading-defect", "other",
}

HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
WEEK_RE = re.compile(r"^(\d{4})-W(\d{2})$")
LEAF_ID_RE = re.compile(r"^[a-z0-9-]+/[A-Z][A-Z0-9.\-]*$")

# ------------------------------------------------------------------ helpers


def canonical_bytes(obj) -> bytes:
    """§3 canonical serialization — exactly Python's json.dumps as pinned."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_hex64(v) -> bool:
    return isinstance(v, str) and bool(HEX64_RE.match(v))


def parse_week(week: str) -> tuple[int, int]:
    m = WEEK_RE.match(week)
    if not m:
        raise ValueError(f"not a week key: {week!r}")
    return int(m.group(1)), int(m.group(2))


def week_monday(week: str) -> datetime:
    y, w = parse_week(week)
    d = datetime.strptime(f"{y}-W{w:02d}-1", "%G-W%V-%u")
    return d


def next_week_key(week: str) -> str:
    d = week_monday(week) + timedelta(days=7)
    iso = d.isocalendar()
    return f"{iso.year}-W{iso.week:02d}"


def et_instant(week: str, iso_day: int, hh: int, mm: int, ss: int) -> datetime:
    """DST-aware America/New_York instant on ISO day `iso_day` of the week."""
    d = week_monday(week) + timedelta(days=iso_day - 1)
    return datetime(d.year, d.month, d.day, hh, mm, ss, tzinfo=ET)


def beacon_target(week: str) -> datetime:
    """§9.2: Saturday 00:00:00 America/New_York of the cycle week."""
    return et_instant(week, 6, 0, 0, 0)


def drand_round_for(instant: datetime) -> int:
    """§9.2: round = floor((unix(target) − genesis)/3) + 1."""
    unix = int(instant.timestamp())
    return (unix - QUICKNET_GENESIS) // QUICKNET_PERIOD + 1


def parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"timestamp without offset: {ts!r}")
    return dt


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------- merkle


def merkle_leaf(commitment: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + commitment).digest()


def merkle_interior(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(commitments: list[bytes]) -> bytes:
    """§5.1: pair left-to-right, odd node promoted unchanged."""
    level = [merkle_leaf(c) for c in commitments]
    if not level:
        raise ValueError("empty tree")
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(merkle_interior(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def expected_proof_dirs(index: int, leaf_count: int) -> list[str]:
    """The exact L/R direction sequence a §5.2 proof for (index, leaf_count)
    must have — a proof with any other shape proves a different position."""
    dirs = []
    pos, n = index, leaf_count
    while n > 1:
        if pos % 2 == 1:
            dirs.append("L")
        elif pos + 1 < n:
            dirs.append("R")
        # else: odd node promoted — no pair at this level (§5.1 rule 4)
        pos //= 2
        n = (n + 1) // 2
    return dirs


def verify_inclusion_proof(
    commitment: bytes, index: int, leaf_count: int, proof, root_hex: str
) -> tuple[bool, str]:
    """§5.2 verification, pinned to (index, leaf_count) from the manifest."""
    if not isinstance(proof, list):
        return False, "proof is not an array"
    for pair in proof:
        if (
            not isinstance(pair, list) or len(pair) != 2
            or pair[0] not in ("L", "R") or not is_hex64(pair[1])
        ):
            return False, f"malformed proof element {pair!r}"
    got_dirs = [p[0] for p in proof]
    want_dirs = expected_proof_dirs(index, leaf_count)
    if got_dirs != want_dirs:
        return False, (
            f"proof shape {got_dirs} does not match index {index} of "
            f"{leaf_count} leaves (expected {want_dirs})"
        )
    h = merkle_leaf(commitment)
    for side, sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        h = merkle_interior(sib, h) if side == "L" else merkle_interior(h, sib)
    if h.hex() != root_hex:
        return False, f"proof root {h.hex()} != merkle_root {root_hex}"
    return True, "ok"


# ------------------------------------------------------------------ reports


class Report:
    """Collects per-check results and renders the table."""

    def __init__(self, heading: str):
        self.heading = heading
        self.rows: list[tuple[str, str, str]] = []

    def add(self, status: str, check: str, detail: str = ""):
        self.rows.append((status, check, detail))

    # conveniences
    def ok(self, check, detail=""):
        self.add("PASS", check, detail)

    def fail(self, check, detail=""):
        self.add("FAIL", check, detail)

    def pending(self, check, detail=""):
        self.add("PENDING", check, detail)

    def skip(self, check, detail=""):
        self.add("SKIPPED", check, detail)

    def note(self, check, detail=""):
        self.add("NOTE", check, detail)

    @property
    def failed(self) -> bool:
        return any(s == "FAIL" for s, _, _ in self.rows)

    def render(self) -> str:
        out = [f"== {self.heading} " + "=" * max(1, 70 - len(self.heading))]
        for status, check, detail in self.rows:
            line = f"  [{status:^9}] {check}"
            if detail:
                line += f"  — {detail}"
            out.append(line)
        return "\n".join(out)


# ----------------------------------------------------------------- context


class Repo:
    def __init__(self, root: Path, args):
        self.root = root
        self.args = args
        self.incidents: list[tuple[Path, bytes, dict | None]] = []
        self.void_trigger: datetime | None = None
        self.bootstrap_path: Path | None = None
        self.bootstrap_doc: dict | None = None

    def path(self, *parts) -> Path:
        return self.root.joinpath(*parts)

    def git(self, *argv) -> subprocess.CompletedProcess | None:
        if not shutil.which("git") or not (self.root / ".git").exists():
            return None
        return subprocess.run(
            ["git", "-C", str(self.root), *argv], capture_output=True, text=True
        )


def load_json(path: Path):
    return json.loads(path.read_bytes())


def is_canonical(raw: bytes) -> bool:
    try:
        return canonical_bytes(json.loads(raw)) == raw
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------- repo-level checks


def check_protocol_integrity(repo: Repo, rep: Report):
    """§14: root PROTOCOL.md byte-equals the highest protocol/vX.Y.Z.md."""
    versions = []
    for p in sorted(repo.path("protocol").glob("v*.md")):
        m = re.match(r"^v(\d+)\.(\d+)\.(\d+)\.md$", p.name)
        if m:
            versions.append((tuple(int(g) for g in m.groups()), p))
    if not versions:
        rep.fail("protocol files", "no protocol/vX.Y.Z.md found")
        return
    versions.sort()
    latest = versions[-1][1]
    root_file = repo.path("PROTOCOL.md")
    if not root_file.exists():
        rep.fail("PROTOCOL.md", "missing")
    elif root_file.read_bytes() == latest.read_bytes():
        rep.ok("PROTOCOL.md byte-equals latest protocol file", latest.name)
    else:
        rep.fail(
            "PROTOCOL.md byte-equals latest protocol file",
            f"differs from {latest.name} (§14 violation)",
        )


def check_incident_chain(repo: Repo, rep: Report):
    """§12.1/§12.2: raw-bytes chain, genesis prev = 64 zeros, NNN cross-check."""
    inc_dir = repo.path("incidents")
    files = sorted(inc_dir.glob("*.json")) if inc_dir.exists() else []
    if not files:
        rep.fail("incident chain", "incidents/000.json (genesis) missing")
        return
    prev_hash = "0" * 64
    numbers = []
    ok = True
    for i, f in enumerate(files):
        raw = f.read_bytes()
        m = re.match(r"^(\d{3})\.json$", f.name)
        if not m:
            rep.fail("incident chain", f"{f.name}: not NNN.json")
            ok = False
            continue
        nnn = int(m.group(1))
        numbers.append(nnn)
        try:
            doc = json.loads(raw)
        except ValueError as e:
            rep.fail("incident chain", f"{f.name}: unparseable JSON ({e})")
            repo.incidents.append((f, raw, None))
            ok = False
            prev_hash = sha256_hex(raw)
            continue
        repo.incidents.append((f, raw, doc))
        if set(doc) != INCIDENT_FIELDS:
            rep.fail("incident chain", f"{f.name}: fields {sorted(doc)} != §12.1 set")
            ok = False
        if doc.get("number") != nnn:
            rep.fail(
                "incident chain",
                f"{f.name}: number {doc.get('number')!r} != filename {nnn}",
            )
            ok = False
        kind = doc.get("kind")
        if nnn == 0:
            if kind != "genesis":
                rep.note("incident chain", f"{f.name}: kind {kind!r} (expected genesis)")
        elif kind not in INCIDENT_KINDS:
            rep.fail("incident chain", f"{f.name}: unknown kind {kind!r}")
            ok = False
        if doc.get("prev_incident_sha256") != prev_hash:
            rep.fail(
                "incident chain",
                f"{f.name}: prev_incident_sha256 {doc.get('prev_incident_sha256')!r}"
                f" != sha256 of previous entry bytes {prev_hash}",
            )
            ok = False
        # §12.2: entries 001+ MUST be canonical (000 is grandfathered)
        if nnn > 0 and not is_canonical(raw):
            rep.fail("incident chain", f"{f.name}: not canonical (§3, §12.2)")
            ok = False
        try:
            parse_iso(doc["recorded_at"])
        except (KeyError, ValueError, TypeError):
            rep.fail("incident chain", f"{f.name}: bad recorded_at")
            ok = False
        prev_hash = sha256_hex(raw)
    if numbers != list(range(len(numbers))):
        rep.fail("incident chain", f"numbers {numbers} not contiguous from 000")
        ok = False
    if ok:
        rep.ok("incident chain", f"{len(files)} entries, genesis prev = 64 zeros")
    compute_void_trigger(repo)


def compute_void_trigger(repo: Repo):
    """§12.4: earliest instant at which the void condition became true —
    the recorded_at of the second incident inside a rolling 52-week window."""
    times = []
    for _, _, doc in repo.incidents:
        if doc and doc.get("kind") != "genesis":
            try:
                times.append(parse_iso(doc["recorded_at"]))
            except (KeyError, ValueError, TypeError):
                pass
    times.sort()
    window = timedelta(seconds=52 * WEEK_SECONDS)
    for i in range(1, len(times)):
        if times[i] - times[i - 1] <= window:
            repo.void_trigger = times[i]
            return


def incident_covering(repo: Repo, week: str, kinds: set[str]) -> dict | None:
    for _, _, doc in repo.incidents:
        if doc and doc.get("week") == week and doc.get("kind") in kinds:
            return doc
    return None


# --------------------------------------------------------------- OTS / 3161


def check_ots(repo: Repo, rep: Report, week: str, subject: Path, ots: Path,
              sealed_at: datetime | None):
    """§13.1 step 8 / §7.1. Never a bare `ots verify` — the stamp is over the
    manifest bytes, so -f must point at the manifest file."""
    cmd = f"ots verify {ots.name} -f {subject.relative_to(repo.root)}"
    if not ots.exists():
        rep.fail(f"OTS stamp ({ots.name})", "missing — committed at seal (§7.1)")
        return
    try:
        from opentimestamps.core.timestamp import DetachedTimestampFile
        from opentimestamps.core.notary import (
            BitcoinBlockHeaderAttestation, PendingAttestation,
        )
        from opentimestamps.core.serialize import (
            BytesDeserializationContext, DeserializationError,
        )
    except ImportError:
        rep.skip(
            f"OTS stamp ({ots.name})",
            f"opentimestamps package not importable; run: {cmd}   "
            "(pip install opentimestamps-client)",
        )
        return
    try:
        ctx = BytesDeserializationContext(ots.read_bytes())
        detached = DetachedTimestampFile.deserialize(ctx)
    except (DeserializationError, Exception) as e:  # noqa: BLE001
        rep.fail(f"OTS stamp ({ots.name})", f"unparseable: {e}")
        return
    digest = hashlib.new(detached.file_hash_op.HASHLIB_NAME,
                         subject.read_bytes()).digest()
    if detached.file_digest != digest:
        rep.fail(
            f"OTS stamp ({ots.name})",
            f"stamped digest {detached.file_digest.hex()} != "
            f"{detached.file_hash_op.HASHLIB_NAME} of {subject.name} ({digest.hex()})",
        )
        return
    heights = []
    pendings = 0
    for _, att in detached.timestamp.all_attestations():
        if isinstance(att, BitcoinBlockHeaderAttestation):
            heights.append(att.height)
        elif isinstance(att, PendingAttestation):
            pendings += 1
    if heights:
        rep.ok(
            f"OTS stamp ({ots.name})",
            f"digest matches; Bitcoin attestation at height {min(heights)} "
            f"(lowest of {len(heights)}) — parsed claim only; confirm with: {cmd}",
        )
    elif pendings:
        deadline = (sealed_at + timedelta(days=7)) if sealed_at else None
        if deadline and now_utc() >= deadline:
            rep.fail(
                f"OTS stamp ({ots.name})",
                f"still pending; §7.1 upgrade deadline {deadline.isoformat()} passed",
            )
        else:
            rep.pending(
                f"OTS stamp ({ots.name})",
                f"pending calendar attestation; upgrade due within 7 days of seal"
                f"{'' if not deadline else ' (by ' + deadline.isoformat() + ')'}",
            )
    else:
        rep.fail(f"OTS stamp ({ots.name})", "no attestations in proof")


GENTIME_RE = re.compile(r"Time stamp: (.+)")


def rfc3161_gentime(tsr: Path) -> datetime | None:
    r = subprocess.run(
        ["openssl", "ts", "-reply", "-in", str(tsr), "-text"],
        capture_output=True, text=True,
    )
    m = GENTIME_RE.search(r.stdout)
    if not m:
        return None
    txt = m.group(1).strip()
    for fmt in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S.%f %Y GMT"):
        try:
            return datetime.strptime(txt, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def check_rfc3161(repo: Repo, rep: Report, week: str, what: str, data: Path,
                  deadline_missing: datetime | None) -> dict[str, datetime]:
    """§13.1 step 9 / §7.2–§7.3. Returns genTime per TSA where verified."""
    gentimes: dict[str, datetime] = {}
    have_openssl = shutil.which("openssl") is not None
    for tsa in ("sectigo", "digicert"):
        name = f"RFC 3161 {what}.{tsa}"
        tsq = repo.path("stamps", week, f"{what}.{tsa}.tsq")
        tsr = repo.path("stamps", week, f"{what}.{tsa}.tsr")
        chain = repo.path("tsa", f"{tsa}-chain.pem")
        cmd = (
            f"openssl ts -verify -queryfile stamps/{week}/{what}.{tsa}.tsq "
            f"-in stamps/{week}/{what}.{tsa}.tsr -CAfile tsa/{tsa}-chain.pem"
        )
        if not tsq.exists() or not tsr.exists():
            if deadline_missing is not None and now_utc() < deadline_missing:
                rep.pending(name, f"token not yet due (deadline {deadline_missing.isoformat()})")
            else:
                rep.fail(name, "token/query missing after its deadline (§13.2)")
            continue
        if not data.exists():
            rep.fail(name, f"{data.name} missing — nothing to bind the token to")
            continue
        if not have_openssl or not chain.exists():
            why = "openssl not on PATH" if not have_openssl else f"{chain} missing"
            rep.skip(name, f"{why}; run: {cmd}")
            continue
        r1 = subprocess.run(
            ["openssl", "ts", "-verify", "-queryfile", str(tsq), "-in", str(tsr),
             "-CAfile", str(chain)], capture_output=True, text=True,
        )
        r2 = subprocess.run(
            ["openssl", "ts", "-verify", "-data", str(data), "-in", str(tsr),
             "-CAfile", str(chain)], capture_output=True, text=True,
        )
        ok1 = r1.returncode == 0 and "Verification: OK" in (r1.stdout + r1.stderr)
        ok2 = r2.returncode == 0 and "Verification: OK" in (r2.stdout + r2.stderr)
        if not (ok1 and ok2):
            err = (r1.stderr + r2.stderr).strip().splitlines()
            rep.fail(name, f"openssl ts -verify failed: {err[-1] if err else 'unknown'}")
            continue
        gt = rfc3161_gentime(tsr)
        if gt is None:
            rep.fail(name, "verified, but genTime could not be parsed from the token")
            continue
        gentimes[tsa] = gt
        rep.ok(name, f"token verifies against {data.name}; genTime {gt.isoformat()}")
    return gentimes


# --------------------------------------------------------------- the beacon


def fetch_url(url: str, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "tsw-verify/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def check_beacon_mirrors(rep: Report, round_no: int, signature_hex: str):
    """--verify-beacon: fetch the round from ≥2 v1-path mirrors, byte-compare.
    NOTE: BLS signature verification is NOT performed (see --help)."""
    bodies: dict[str, bytes] = {}
    for mirror in DRAND_MIRRORS:
        url = f"{mirror}/{QUICKNET_CHAIN_HASH}/public/{round_no}"
        try:
            bodies[mirror] = fetch_url(url)
        except (urllib.error.URLError, OSError, ValueError) as e:
            rep.note("beacon mirror", f"{url}: unreachable ({e})")
    if len(bodies) < 2:
        rep.skip(
            "beacon cross-check",
            f"fewer than 2 of {len(DRAND_MIRRORS)} mirrors reachable; try: "
            f"curl {DRAND_MIRRORS[0]}/{QUICKNET_CHAIN_HASH}/public/{round_no}",
        )
        return
    unique = {b for b in bodies.values()}
    if len(unique) != 1:
        rep.fail("beacon cross-check", f"mirrors disagree byte-for-byte: {sorted(bodies)}")
        return
    body = next(iter(unique))
    try:
        doc = json.loads(body)
    except ValueError:
        rep.fail("beacon cross-check", "mirror response is not JSON")
        return
    if doc.get("round") != round_no:
        rep.fail("beacon cross-check", f"mirror round {doc.get('round')} != pinned {round_no}")
        return
    if doc.get("signature") != signature_hex:
        rep.fail(
            "beacon cross-check",
            f"mirror signature != audits/<week>/beacon.json signature_hex",
        )
        return
    rep.ok(
        "beacon cross-check",
        f"{len(bodies)} mirrors byte-identical; signature matches beacon.json "
        "(BLS signature itself NOT verified — see --help)",
    )


# ------------------------------------------------------------ week verifier


class WeekVerifier:
    def __init__(self, repo: Repo, week: str, prev: "WeekVerifier | None"):
        self.repo = repo
        self.week = week
        self.prev = prev
        self.rep = Report(week)
        self.manifest_path = repo.path("manifests", f"{week}.manifest.json")
        self.manifest_raw: bytes | None = None
        self.manifest: dict | None = None
        self.sealed_at: datetime | None = None
        self.target: datetime | None = None
        self.labels: dict | None = None
        self.beacon: dict | None = None
        self.sampled: list[int] | None = None
        self.audit_set: list[int] | None = None

    # -- step 0: read + canonical + schema
    def load_manifest(self) -> bool:
        if not self.manifest_path.exists():
            self.rep.fail("manifest", f"{self.manifest_path.name} missing")
            return False
        self.manifest_raw = self.manifest_path.read_bytes()
        try:
            self.manifest = json.loads(self.manifest_raw)
        except ValueError as e:
            self.rep.fail("manifest", f"unparseable JSON: {e}")
            return False
        if canonical_bytes(self.manifest) != self.manifest_raw:
            self.rep.fail("manifest canonical form", "bytes are not §3 canonical")
        m = self.manifest
        missing = MANIFEST_FIELDS - set(m)
        extra = set(m) - MANIFEST_FIELDS
        if missing:
            self.rep.fail("manifest schema", f"missing fields {sorted(missing)}")
            return False
        if extra:
            self.rep.note("manifest schema", f"fields beyond §6.2: {sorted(extra)}")
        if m["week"] != self.week:
            self.rep.fail("manifest week", f"{m['week']!r} != filename week {self.week}")
            return False
        for f in ("protocol_sha256", "prev_manifest_sha256", "roster_sha256",
                  "universe_sha256", "merkle_root", "week_seed_hash",
                  "cycle_manifest", "grading_sha256", "derive_script_sha256",
                  "prev_incident_sha256", "archive_sha256", "seed_tle_sha256"):
            if not is_hex64(m[f]):
                self.rep.fail("manifest schema", f"{f} is not 64 lowercase hex")
        if m["repo_git_sha"] is not None and not (
            isinstance(m["repo_git_sha"], str) and HEX40_RE.match(m["repo_git_sha"])
        ):
            self.rep.fail("manifest schema", "repo_git_sha neither null nor 40-hex")
        try:
            self.sealed_at = parse_iso(m["sealed_at"])
        except (ValueError, TypeError):
            self.rep.fail("manifest schema", f"sealed_at unparseable: {m['sealed_at']!r}")
        if m["record_status"] not in ("intact", "void"):
            self.rep.fail("manifest schema", f"record_status {m['record_status']!r}")
        if m["price_source"] != PRICE_SOURCE:
            self.rep.fail("price_source", f"differs from the §6.2 fixed string: {m['price_source']!r}")
        if m["archive_cipher"] != ARCHIVE_CIPHER:
            self.rep.fail("archive_cipher", f"{m['archive_cipher']!r} != {ARCHIVE_CIPHER!r}")
        if not isinstance(m["archive_size"], int) or m["archive_size"] <= 0:
            self.rep.fail("archive_size", f"{m['archive_size']!r} not a positive integer")
        self.check_drand_pin()
        if self.target is None:
            # keep deadline arithmetic working even when the drand pin FAILed
            self.target = beacon_target(self.week)
        self.check_archive_release()
        self.check_seal_time()
        return True

    def check_drand_pin(self):
        m = self.manifest
        d = m["drand"]
        if not isinstance(d, dict) or set(d) != {"chain_hash", "round", "target_time_utc"}:
            self.rep.fail("drand pin", f"drand object malformed: {d!r}")
            return
        problems = []
        if d["chain_hash"] != QUICKNET_CHAIN_HASH:
            problems.append(f"chain_hash {d['chain_hash']!r} != quicknet (§9.2)")
        try:
            pinned_target = parse_iso(d["target_time_utc"])
        except (ValueError, TypeError):
            self.rep.fail("drand pin", f"target_time_utc unparseable: {d['target_time_utc']!r}")
            return
        computed_target = beacon_target(self.week)
        if pinned_target != computed_target:
            problems.append(
                f"target_time_utc {pinned_target.isoformat()} != Saturday 00:00 ET "
                f"of {self.week} = {computed_target.astimezone(timezone.utc).isoformat()}"
            )
        want_round = drand_round_for(pinned_target)
        if d["round"] != want_round:
            problems.append(f"round {d['round']} != §9.2 formula {want_round}")
        self.target = pinned_target
        if problems:
            self.rep.fail("drand pin", "; ".join(problems))
        else:
            self.rep.ok("drand pin", f"round {d['round']} at {d['target_time_utc']}")

    def check_archive_release(self):
        m = self.manifest
        a = m["archive_release"]
        if not isinstance(a, dict) or set(a) != {
            "embargo_weeks", "tlock_chain", "tlock_round", "policy",
        }:
            self.rep.fail("archive_release", f"object malformed: {a!r}")
            return
        problems = []
        if a["embargo_weeks"] != EMBARGO_WEEKS:
            problems.append(f"embargo_weeks {a['embargo_weeks']!r} != {EMBARGO_WEEKS}")
        if a["policy"] != ARCHIVE_POLICY:
            problems.append(f"policy {a['policy']!r} != pinned §6.2 string")
        if a["tlock_chain"] != QUICKNET_CHAIN_HASH:
            problems.append("tlock_chain != quicknet chain hash")
        if self.sealed_at is not None:
            embargo = self.sealed_at + timedelta(seconds=EMBARGO_WEEKS * WEEK_SECONDS)
            want = drand_round_for(embargo)
            if a["tlock_round"] != want:
                problems.append(
                    f"tlock_round {a['tlock_round']!r} != §9.2 formula at "
                    f"sealed_at+104w ({want})"
                )
        if problems:
            self.rep.fail("archive_release", "; ".join(problems))
        else:
            self.rep.ok("archive_release", f"tlock_round {a['tlock_round']}")

    def check_seal_time(self):
        if self.sealed_at is None:
            return
        open_et = et_instant(self.week, 1, 9, 30, 0)  # Monday 09:30:00 ET (§2)
        if self.sealed_at < open_et:
            self.rep.ok("seal time", f"sealed_at {self.sealed_at.isoformat()} before Monday open")
        else:
            inc = incident_covering(self.repo, self.week, {"late-seal"})
            if inc:
                self.rep.note("seal time", f"late seal, covered by incident {inc['number']:03d}")
            else:
                self.rep.fail(
                    "seal time",
                    f"sealed_at {self.sealed_at.isoformat()} at/after Monday 09:30 ET "
                    "with no late-seal incident (§2, §12.3)",
                )

    # -- step 1: protocol pin
    def check_protocol_pin(self):
        m = self.manifest
        ver = m["protocol_version"]
        pfile = self.repo.path("protocol", f"v{ver}.md")
        if not pfile.exists():
            self.rep.fail("protocol pin", f"protocol/v{ver}.md missing")
            return
        got = sha256_hex(pfile.read_bytes())
        if got != m["protocol_sha256"]:
            self.rep.fail(
                "protocol pin",
                f"sha256(protocol/v{ver}.md) = {got} != protocol_sha256 {m['protocol_sha256']}",
            )
            return
        note = ""
        if ver not in PROTOCOL_IMPLEMENTED:
            note = (f" — NOTE: week pins {ver}; this verifier implements "
                    f"{'/'.join(PROTOCOL_IMPLEMENTED)} semantics (§14)")
        self.rep.ok("protocol pin", f"protocol/v{ver}.md matches protocol_sha256{note}")

    # -- step 2: chain walk
    def check_chain(self):
        m = self.manifest
        if self.prev is not None:
            want = sha256_hex(self.prev.manifest_raw)
            src = f"previous manifest {self.prev.week}"
            want_seq = self.prev.manifest["sequence"] + 1
        elif self.repo.bootstrap_path is not None:
            want = sha256_hex(self.repo.bootstrap_path.read_bytes())
            src = f"bootstrap manifest {self.repo.bootstrap_doc.get('week', '?')} (§13.3)"
            want_seq = 2  # bootstrap counts in sequence (§6.2)
        else:
            want = "0" * 64
            src = "genesis (no predecessor)"
            want_seq = 1
        if m["prev_manifest_sha256"] != want:
            self.rep.fail(
                "manifest chain",
                f"prev_manifest_sha256 {m['prev_manifest_sha256']} != sha256 of {src} = {want}",
            )
        else:
            self.rep.ok("manifest chain", f"prev_manifest_sha256 matches {src}")
        if m["sequence"] != want_seq:
            self.rep.fail("sequence", f"{m['sequence']} != expected {want_seq}")
        else:
            self.rep.ok("sequence", str(m["sequence"]))
        # consecutive weeks (SHOULD) — skipped weeks MUST be incident-covered
        prev_week = (
            self.prev.week if self.prev is not None
            else (self.repo.bootstrap_doc or {}).get("week")
        )
        if prev_week:
            expected = next_week_key(prev_week)
            skipped = []
            wk = expected
            guard = 0
            while wk != self.week and guard < 530:
                skipped.append(wk)
                wk = next_week_key(wk)
                guard += 1
            if guard >= 530:
                self.rep.fail("week continuity", f"{prev_week} → {self.week} not a forward step")
            elif skipped:
                covered, uncovered = [], []
                for s in skipped:
                    inc = incident_covering(self.repo, s, {"late-seal", "other"})
                    (covered if inc else uncovered).append(s)
                if covered:
                    self.rep.note(
                        "week continuity",
                        f"{len(covered)} skipped week(s) covered by incidents: "
                        f"{', '.join(covered)}",
                    )
                if uncovered:
                    self.rep.fail(
                        "week continuity",
                        f"{len(uncovered)} skipped week(s) with no covering "
                        f"incident (§13.1 step 2): {', '.join(uncovered)}",
                    )

    # -- step 3: roster/universe pins + §11
    def _git_find_blob(self, filename: str, want_sha: str) -> str | None:
        """Return committer date (ISO) of the earliest commit whose version of
        `filename` has sha256 == want_sha, walking git history; None if absent."""
        r = self.repo.git("log", "--format=%H %cI", "--", filename)
        if r is None or r.returncode != 0:
            return None
        found = None
        for line in r.stdout.splitlines():
            commit, _, cdate = line.partition(" ")
            show = self.repo.git("show", f"{commit}:{filename}")
            if show is not None and show.returncode == 0:
                if sha256_hex(show.stdout.encode()) == want_sha:
                    found = cdate  # keep walking: earliest introduction wins
        return found

    def check_roster_universe(self):
        m = self.manifest
        for fname, field in (("roster.json", "roster_sha256"),
                             ("universe.json", "universe_sha256")):
            pinned = m[field]
            cur = self.repo.path(fname)
            cur_sha = sha256_hex(cur.read_bytes()) if cur.exists() else None
            prev_pin = self.prev.manifest[field] if self.prev else None
            if pinned == cur_sha:
                self.rep.ok(f"{field} pin", f"matches current {fname}")
            else:
                when = self._git_find_blob(fname, pinned)
                if when is not None:
                    self.rep.ok(
                        f"{field} pin",
                        f"matches a historical {fname} (committed {when})",
                    )
                elif cur_sha is None:
                    self.rep.fail(f"{field} pin", f"{fname} missing from repo")
                elif self.repo.git("rev-parse", "HEAD") is None:
                    self.rep.skip(
                        f"{field} pin",
                        f"pin != current {fname} and no git history available to "
                        f"check older versions; run from a git clone",
                    )
                else:
                    self.rep.fail(
                        f"{field} pin",
                        f"pinned {pinned} matches neither current nor any "
                        f"committed version of {fname}",
                    )
            # §11 change notice
            if prev_pin is not None and pinned != prev_pin:
                when = self._git_find_blob(fname, pinned)
                prev_sealed = self.prev.sealed_at
                if when is None:
                    if self.repo.git("rev-parse", "HEAD") is None:
                        self.rep.skip(
                            f"{fname} §11 notice",
                            "changed between weeks; git history unavailable to date the change",
                        )
                    else:
                        self.rep.fail(
                            f"{fname} §11 notice",
                            "changed between weeks but the introducing commit was not found",
                        )
                elif prev_sealed is not None and parse_iso(when) < prev_sealed:
                    self.rep.ok(
                        f"{fname} §11 notice",
                        f"change committed {when}, before week {self.prev.week} sealed",
                    )
                else:
                    self.rep.fail(
                        f"{fname} §11 notice",
                        f"change committed {when}, NOT before previous week's seal "
                        f"({prev_sealed}) — commitment-mismatch (§11)",
                    )

    # -- step 4: merkle rebuild
    def check_merkle(self) -> list[bytes] | None:
        m = self.manifest
        leaf_ids = m["leaf_ids"]
        if not isinstance(leaf_ids, list) or not leaf_ids:
            self.rep.fail("leaf_ids", "not a non-empty array")
            return None
        if len(leaf_ids) != m["leaf_count"]:
            self.rep.fail("leaf_ids", f"length {len(leaf_ids)} != leaf_count {m['leaf_count']}")
        bad = [l for l in leaf_ids if not (isinstance(l, str) and LEAF_ID_RE.match(l))]
        if bad:
            self.rep.fail("leaf_ids", f"malformed ids: {bad[:5]}")
            return None
        enc = [l.encode() for l in leaf_ids]
        if enc != sorted(enc):
            self.rep.fail("leaf_ids", "not bytewise ascending (§5.1)")
        if len(set(leaf_ids)) != len(leaf_ids):
            self.rep.fail("leaf_ids", "duplicate leaf_ids")
        commitments = []
        problems = []
        for lid in leaf_ids:
            slug, _, ticker = lid.partition("/")
            f = self.repo.path("hashes", slug, self.week, f"{ticker}.sha256")
            if not f.exists():
                problems.append(f"missing {f.relative_to(self.repo.root)}")
                continue
            raw = f.read_bytes()
            if len(raw) != 65 or raw[64:] != b"\n" or not HEX64_RE.match(raw[:64].decode("ascii", "replace")):
                problems.append(f"{f.relative_to(self.repo.root)}: not 64 hex + newline (§4.3)")
                continue
            commitments.append(bytes.fromhex(raw[:64].decode()))
        # one-to-one: no extra files for this week
        expected_files = {
            self.repo.path("hashes", l.partition("/")[0], self.week,
                           l.partition("/")[2] + ".sha256")
            for l in leaf_ids
        }
        hashes_dir = self.repo.path("hashes")
        if hashes_dir.exists():
            for f in hashes_dir.glob(f"*/{self.week}/*.sha256"):
                if f not in expected_files:
                    problems.append(f"extra file {f.relative_to(self.repo.root)} not in leaf_ids")
        if problems:
            self.rep.fail("hashes/ file set", "; ".join(problems[:6]))
            return None
        root = merkle_root(commitments).hex()
        if root != m["merkle_root"]:
            self.rep.fail("merkle root", f"rebuilt {root} != manifest {m['merkle_root']}")
            return commitments
        self.rep.ok("merkle root", f"rebuilt from {len(commitments)} hashes/ files; matches")
        return commitments

    # -- step 5: labels
    def check_labels(self):
        m = self.manifest
        path = self.repo.path("labels", f"{self.week}.json")
        friday = et_instant(self.week, 5, 23, 59, 59)
        if not path.exists():
            if self.target is not None and now_utc() < self.target:
                self.rep.pending(
                    "labels", f"due Friday 23:59:59 ET ({friday.isoformat()}); "
                    f"hard deadline is the beacon target {self.target.isoformat()} (§8.5)")
            else:
                self.rep.fail("labels", "missing after the §8.5 beacon-target deadline")
            return
        raw = path.read_bytes()
        try:
            doc = json.loads(raw)
        except ValueError as e:
            self.rep.fail("labels", f"unparseable: {e}")
            return
        if canonical_bytes(doc) != raw:
            self.rep.fail("labels canonical form", "bytes are not §3 canonical")
        if set(doc) != {"week", "entries"} or doc.get("week") != self.week:
            self.rep.fail("labels", f"top-level shape/week wrong: {sorted(doc)}")
            return
        entries = doc["entries"]
        n = m["leaf_count"]
        problems = []
        if not isinstance(entries, list) or len(entries) != n:
            problems.append(f"{len(entries)} entries != leaf_count {n}")
        self.labels = doc
        prev_idx = -1
        for e in entries if isinstance(entries, list) else []:
            if not isinstance(e, dict) or set(e) != LABEL_ENTRY_FIELDS:
                problems.append(f"entry fields wrong: {e!r}"[:120])
                continue
            i = e["index"]
            if not isinstance(i, int) or i != prev_idx + 1:
                problems.append(f"index {i!r} out of order (after {prev_idx})")
            prev_idx = i if isinstance(i, int) else prev_idx
            if isinstance(i, int) and 0 <= i < n:
                slug, _, ticker = m["leaf_ids"][i].partition("/")
                if e["model"] != slug or e["ticker"] != ticker:
                    problems.append(
                        f"entry {i}: model/ticker {e['model']}/{e['ticker']} != "
                        f"leaf_id {m['leaf_ids'][i]}")
            if e["outcome"] not in OUTCOMES:
                problems.append(f"entry {i}: outcome {e['outcome']!r}")
                continue
            nums = (e["actual"], e["reference"], e["final_close"], e["error"])
            if e["outcome"] == "abstain":
                if any(v is not None for v in nums):
                    problems.append(f"entry {i}: abstain with non-null numerics (§8.2)")
            else:
                if any(not isinstance(v, (int, float)) or isinstance(v, bool) for v in nums):
                    problems.append(f"entry {i}: non-abstain with null/non-number numerics")
                    continue
                if e["reference"] == 0:
                    problems.append(f"entry {i}: reference is 0")
                    continue
                want_actual = round((e["final_close"] / e["reference"] - 1) * 100, 2)
                if e["actual"] != want_actual:
                    problems.append(
                        f"entry {i}: actual {e['actual']!r} != §8.3 recompute {want_actual!r}")
                if (e["outcome"] == "scratch") != (e["actual"] == 0.0):
                    problems.append(
                        f"entry {i}: outcome {e['outcome']} inconsistent with "
                        f"actual {e['actual']!r} (§8.3 scratch iff 0.0)")
        if problems:
            self.rep.fail("label coverage", "; ".join(problems[:6]))
        else:
            self.rep.ok("label coverage",
                        f"exactly one entry per index 0..{n - 1}, §8 well-formed")

    # -- step 6: audit indices
    def check_audit(self):
        m = self.manifest
        script = self.repo.path("scripts", "derive_indices.py")
        if not script.exists():
            self.rep.fail("derive_indices pin", "scripts/derive_indices.py missing")
            return
        got = sha256_hex(script.read_bytes())
        if got != m["derive_script_sha256"]:
            self.rep.fail(
                "derive_indices pin",
                f"sha256(scripts/derive_indices.py) = {got} != "
                f"derive_script_sha256 {m['derive_script_sha256']}",
            )
        else:
            self.rep.ok("derive_indices pin", "scripts/derive_indices.py matches manifest pin")
        bpath = self.repo.path("audits", self.week, "beacon.json")
        reveal_deadline = (
            self.target + timedelta(hours=24) if self.target else None
        )
        if not bpath.exists():
            if reveal_deadline is not None and now_utc() < reveal_deadline:
                self.rep.pending(
                    "audit record",
                    f"due within 24 h of beacon target ({reveal_deadline.isoformat()}, §9.7)")
            else:
                self.rep.fail("audit record", "audits/<week>/beacon.json missing after §9.7 deadline")
            return
        raw = bpath.read_bytes()
        try:
            doc = json.loads(raw)
        except ValueError as e:
            self.rep.fail("audit record", f"unparseable: {e}")
            return
        if canonical_bytes(doc) != raw:
            self.rep.fail("audit record canonical form", "bytes are not §3 canonical")
        if set(doc) != BEACON_FIELDS:
            self.rep.fail("audit record", f"fields {sorted(doc)} != §9.6 set")
            return
        self.beacon = doc
        problems = []
        if doc["week"] != self.week:
            problems.append(f"week {doc['week']!r}")
        source = doc["source"]
        if source == "drand":
            if doc["round"] is None or doc["signature_hex"] is None:
                problems.append("drand source with null round/signature_hex (§9.6)")
            if doc["block_height"] is not None or doc["block_hash"] is not None:
                problems.append("drand source with non-null block fields (§9.6)")
            md = m["drand"] if isinstance(m["drand"], dict) else {}
            if doc["round"] != md.get("round"):
                problems.append(
                    f"round {doc['round']} != manifest-pinned {md.get('round')}")
            sig_hex = doc["signature_hex"]
            if not isinstance(sig_hex, str) or not re.fullmatch(r"[0-9a-f]+", sig_hex or ""):
                problems.append("signature_hex not lowercase hex")
                sig_hex = None
            elif len(sig_hex) != 96:
                self.rep.note(
                    "audit record",
                    f"signature_hex is {len(sig_hex) // 2} bytes (quicknet G1 "
                    "signatures are 48 — §9.2 informative)")
        elif source == "bitcoin-fallback":
            self.rep.note("audit record", "bitcoin-fallback beacon used (§9.8)")
            if doc["block_height"] is None or doc["block_hash"] is None:
                problems.append("fallback source with null block fields (§9.6)")
            if doc["round"] is not None or doc["signature_hex"] is not None:
                problems.append("fallback source with non-null drand fields (§9.6)")
            sig_hex = doc["block_hash"]
        else:
            problems.append(f"source {source!r}")
            sig_hex = None
        if problems:
            self.rep.fail("audit record", "; ".join(problems))
            return
        # run the pinned script — the ONE shared implementation (§9.3)
        spec = importlib.util.spec_from_file_location("derive_indices", script)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as e:  # noqa: BLE001
            self.rep.fail("derive indices", f"scripts/derive_indices.py failed to load: {e}")
            return
        n = m["leaf_count"]
        k = mod.audit_k(n)
        if doc["k"] != k:
            self.rep.fail("audit k", f"beacon.json k {doc['k']} != recomputed {k}")
        else:
            self.rep.ok("audit k", f"K = {k} for leaf_count {n} (§9.3)")
        if sig_hex is None:
            return
        try:
            indices = mod.derive_indices(sig_hex, self.week, n, k)
        except Exception as e:  # noqa: BLE001
            self.rep.fail("derive indices", f"derivation failed: {e}")
            return
        if doc["indices"] != indices:
            self.rep.fail(
                "sampled indices",
                f"beacon.json indices != derive_indices.py output (acceptance "
                f"order, §9.3/§9.6): {doc['indices']} vs {indices}",
            )
        else:
            self.rep.ok("sampled indices", f"{k} indices match the §9.3 derivation")
        self.sampled = indices
        if self.labels is not None:
            special = [
                e["index"] for e in self.labels["entries"]
                if isinstance(e, dict) and e.get("outcome") in ("scratch", "abstain")
            ]
            want_set = sorted(set(indices) | set(special))
            if doc["audit_set"] != want_set:
                self.rep.fail(
                    "audit set",
                    f"beacon.json audit_set != K ∪ scratch ∪ abstain ascending "
                    f"(§9.4/§9.6): {doc['audit_set']} vs {want_set}",
                )
            else:
                self.rep.ok("audit set", f"{len(want_set)} owed leaves (§9.4)")
            self.audit_set = want_set
        else:
            self.rep.pending("audit set", "labels not yet published; owed set unknown")
        if self.repo.args.verify_beacon and source == "drand":
            if self.repo.args.offline:
                self.rep.skip("beacon cross-check", "--offline given with --verify-beacon")
            else:
                check_beacon_mirrors(self.rep, doc["round"], doc["signature_hex"])

    # -- step 7: reveals
    def check_reveals(self):
        m = self.manifest
        if self.audit_set is None or self.sampled is None or self.labels is None:
            self.rep.pending("reveals", "owed set not yet determinable (labels/beacon pending)")
            return
        reveal_deadline = self.target + timedelta(hours=24) if self.target else None
        label_by_index = {
            e.get("index"): e for e in self.labels["entries"] if isinstance(e, dict)
        }
        sampled = set(self.sampled)
        problems = []
        checked = 0
        for idx in self.audit_set:
            lid = m["leaf_ids"][idx]
            slug, _, ticker = lid.partition("/")
            rpath = self.repo.path("audits", self.week, slug, f"{ticker}.json")
            tag = f"{lid}[{idx}]"
            if not rpath.exists():
                if reveal_deadline is not None and now_utc() < reveal_deadline:
                    self.rep.pending("reveals", f"{tag} not yet due (§9.7)")
                else:
                    problems.append(f"{tag}: reveal missing after §9.7 deadline")
                continue
            raw = rpath.read_bytes()
            try:
                doc = json.loads(raw)
            except ValueError as e:
                problems.append(f"{tag}: unparseable ({e})")
                continue
            if canonical_bytes(doc) != raw:
                problems.append(f"{tag}: reveal not §3 canonical")
            if set(doc) != REVEAL_FIELDS:
                problems.append(f"{tag}: fields {sorted(doc)} != §9.5 set")
                continue
            if (doc["week"], doc["index"], doc["model"], doc["ticker"]) != (
                self.week, idx, slug, ticker
            ):
                problems.append(f"{tag}: week/index/model/ticker mismatch")
                continue
            label = label_by_index.get(idx)
            if label is None or "outcome" not in label:
                problems.append(f"{tag}: no usable label entry for this index")
                continue
            want_kind = "sampled" if idx in sampled else label["outcome"]
            if doc["kind"] != want_kind:
                problems.append(
                    f"{tag}: kind {doc['kind']!r} != {want_kind!r} "
                    "(§9.5, sampled precedence)")
            if doc["merkle_root"] != m["merkle_root"]:
                problems.append(f"{tag}: reveal merkle_root != manifest")
            try:
                payload = base64.b64decode(doc["payload_b64"], validate=True)
            except (ValueError, TypeError):
                problems.append(f"{tag}: payload_b64 not valid base64")
                continue
            try:
                leaf = json.loads(payload)
            except ValueError:
                problems.append(f"{tag}: payload is not JSON")
                continue
            if canonical_bytes(leaf) != payload:
                problems.append(f"{tag}: payload fails recanonicalization (§13.1 step 7)")
                continue
            if not (isinstance(doc["salt_hex"], str) and re.fullmatch(r"[0-9a-f]{64}", doc["salt_hex"])):
                problems.append(f"{tag}: salt_hex not 32 bytes of lowercase hex")
                continue
            hfile = self.repo.path("hashes", slug, self.week, f"{ticker}.sha256")
            committed = hfile.read_bytes()[:64].decode() if hfile.exists() else None
            commitment = sha256_hex(payload + bytes.fromhex(doc["salt_hex"]))
            if commitment != committed:
                problems.append(
                    f"{tag}: SHA-256(payload‖salt) {commitment} != committed {committed}")
                continue
            ok, why = verify_inclusion_proof(
                bytes.fromhex(commitment), idx, m["leaf_count"], doc["proof"],
                m["merkle_root"],
            )
            if not ok:
                problems.append(f"{tag}: {why}")
                continue
            problems.extend(f"{tag}: {p}" for p in self._label_consistency(leaf, label, slug, ticker))
            checked += 1
        # extra reveal files beyond the owed set are a disclosure, not a failure
        audits_dir = self.repo.path("audits", self.week)
        owed_files = {
            self.repo.path("audits", self.week, m["leaf_ids"][i].partition("/")[0],
                           m["leaf_ids"][i].partition("/")[2] + ".json")
            for i in self.audit_set
        }
        if audits_dir.exists():
            for f in audits_dir.glob("*/*.json"):
                if f not in owed_files:
                    self.rep.note("reveals", f"extra reveal beyond the owed set: "
                                  f"{f.relative_to(self.repo.root)}")
        if problems:
            self.rep.fail("reveals", "; ".join(problems[:8]))
        elif checked == len(self.audit_set):
            self.rep.ok(
                "reveals",
                f"all {checked} owed leaves: recanonicalize, salted hash, Merkle "
                "proof, label consistency (§13.1 step 7)")
        self.rep.skip(
            "price plausibility",
            "SHOULD-check not automated: compare each revealed label's "
            "reference/final_close with an independent daily-close source "
            "(±1% informative tolerance, §13.1 step 7)")

    def _label_consistency(self, leaf, label, slug, ticker) -> list[str]:
        problems = []
        outcome = label["outcome"]
        if outcome == "abstain":
            want = {"kind": "abstain", "model": slug, "ticker": ticker, "week": self.week}
            if canonical_bytes(leaf) != canonical_bytes(want):
                problems.append(
                    "abstain label but leaf is not the exact §8.4 abstain shape")
            return problems
        if isinstance(leaf, dict) and leaf.get("kind") == "abstain":
            problems.append("leaf has abstain shape but label outcome is "
                            f"{outcome!r} (§13.1 step 7)")
            return problems
        if not isinstance(leaf, dict):
            return ["leaf payload is not an object"]
        missing = {"week", "model", "ticker", "direction", "predicted", "reference"} - set(leaf)
        if missing:
            return [f"prediction leaf missing §8.4 fields {sorted(missing)}"]
        if (leaf["week"], leaf["model"], leaf["ticker"]) != (self.week, slug, ticker):
            problems.append("leaf week/model/ticker do not match manifest/label")
        if leaf["direction"] not in ("LONG", "SHORT"):
            problems.append(f"direction {leaf['direction']!r}")
            return problems
        if label["reference"] != leaf["reference"]:
            problems.append(
                f"label reference {label['reference']!r} != leaf {leaf['reference']!r}")
        if label["reference"]:
            want_actual = round((label["final_close"] / label["reference"] - 1) * 100, 2)
            if label["actual"] != want_actual:
                problems.append(f"actual {label['actual']!r} != recompute {want_actual!r}")
            if want_actual == 0.0:
                want_outcome = "scratch"
            elif (leaf["direction"] == "LONG") == (want_actual > 0):
                want_outcome = "win"
            else:
                want_outcome = "loss"
            if outcome != want_outcome:
                problems.append(f"outcome {outcome!r} != graded {want_outcome!r} (§8.3)")
            want_error = round(leaf["predicted"] - want_actual, 1)
            if label["error"] != want_error:
                problems.append(f"error {label['error']!r} != round(predicted−actual,1) {want_error!r}")
        return problems

    # -- step 8 context: incidents & void
    def check_incidents_pin(self):
        m = self.manifest
        chain_hashes = {sha256_hex(raw) for _, raw, _ in self.repo.incidents}
        if m["prev_incident_sha256"] in chain_hashes:
            self.rep.ok("incident pin", "prev_incident_sha256 is in the incident chain")
        else:
            self.rep.fail(
                "incident pin",
                f"prev_incident_sha256 {m['prev_incident_sha256']} matches no "
                "incidents/NNN.json bytes",
            )
        # §12.4 void arithmetic + one-way latch
        want_void = False
        why = "no two non-genesis incidents within 52 weeks"
        if (
            self.repo.void_trigger is not None
            and self.sealed_at is not None
            and self.sealed_at >= self.repo.void_trigger
        ):
            want_void = True
            why = f"void triggered {self.repo.void_trigger.isoformat()} (§12.4)"
        if self.prev is not None and self.prev.manifest["record_status"] == "void":
            want_void = True
            why = "previous manifest is void (one-way latch, §12.4)"
        want = "void" if want_void else "intact"
        if m["record_status"] == want:
            self.rep.ok("record_status", f"{want} — {why}")
        else:
            self.rep.fail(
                "record_status",
                f"manifest says {m['record_status']!r} but §12.4 arithmetic says "
                f"{want!r} ({why})",
            )

    # -- step 10: archive
    def check_archive(self):
        m = self.manifest
        asset = f"tensorswing-{self.week}.tar.gz.enc"
        url = self._release_url(asset)
        if not self.repo.args.all:
            self.rep.skip(
                "archive asset",
                f"not fetched by default; run with --all, or: curl -L -o {asset} "
                f"{url} && shasum -a 256 {asset}  # expect {m['archive_sha256']}",
            )
            return
        if self.repo.args.offline:
            self.rep.skip(
                "archive asset",
                f"--offline; check yourself: curl -L -o {asset} {url} && "
                f"shasum -a 256 {asset}  # expect {m['archive_sha256']}",
            )
            return
        try:
            data = fetch_url(url, timeout=120)
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.rep.fail("archive asset", f"fetch failed: {url}: {e}")
            return
        got_sha, got_size = sha256_hex(data), len(data)
        if got_sha != m["archive_sha256"] or got_size != m["archive_size"]:
            self.rep.fail(
                "archive asset",
                f"release asset sha256/size {got_sha}/{got_size} != manifest "
                f"{m['archive_sha256']}/{m['archive_size']}",
            )
        else:
            self.rep.ok("archive asset", f"{asset}: sha256 and size match ({got_size} bytes)")

    def _release_url(self, asset: str) -> str:
        owner_repo = "YermekIbrayev/tensorswing-record"
        r = self.repo.git("remote", "get-url", "origin")
        if r is not None and r.returncode == 0:
            m = re.search(r"github\.com[:/]+([^/]+/[^/\s]+?)(?:\.git)?$", r.stdout.strip())
            if m:
                owner_repo = m.group(1)
        return f"https://github.com/{owner_repo}/releases/download/{self.week}/{asset}"

    # -- step 11: seed release
    def check_seed_release(self):
        m = self.manifest
        tle = self.repo.path("release", f"{self.week}.seed.tle")
        if not tle.exists():
            self.rep.fail("seed tle", "release/<week>.seed.tle missing (published at seal, §10.4)")
        else:
            got = sha256_hex(tle.read_bytes())
            if got != m["seed_tle_sha256"]:
                self.rep.fail("seed tle", f"sha256 {got} != seed_tle_sha256 {m['seed_tle_sha256']}")
            else:
                self.rep.ok("seed tle", "release/<week>.seed.tle matches seed_tle_sha256")
        if self.sealed_at is None:
            return
        embargo = self.sealed_at + timedelta(seconds=EMBARGO_WEEKS * WEEK_SECONDS)
        if now_utc() < embargo:
            return  # not yet due; nothing to report every week for 2 years
        seed = self.repo.path("release", f"{self.week}.seed")
        if not seed.exists():
            if now_utc() < embargo + timedelta(hours=72):
                self.rep.pending("seed release", f"manual seed due by {embargo + timedelta(hours=72)}")
            else:
                self.rep.fail("seed release", "release/<week>.seed missing past embargo+72h (§10.4)")
            return
        raw = seed.read_bytes()
        if not re.fullmatch(rb"[0-9a-f]{64}\n", raw):
            self.rep.fail("seed release", "seed file is not 64 lowercase hex + newline")
            return
        if sha256_hex(bytes.fromhex(raw[:64].decode())) != m["week_seed_hash"]:
            self.rep.fail("seed release", "released seed does not hash to week_seed_hash")
            return
        self.rep.ok("seed release", "released seed hashes to week_seed_hash")
        self.rep.skip(
            "full-set verification",
            "SHOULD-check not automated (AES-256-GCM needs a non-stdlib "
            "library): re-derive salts per §4.2 from the released seed, decrypt "
            "the archive per §10.3, recompute every §4.3 commitment",
        )

    # -- steps 8/9 wrappers
    def check_stamps(self):
        check_ots(
            self.repo, self.rep, self.week, self.manifest_path,
            self.repo.path(f"{self.week}.manifest.ots"), self.sealed_at,
        )
        check_rfc3161(self.repo, self.rep, self.week, "manifest",
                      self.manifest_path, deadline_missing=None)
        labels_path = self.repo.path("labels", f"{self.week}.json")
        gentimes = check_rfc3161(
            self.repo, self.rep, self.week, "labels", labels_path,
            deadline_missing=self.target,
        )
        for tsa, gt in gentimes.items():
            if self.target is None:
                continue
            if gt < self.target:
                self.rep.ok(
                    f"§8.5 ordering ({tsa})",
                    f"labels genTime {gt.isoformat()} strictly before beacon "
                    f"target {self.target.isoformat()}")
            else:
                self.rep.fail(
                    f"§8.5 ordering ({tsa})",
                    f"labels genTime {gt.isoformat()} NOT strictly before beacon "
                    f"target {self.target.isoformat()} — audit void "
                    "(label-after-beacon, §8.5/§12.3)")

    def run(self) -> Report:
        if not self.load_manifest():
            return self.rep
        self.check_protocol_pin()
        self.check_chain()
        self.check_roster_universe()
        self.check_merkle()
        self.check_labels()
        self.check_audit()
        self.check_reveals()
        self.check_incidents_pin()
        self.check_stamps()
        self.check_archive()
        self.check_seed_release()
        return self.rep


# -------------------------------------------------------------- bootstrap


def verify_bootstrap(repo: Repo) -> Report | None:
    """§13.3: the 2026-W34 bootstrap manifest — presence + OTS stamp only."""
    candidates = sorted(repo.path("manifests").glob("*.manifest.json")) \
        if repo.path("manifests").exists() else []
    for p in candidates:
        try:
            doc = json.loads(p.read_bytes())
        except ValueError:
            continue
        if isinstance(doc, dict) and "cycle_sha256" in doc and "merkle_root" not in doc:
            repo.bootstrap_path = p
            repo.bootstrap_doc = doc
            break
    if repo.bootstrap_path is None:
        return None
    doc = repo.bootstrap_doc
    week = doc.get("week", repo.bootstrap_path.name.split(".")[0])
    rep = Report(f"{week} (BOOTSTRAP, §13.3)")
    missing = BOOTSTRAP_FIELDS - set(doc)
    if missing:
        rep.fail("bootstrap manifest", f"missing fields {sorted(missing)}")
    else:
        rep.add("BOOTSTRAP", "bootstrap manifest",
                f"reduced schema present ({repo.bootstrap_path.name}); no other "
                "§13.1 step applies (§13.3)")
    if week != BOOTSTRAP_WEEK:
        rep.note("bootstrap manifest",
                 f"week {week!r} — the protocol names {BOOTSTRAP_WEEK} (§13.3)")
    stamped_at = None
    try:
        stamped_at = parse_iso(doc["stamped_at"])
    except (KeyError, ValueError, TypeError):
        rep.fail("bootstrap manifest", "stamped_at unparseable")
    check_ots(repo, rep, week, repo.bootstrap_path,
              repo.path(f"{week}.manifest.ots"), stamped_at)
    return rep


# ------------------------------------------------------------------- main


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="verify.py",
        description="Check the tensorswing-record repository against protocol §13.",
        epilog=__doc__.split("WHAT THIS TOOL DOES NOT DO", 1)[1].join(
            ["LIMITS — WHAT THIS TOOL DOES NOT DO", ""]
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("weeks", nargs="*", metavar="week",
                    help="week key(s) like 2026-W35; default: every week in manifests/")
    ap.add_argument("--all", action="store_true",
                    help="also download the GitHub Release archive asset and check "
                         "archive_sha256/archive_size (network)")
    ap.add_argument("--verify-beacon", action="store_true",
                    help="fetch the pinned drand round from >=2 public mirrors and "
                         "byte-compare (network; BLS signature NOT verified)")
    ap.add_argument("--offline", action="store_true",
                    help="never touch the network; network-only checks report "
                         "SKIPPED with the exact command to run")
    ap.add_argument("--repo", type=Path, default=None,
                    help="repository root (default: parent of this script's directory)")
    args = ap.parse_args(argv)

    root = (args.repo or Path(__file__).resolve().parent.parent).resolve()
    repo = Repo(root, args)
    reports: list[Report] = []

    repo_rep = Report("repository")
    check_protocol_integrity(repo, repo_rep)
    check_incident_chain(repo, repo_rep)
    reports.append(repo_rep)

    boot_rep = verify_bootstrap(repo)

    manifests_dir = repo.path("manifests")
    all_weeks = []
    if manifests_dir.exists():
        for p in sorted(manifests_dir.glob("*.manifest.json")):
            wk = p.name[: -len(".manifest.json")]
            if WEEK_RE.match(wk) and p != repo.bootstrap_path:
                all_weeks.append(wk)
    all_weeks.sort()

    selected = args.weeks or all_weeks
    bad_args = [w for w in selected if not WEEK_RE.match(w)]
    if bad_args:
        ap.error(f"not week keys: {bad_args}")

    if boot_rep is not None:
        boot_week = (repo.bootstrap_doc or {}).get("week")
        if not args.weeks or boot_week in args.weeks:
            reports.append(boot_rep)
        selected = [w for w in selected if w != boot_week]

    # chain walk needs every week oldest→newest regardless of selection (§13.1)
    prev: WeekVerifier | None = None
    by_week: dict[str, WeekVerifier] = {}
    for wk in all_weeks:
        v = WeekVerifier(repo, wk, prev)
        v.run()
        by_week[wk] = v
        if v.manifest_raw is not None and v.manifest is not None:
            prev = v
    for wk in selected:
        if wk in by_week:
            reports.append(by_week[wk].rep)
        else:
            r = Report(wk)
            r.fail("manifest", f"manifests/{wk}.manifest.json not found")
            reports.append(r)

    if not all_weeks and boot_rep is None and not args.weeks:
        repo_rep.note("weeks", "no weekly manifests present yet; nothing further to check")

    print(__doc__.split("\n", 1)[0])
    print(f"repo: {root}")
    print(f"time: {now_utc().isoformat()}\n")
    for r in reports:
        print(r.render())
        print()
    n_fail = sum(1 for r in reports if r.failed)
    verdict = "FAIL" if n_fail else "OK"
    print(f"verdict: {verdict} ({len(reports) - 1} section(s) checked, "
          f"{n_fail} with failures)")
    if not n_fail:
        print("note: PASS here means the §13 checks this tool can run held; "
              "see --help for what is out of scope.")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
