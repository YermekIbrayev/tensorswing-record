"""verify.py acceptance tests — stdlib unittest only, no pytest.

Every fixture is generated at test time by tests/golden_gen.py (an
independent producer-side implementation of the protocol text) and then
verify.py is run over it AS A SUBPROCESS, asserting on its report table
and exit code: golden week PASSes, each broken variant FAILs on exactly
the check the tampering targets, young weeks report PENDING, and the
bootstrap week reports BOOTSTRAP.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from golden_gen import (
    REPO_ROOT, WEEK, build_bootstrap, build_golden, rewrite_json,
    rewrite_manifest,
)

VERIFY = REPO_ROOT / "scripts" / "verify.py"
VECTORS = REPO_ROOT / "protocol" / "test-vectors" / "v1"


def run_verify(repo: Path, *extra: str) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, str(VERIFY), "--offline", "--repo", str(repo), *extra],
        capture_output=True, text=True, timeout=300,
    )
    return r.returncode, r.stdout + r.stderr


def rows(output: str, check: str) -> list[str]:
    """Statuses of every report row whose check name matches."""
    pat = re.compile(r"^\s*\[\s*(\S+)\s*\]\s+" + re.escape(check), re.M)
    return pat.findall(output)


def load_verify_module():
    spec = importlib.util.spec_from_file_location("verify_under_test", VERIFY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class VectorTests(unittest.TestCase):
    """verify.py's §3/§5 primitives against the pinned protocol vectors."""

    @classmethod
    def setUpClass(cls):
        cls.v = load_verify_module()

    def test_canonical_vectors(self):
        for case in json.loads((VECTORS / "canonical.json").read_bytes())["cases"]:
            got = self.v.canonical_bytes(case["input"])
            self.assertEqual(got, case["canonical"].encode(), case["name"])
            self.assertEqual(self.v.sha256_hex(got), case["sha256"], case["name"])

    def test_merkle_vectors(self):
        mv = json.loads((VECTORS / "merkle.json").read_bytes())
        commits = [bytes.fromhex(h) for h in mv["commitments_hex"]]
        for n, want in mv["roots"].items():
            self.assertEqual(self.v.merkle_root(commits[: int(n)]).hex(), want)
        ip = mv["inclusion_proof"]
        ok, why = self.v.verify_inclusion_proof(
            bytes.fromhex(ip["commitment_hex"]), ip["index"], ip["leaf_count"],
            ip["proof"], ip["merkle_root"])
        self.assertTrue(ok, why)
        ok, _ = self.v.verify_inclusion_proof(
            bytes.fromhex(ip["commitment_hex"]), 1, ip["leaf_count"],
            ip["proof"], ip["merkle_root"])
        self.assertFalse(ok, "a proof for index 2 must not verify as index 1")

    def test_indices_vector_via_pinned_script(self):
        iv = json.loads((VECTORS / "indices.json").read_bytes())
        spec = importlib.util.spec_from_file_location(
            "derive_indices_t", REPO_ROOT / "scripts" / "derive_indices.py")
        d = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(d)
        k = d.audit_k(iv["leaf_count"])
        self.assertEqual(k, iv["expected"]["k"])
        self.assertEqual(
            d.derive_indices(iv["beacon_signature_hex"], iv["week"],
                             iv["leaf_count"], k),
            iv["expected"]["indices"])

    def test_hkdf_vectors_generator_side(self):
        from golden_gen import hkdf_sha256
        for case in json.loads((VECTORS / "hkdf.json").read_bytes())["cases"]:
            if case["salt_hex"]:
                continue  # generator implements the protocol's empty-salt form
            got = hkdf_sha256(bytes.fromhex(case["ikm_hex"]),
                              bytes.fromhex(case["info_hex"]), case["length"])
            self.assertEqual(got.hex(), case["okm_hex"], case["name"])


class GoldenWeekTests(unittest.TestCase):
    """One golden fixture, verified once; assertions on the report."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="tsw-golden-")
        cls.repo = Path(cls.tmp.name)
        build_golden(cls.repo)
        cls.rc, cls.out = run_verify(cls.repo)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_exit_zero(self):
        self.assertEqual(self.rc, 0, self.out)

    def test_key_checks_pass(self):
        for check in ("protocol pin", "manifest chain", "sequence",
                      "merkle root", "label coverage", "audit k",
                      "sampled indices", "audit set", "reveals",
                      "incident chain", "incident pin", "record_status",
                      "drand pin", "archive_release", "derive_indices pin",
                      "seed tle", "PROTOCOL.md byte-equals"):
            statuses = rows(self.out, check)
            self.assertTrue(statuses, f"no report row for {check!r}\n{self.out}")
            self.assertIn("PASS", statuses, f"{check}: {statuses}\n{self.out}")

    def test_no_failures_anywhere(self):
        self.assertNotIn("[  FAIL   ]", self.out, self.out)

    def test_network_checks_skipped_offline(self):
        self.assertIn("SKIPPED", "".join(rows(self.out, "archive asset")), self.out)

    def test_ots_never_bare(self):
        # every printed ots command must bind the manifest file with -f
        for m in re.finditer(r"ots verify (\S+)(.*)", self.out):
            self.assertIn("-f", m.group(2), f"bare ots verify printed: {m.group(0)}")


class BrokenVariantTests(unittest.TestCase):
    """Each tampering FAILs on the check it targets, with exit code 1."""

    def _mutated(self, mutate) -> tuple[int, str]:
        with tempfile.TemporaryDirectory(prefix="tsw-broken-") as tmp:
            repo = Path(tmp)
            build_golden(repo)
            mutate(repo)
            return run_verify(repo)

    def assert_fails(self, rc, out, check):
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL", rows(out, check), f"{check} did not FAIL\n{out}")

    def test_bad_merkle_root(self):
        rc, out = self._mutated(lambda r: rewrite_manifest(
            r, WEEK, lambda m: m.update(merkle_root="ab" * 32)))
        self.assert_fails(rc, out, "merkle root")

    def test_broken_manifest_chain(self):
        rc, out = self._mutated(lambda r: rewrite_manifest(
            r, WEEK, lambda m: m.update(prev_manifest_sha256="12" * 32)))
        self.assert_fails(rc, out, "manifest chain")

    def test_label_gap(self):
        rc, out = self._mutated(lambda r: rewrite_json(
            r / "labels" / f"{WEEK}.json",
            lambda d: d["entries"].pop(1)))
        self.assert_fails(rc, out, "label coverage")

    def test_wrong_audit_set(self):
        def swap(d):
            d["indices"][0], d["indices"][1] = d["indices"][1], d["indices"][0]
        rc, out = self._mutated(lambda r: rewrite_json(
            r / "audits" / WEEK / "beacon.json", swap))
        self.assert_fails(rc, out, "sampled indices")

    def test_tampered_reveal(self):
        def tamper(repo: Path):
            path = repo / "audits" / WEEK / "alpha" / "AAA.json"

            def m(d):
                import base64
                leaf = json.loads(base64.b64decode(d["payload_b64"]))
                leaf["predicted"] = 9.99  # rewrite history, keep it canonical
                d["payload_b64"] = base64.b64encode(
                    json.dumps(leaf, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True).encode()).decode()
            rewrite_json(path, m)
        rc, out = self._mutated(tamper)
        self.assert_fails(rc, out, "reveals")

    def test_bad_incident_chain(self):
        rc, out = self._mutated(lambda r: rewrite_json(
            r / "incidents" / "001.json",
            lambda d: d.update(prev_incident_sha256="ef" * 32)))
        self.assert_fails(rc, out, "incident chain")

    def test_void_mismatch(self):
        def add_second_incident(repo: Path):
            import hashlib
            from golden_gen import _write_incident
            prev = hashlib.sha256(
                (repo / "incidents" / "001.json").read_bytes()).hexdigest()
            # second non-genesis incident 28 days after 001, well before the
            # W20 seal -> §12.4 says the W20 manifest must be void; it says
            # intact -> record_status must FAIL
            _write_incident(repo, 2, "other", None,
                            "synthetic: second incident inside 52 weeks",
                            prev, "2026-03-01T09:00:00-05:00")
        rc, out = self._mutated(add_second_incident)
        self.assert_fails(rc, out, "record_status")


class BootstrapAndPendingTests(unittest.TestCase):
    """§13.3 bootstrap handling + §13.2 young-week PENDING semantics."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="tsw-boot-")
        cls.repo = Path(cls.tmp.name)
        cls.boot_week, cls.young_week = build_bootstrap(cls.repo)
        cls.rc, cls.out = run_verify(cls.repo)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_exit_zero(self):
        self.assertEqual(self.rc, 0, self.out)

    def test_bootstrap_reported(self):
        self.assertIn("BOOTSTRAP", rows(self.out, "bootstrap manifest"), self.out)

    def test_chain_from_bootstrap(self):
        self.assertIn("PASS", rows(self.out, "manifest chain"), self.out)
        self.assertIn("PASS", rows(self.out, "sequence"), self.out)

    def test_young_week_pending_not_fail(self):
        self.assertIn("PENDING", rows(self.out, "labels"), self.out)
        self.assertIn("PENDING", rows(self.out, "audit record"), self.out)
        self.assertNotIn("[  FAIL   ]", self.out, self.out)


if __name__ == "__main__":
    unittest.main()
