#!/usr/bin/env python3
"""
Comprehensive test suite for the Consumer Adoption Ladder Pack.

Tests climb_ladder.py (generator) and verify_ladder.py (verifier) across
14 test classes with 130+ tests. Uses only stdlib (unittest, tempfile, json,
os, shutil, re). No pytest dependency required.
"""

import copy
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

# ---------------------------------------------------------------------------
# Path setup — ensure climb_ladder and verify_ladder are importable
# ---------------------------------------------------------------------------
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import climb_ladder as cl
import verify_ladder as vl

ARTIFACTS_DIR = os.path.join(REPO_ROOT, "consumer_artifacts")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tmpdir():
    """Create a temporary directory, return its path."""
    return tempfile.mkdtemp(prefix="test_ladder_")


def _write_json(directory, filename, obj):
    """Write a Python object as JSON to *directory/filename*."""
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    return path


def _run_full_report(artifacts_dir=None, producer_id="test_producer",
                     previous_hash=None):
    """Run the LadderRunner and return the report dict."""
    if artifacts_dir is None:
        artifacts_dir = ARTIFACTS_DIR
    runner = cl.LadderRunner(artifacts_dir, producer_id,
                             previous_hash=previous_hash)
    return runner.run()


def _minimal_discovery():
    """Return a minimal valid discovery_result.json payload."""
    return {
        "producers": [
            {
                "producer_id": "test",
                "endpoint": "https://example.com/api",
                "reputation_grade": "B",
                "schema_ref": "1.0.0",
            }
        ]
    }


def _minimal_health():
    """Return a minimal valid health_report.json payload."""
    return {
        "composite_grade": "B",
        "dimensions": {
            "liveness": {"passed": True, "status": "OK"},
            "schema_compliance": {"passed": True, "status": "OK"},
        },
    }


def _minimal_trust():
    """Return a minimal valid trust_evaluation.json payload."""
    return {
        "verdict": {"recommendation": "ADOPT_WITH_CAVEATS"},
        "risk_factors": [{"id": "R1", "description": "test risk"}],
        "integration_checklist": [{"step": 1, "description": "connect"}],
    }


def _minimal_acceptance():
    """Return a minimal valid acceptance_report.json payload."""
    return {
        "verdict": {"recommendation": "READY"},
        "checks": [
            {"name": "connectivity_check", "passed": True},
        ],
        "blockers": [],
    }


def _minimal_signal_sample():
    """Return a minimal valid signal_sample.json payload."""
    return [
        {
            "symbol": "BTC",
            "direction": "bullish",
            "confidence": 0.75,
            "horizon_hours": 24,
            "timestamp": "2026-04-01T00:00:00Z",
        }
    ]


def _minimal_drift():
    """Return a minimal valid drift_report.json payload."""
    return {
        "alert_severity": "LOW",
        "detection_methods": [
            {"name": "CUSUM", "triggered": False},
            {"name": "SPRT", "triggered": False},
        ],
    }


def _minimal_calibration():
    """Return a minimal valid calibration_report.json payload."""
    return {
        "ece": {"value": 0.05},
        "brier_score": 0.22,
        "per_symbol": {"BTC": {"ece": 0.04}, "ETH": {"ece": 0.06}},
    }


def _minimal_resolved_signals(n=150):
    """Return a list of n minimal resolved signals."""
    return [
        {
            "signal_id": "sig-{}".format(i),
            "symbol": "BTC",
            "direction": "bullish",
            "confidence": 0.6,
            "resolved": True,
            "correct": i % 2 == 0,
        }
        for i in range(n)
    ]


def _minimal_backtest():
    """Return a minimal valid backtest_report.json payload."""
    return {
        "verdict": {"decision": "ADOPT"},
        "best_accuracy": 56.04,
        "strategies": {
            "follow_all": {"metrics": {"accuracy": 52.0}},
            "high_confidence": {"metrics": {"accuracy": 56.04}},
        },
    }


def _minimal_experience():
    """Return a minimal valid experience_report.json payload."""
    return {
        "satisfaction_verdict": {"verdict": "SATISFIED", "confidence": 0.8},
    }


def _minimal_scorecard():
    """Return a minimal valid integration_scorecard.json payload."""
    return {
        "overall_verdict": {"readiness": "READY", "grade": "B"},
        "cross_consistency_checks": [
            {"name": "check1", "passed": True},
            {"name": "check2", "passed": True},
            {"name": "check3", "passed": True},
            {"name": "check4", "passed": True},
        ],
    }


def _minimal_forensic():
    """Return a minimal valid forensic_report.json payload."""
    return {
        "failure_mode_ranking": [
            {"mode": "stale_signal", "count": 5},
            {"mode": "direction_flip", "count": 3},
        ],
    }


def _write_all_artifacts(tmpdir):
    """Write all minimal artifacts needed for a full TRUST pass."""
    _write_json(tmpdir, "discovery_result.json", _minimal_discovery())
    _write_json(tmpdir, "health_report.json", _minimal_health())
    _write_json(tmpdir, "trust_evaluation.json", _minimal_trust())
    _write_json(tmpdir, "acceptance_report.json", _minimal_acceptance())
    _write_json(tmpdir, "signal_sample.json", _minimal_signal_sample())
    _write_json(tmpdir, "quickstart_result.json", {"status": "ok"})
    _write_json(tmpdir, "drift_report.json", _minimal_drift())
    _write_json(tmpdir, "calibration_report.json", _minimal_calibration())
    _write_json(tmpdir, "resolved_signals.json", _minimal_resolved_signals())
    _write_json(tmpdir, "backtest_report.json", _minimal_backtest())
    _write_json(tmpdir, "experience_report.json", _minimal_experience())
    _write_json(tmpdir, "integration_scorecard.json", _minimal_scorecard())
    _write_json(tmpdir, "forensic_report.json", _minimal_forensic())


# ===========================================================================
# 1. TestHelpers (10 tests)
# ===========================================================================
class TestHelpers(unittest.TestCase):
    """Test utility helper functions in climb_ladder."""

    def test_sha256_bytes_input(self):
        result = cl._sha256(b"hello")
        self.assertEqual(len(result), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in result))

    def test_sha256_str_input(self):
        result = cl._sha256("hello")
        self.assertEqual(len(result), 64)
        # Same as bytes version
        self.assertEqual(result, cl._sha256(b"hello"))

    def test_sha256_deterministic(self):
        a = cl._sha256("test data")
        b = cl._sha256("test data")
        self.assertEqual(a, b)

    def test_now_iso_format(self):
        ts = cl._now_iso()
        # Must end with Z and match ISO pattern
        self.assertTrue(ts.endswith("Z"))
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_report_id_format(self):
        rid = cl._report_id()
        self.assertRegex(rid, r"^CAL-[A-F0-9]{12}$")

    def test_round6_float(self):
        self.assertEqual(cl._round6(3.14159265358979), 3.141593)

    def test_round6_non_float(self):
        self.assertEqual(cl._round6(42), 42)
        self.assertEqual(cl._round6("test"), "test")

    def test_safe_get_nested(self):
        d = {"a": {"b": {"c": 42}}}
        self.assertEqual(cl._safe_get(d, "a", "b", "c"), 42)

    def test_safe_get_missing(self):
        d = {"a": {"b": 1}}
        self.assertIsNone(cl._safe_get(d, "a", "x", "y"))
        self.assertEqual(cl._safe_get(d, "a", "x", default="default"), "default")

    def test_grade_ord(self):
        self.assertEqual(cl._grade_ord("A"), 0)
        self.assertEqual(cl._grade_ord("B"), 1)
        self.assertEqual(cl._grade_ord("C"), 2)
        self.assertEqual(cl._grade_ord("D"), 3)
        self.assertEqual(cl._grade_ord("F"), 5)
        self.assertEqual(cl._grade_ord("Z"), 5)  # unknown -> 5


# ===========================================================================
# 2. TestArtifactScanner (10 tests)
# ===========================================================================
class TestArtifactScanner(unittest.TestCase):
    """Test the ArtifactScanner class."""

    def test_scan_empty_dir(self):
        tmpdir = _make_tmpdir()
        try:
            scanner = cl.ArtifactScanner(tmpdir)
            result = scanner.scan()
            self.assertIsInstance(result, dict)
            for fname in cl.ArtifactScanner.KNOWN_FILES:
                self.assertIsNone(result[fname])
        finally:
            shutil.rmtree(tmpdir)

    def test_scan_finds_known_file(self):
        tmpdir = _make_tmpdir()
        try:
            _write_json(tmpdir, "discovery_result.json", {"producers": []})
            scanner = cl.ArtifactScanner(tmpdir)
            scanner.scan()
            self.assertIsNotNone(scanner.get("discovery_result.json"))
        finally:
            shutil.rmtree(tmpdir)

    def test_exists_true(self):
        tmpdir = _make_tmpdir()
        try:
            _write_json(tmpdir, "health_report.json", {"grade": "A"})
            scanner = cl.ArtifactScanner(tmpdir)
            scanner.scan()
            self.assertTrue(scanner.exists("health_report.json"))
        finally:
            shutil.rmtree(tmpdir)

    def test_exists_false(self):
        tmpdir = _make_tmpdir()
        try:
            scanner = cl.ArtifactScanner(tmpdir)
            scanner.scan()
            self.assertFalse(scanner.exists("health_report.json"))
        finally:
            shutil.rmtree(tmpdir)

    def test_get_returns_parsed_json(self):
        tmpdir = _make_tmpdir()
        try:
            data = {"key": "value", "num": 42}
            _write_json(tmpdir, "trust_evaluation.json", data)
            scanner = cl.ArtifactScanner(tmpdir)
            scanner.scan()
            result = scanner.get("trust_evaluation.json")
            self.assertEqual(result["key"], "value")
            self.assertEqual(result["num"], 42)
        finally:
            shutil.rmtree(tmpdir)

    def test_raw_returns_string(self):
        tmpdir = _make_tmpdir()
        try:
            data = {"test": True}
            _write_json(tmpdir, "drift_report.json", data)
            scanner = cl.ArtifactScanner(tmpdir)
            scanner.scan()
            raw = scanner.raw("drift_report.json")
            self.assertIsInstance(raw, str)
            self.assertIn("test", raw)
        finally:
            shutil.rmtree(tmpdir)

    def test_raw_missing_returns_empty(self):
        tmpdir = _make_tmpdir()
        try:
            scanner = cl.ArtifactScanner(tmpdir)
            scanner.scan()
            self.assertEqual(scanner.raw("nonexistent.json"), "")
        finally:
            shutil.rmtree(tmpdir)

    def test_invalid_json_yields_none(self):
        tmpdir = _make_tmpdir()
        try:
            path = os.path.join(tmpdir, "health_report.json")
            with open(path, "w") as f:
                f.write("not valid json {{{")
            scanner = cl.ArtifactScanner(tmpdir)
            scanner.scan()
            self.assertIsNone(scanner.get("health_report.json"))
        finally:
            shutil.rmtree(tmpdir)

    def test_raw_contents_for_stage(self):
        tmpdir = _make_tmpdir()
        try:
            _write_json(tmpdir, "drift_report.json", {"a": 1})
            _write_json(tmpdir, "calibration_report.json", {"b": 2})
            scanner = cl.ArtifactScanner(tmpdir)
            scanner.scan()
            combined = scanner.raw_contents_for_stage(
                ["drift_report.json", "calibration_report.json"]
            )
            self.assertIn('"a"', combined)
            self.assertIn('"b"', combined)
        finally:
            shutil.rmtree(tmpdir)

    def test_scan_with_real_artifacts(self):
        if not os.path.isdir(ARTIFACTS_DIR):
            self.skipTest("Real artifacts dir not found")
        scanner = cl.ArtifactScanner(ARTIFACTS_DIR)
        result = scanner.scan()
        self.assertIsNotNone(result.get("discovery_result.json"))
        self.assertIsNotNone(result.get("health_report.json"))
        self.assertTrue(scanner.exists("discovery_result.json"))


# ===========================================================================
# 3. TestReceiptBuilder (6 tests)
# ===========================================================================
class TestReceiptBuilder(unittest.TestCase):
    """Test the ReceiptBuilder static class."""

    def setUp(self):
        self.tmpdir = _make_tmpdir()
        _write_json(self.tmpdir, "discovery_result.json", {"test": True})
        self.scanner = cl.ArtifactScanner(self.tmpdir)
        self.scanner.scan()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_build_returns_dict(self):
        receipt = cl.ReceiptBuilder.build(
            "DISCOVER", [{"check_id": "CHK-DISC-1", "passed": True}],
            self.scanner, ["discovery_result.json"], True
        )
        self.assertIsInstance(receipt, dict)

    def test_build_has_required_keys(self):
        receipt = cl.ReceiptBuilder.build(
            "DISCOVER", [], self.scanner, ["discovery_result.json"], False
        )
        for key in ("stage_hash", "inputs_hash", "timestamp", "passed"):
            self.assertIn(key, receipt)

    def test_stage_hash_is_hex64(self):
        receipt = cl.ReceiptBuilder.build(
            "EVALUATE", [{"a": 1}], self.scanner, [], True
        )
        self.assertRegex(receipt["stage_hash"], r"^[0-9a-f]{64}$")

    def test_inputs_hash_is_hex64(self):
        receipt = cl.ReceiptBuilder.build(
            "DISCOVER", [], self.scanner, ["discovery_result.json"], True
        )
        self.assertRegex(receipt["inputs_hash"], r"^[0-9a-f]{64}$")

    def test_timestamp_is_iso(self):
        receipt = cl.ReceiptBuilder.build(
            "DISCOVER", [], self.scanner, [], False
        )
        self.assertRegex(receipt["timestamp"],
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_passed_reflects_input(self):
        r1 = cl.ReceiptBuilder.build("DISCOVER", [], self.scanner, [], True)
        r2 = cl.ReceiptBuilder.build("DISCOVER", [], self.scanner, [], False)
        self.assertTrue(r1["passed"])
        self.assertFalse(r2["passed"])


# ===========================================================================
# 4. TestDiscoverEvaluator (10 tests)
# ===========================================================================
class TestDiscoverEvaluator(unittest.TestCase):
    """Test the DISCOVER stage evaluator."""

    def _make_evaluator(self, artifacts=None):
        tmpdir = _make_tmpdir()
        if artifacts:
            for name, data in artifacts.items():
                _write_json(tmpdir, name, data)
        scanner = cl.ArtifactScanner(tmpdir)
        scanner.scan()
        evaluator = cl.DiscoverEvaluator(scanner, prev_status=None)
        return evaluator, tmpdir

    def test_discover_with_valid_data(self):
        ev, tmpdir = self._make_evaluator({
            "discovery_result.json": _minimal_discovery()
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["stage_id"], "DISCOVER")
            self.assertEqual(result["status"], "PASSED")
        finally:
            shutil.rmtree(tmpdir)

    def test_discover_missing_file(self):
        ev, tmpdir = self._make_evaluator({})
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
            self.assertTrue(len(result["blockers"]) > 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_discover_no_producers(self):
        ev, tmpdir = self._make_evaluator({
            "discovery_result.json": {"producers": []}
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_discover_grade_extraction(self):
        ev, tmpdir = self._make_evaluator({
            "discovery_result.json": {
                "producers": [
                    {"producer_id": "test", "endpoint": "http://x",
                     "reputation_grade": "A", "schema_ref": "1.0.0"}
                ]
            }
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "PASSED")
            grade_check = [c for c in result["checks"]
                           if c["check_id"] == "CHK-DISC-3"][0]
            self.assertTrue(grade_check["passed"])
            self.assertIn("A", grade_check["detail"])
        finally:
            shutil.rmtree(tmpdir)

    def test_discover_endpoint_extraction(self):
        ev, tmpdir = self._make_evaluator({
            "discovery_result.json": {
                "producers": [
                    {"producer_id": "test", "endpoint": "https://api.example.com",
                     "reputation_grade": "B", "schema_ref": "1.0.0"}
                ]
            }
        })
        try:
            result = ev.evaluate()
            endpoint_check = [c for c in result["checks"]
                              if c["check_id"] == "CHK-DISC-4"][0]
            self.assertTrue(endpoint_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_discover_missing_grade(self):
        ev, tmpdir = self._make_evaluator({
            "discovery_result.json": {
                "producers": [
                    {"producer_id": "test", "endpoint": "http://x"}
                ]
            }
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_discover_checks_have_5(self):
        ev, tmpdir = self._make_evaluator({
            "discovery_result.json": _minimal_discovery()
        })
        try:
            result = ev.evaluate()
            self.assertEqual(len(result["checks"]), 5)
        finally:
            shutil.rmtree(tmpdir)

    def test_discover_receipt_present(self):
        ev, tmpdir = self._make_evaluator({
            "discovery_result.json": _minimal_discovery()
        })
        try:
            result = ev.evaluate()
            self.assertIn("receipt", result)
            self.assertRegex(result["receipt"]["stage_hash"], r"^[0-9a-f]{64}$")
        finally:
            shutil.rmtree(tmpdir)

    def test_discover_registry_fallback(self):
        """Discover should fall back to registry.json if discovery_result.json missing."""
        ev, tmpdir = self._make_evaluator({
            "registry.json": {
                "entries": [
                    {"producer_id": "test", "endpoint": "http://x",
                     "reputation_grade": "C", "schema_ref": "1.0.0"}
                ]
            }
        })
        try:
            result = ev.evaluate()
            file_check = [c for c in result["checks"]
                          if c["check_id"] == "CHK-DISC-1"][0]
            self.assertTrue(file_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_discover_source_artifacts(self):
        ev, tmpdir = self._make_evaluator({
            "discovery_result.json": _minimal_discovery()
        })
        try:
            result = ev.evaluate()
            self.assertTrue(len(result["source_artifacts"]) >= 1)
            self.assertIn("ART-DISC-1",
                          result["source_artifacts"][0]["artifact_id"])
        finally:
            shutil.rmtree(tmpdir)


# ===========================================================================
# 5. TestEvaluateEvaluator (10 tests)
# ===========================================================================
class TestEvaluateEvaluator(unittest.TestCase):
    """Test the EVALUATE stage evaluator."""

    def _make_evaluator(self, artifacts=None, prev_status="PASSED"):
        tmpdir = _make_tmpdir()
        if artifacts:
            for name, data in artifacts.items():
                _write_json(tmpdir, name, data)
        scanner = cl.ArtifactScanner(tmpdir)
        scanner.scan()
        evaluator = cl.EvaluateEvaluator(scanner, prev_status=prev_status)
        return evaluator, tmpdir

    def test_evaluate_passes_with_good_data(self):
        ev, tmpdir = self._make_evaluator({
            "health_report.json": _minimal_health(),
            "trust_evaluation.json": _minimal_trust(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "PASSED")
        finally:
            shutil.rmtree(tmpdir)

    def test_evaluate_blocked_without_health(self):
        ev, tmpdir = self._make_evaluator({
            "trust_evaluation.json": _minimal_trust(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_evaluate_blocked_when_prereq_not_met(self):
        ev, tmpdir = self._make_evaluator({
            "health_report.json": _minimal_health(),
            "trust_evaluation.json": _minimal_trust(),
        }, prev_status="BLOCKED")
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_evaluate_grade_threshold_c(self):
        """Grade C should pass the C-or-better check."""
        health = {"composite_grade": "C"}
        ev, tmpdir = self._make_evaluator({
            "health_report.json": health,
            "trust_evaluation.json": _minimal_trust(),
        })
        try:
            result = ev.evaluate()
            grade_check = [c for c in result["checks"]
                           if c["check_id"] == "CHK-EVAL-2"][0]
            self.assertTrue(grade_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_evaluate_grade_d_fails(self):
        """Grade D should fail the C-or-better check."""
        health = {"composite_grade": "D"}
        ev, tmpdir = self._make_evaluator({
            "health_report.json": health,
            "trust_evaluation.json": _minimal_trust(),
        })
        try:
            result = ev.evaluate()
            grade_check = [c for c in result["checks"]
                           if c["check_id"] == "CHK-EVAL-2"][0]
            self.assertFalse(grade_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_evaluate_verdict_adopt(self):
        ev, tmpdir = self._make_evaluator({
            "health_report.json": _minimal_health(),
            "trust_evaluation.json": {
                "verdict": {"recommendation": "ADOPT"},
                "risk_factors": [],
                "integration_checklist": [{"step": 1}],
            },
        })
        try:
            result = ev.evaluate()
            verdict_check = [c for c in result["checks"]
                             if c["check_id"] == "CHK-EVAL-5"][0]
            self.assertTrue(verdict_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_evaluate_verdict_wait_fails(self):
        ev, tmpdir = self._make_evaluator({
            "health_report.json": _minimal_health(),
            "trust_evaluation.json": {
                "verdict": {"recommendation": "WAIT"},
                "risk_factors": [],
                "integration_checklist": [],
            },
        })
        try:
            result = ev.evaluate()
            verdict_check = [c for c in result["checks"]
                             if c["check_id"] == "CHK-EVAL-5"][0]
            self.assertFalse(verdict_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_evaluate_checks_count(self):
        ev, tmpdir = self._make_evaluator({
            "health_report.json": _minimal_health(),
            "trust_evaluation.json": _minimal_trust(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(len(result["checks"]), 7)
        finally:
            shutil.rmtree(tmpdir)

    def test_evaluate_hard_gate_failure(self):
        health = {
            "composite_grade": "B",
            "dimensions": {
                "liveness": {"passed": False, "status": "FAIL"},
            },
        }
        ev, tmpdir = self._make_evaluator({
            "health_report.json": health,
            "trust_evaluation.json": _minimal_trust(),
        })
        try:
            result = ev.evaluate()
            gate_check = [c for c in result["checks"]
                          if c["check_id"] == "CHK-EVAL-3"][0]
            self.assertFalse(gate_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_evaluate_source_artifacts(self):
        ev, tmpdir = self._make_evaluator({
            "health_report.json": _minimal_health(),
            "trust_evaluation.json": _minimal_trust(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(len(result["source_artifacts"]), 2)
        finally:
            shutil.rmtree(tmpdir)


# ===========================================================================
# 6. TestIntegrateEvaluator (10 tests)
# ===========================================================================
class TestIntegrateEvaluator(unittest.TestCase):
    """Test the INTEGRATE stage evaluator."""

    def _make_evaluator(self, artifacts=None, prev_status="PASSED"):
        tmpdir = _make_tmpdir()
        if artifacts:
            for name, data in artifacts.items():
                _write_json(tmpdir, name, data)
        scanner = cl.ArtifactScanner(tmpdir)
        scanner.scan()
        evaluator = cl.IntegrateEvaluator(scanner, prev_status=prev_status)
        return evaluator, tmpdir

    def test_integrate_passes(self):
        ev, tmpdir = self._make_evaluator({
            "acceptance_report.json": _minimal_acceptance(),
            "signal_sample.json": _minimal_signal_sample(),
            "quickstart_result.json": {"status": "ok"},
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "PASSED")
        finally:
            shutil.rmtree(tmpdir)

    def test_integrate_blocked_no_acceptance(self):
        ev, tmpdir = self._make_evaluator({
            "signal_sample.json": _minimal_signal_sample(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_integrate_blocked_prereq_fail(self):
        ev, tmpdir = self._make_evaluator({
            "acceptance_report.json": _minimal_acceptance(),
            "signal_sample.json": _minimal_signal_sample(),
        }, prev_status="BLOCKED")
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_integrate_verdict_dict_format(self):
        ev, tmpdir = self._make_evaluator({
            "acceptance_report.json": {
                "verdict": {"recommendation": "READY"},
                "checks": [],
                "blockers": [],
            },
            "signal_sample.json": _minimal_signal_sample(),
            "quickstart_result.json": {"status": "ok"},
        })
        try:
            result = ev.evaluate()
            verdict_check = [c for c in result["checks"]
                             if c["check_id"] == "CHK-INTG-2"][0]
            self.assertTrue(verdict_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_integrate_verdict_partial(self):
        ev, tmpdir = self._make_evaluator({
            "acceptance_report.json": {
                "verdict": {"recommendation": "PARTIAL"},
                "checks": [],
                "blockers": [],
            },
            "signal_sample.json": _minimal_signal_sample(),
            "quickstart_result.json": {"status": "ok"},
        })
        try:
            result = ev.evaluate()
            verdict_check = [c for c in result["checks"]
                             if c["check_id"] == "CHK-INTG-2"][0]
            self.assertTrue(verdict_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_integrate_signal_validation(self):
        """Signal sample must have required fields."""
        ev, tmpdir = self._make_evaluator({
            "acceptance_report.json": _minimal_acceptance(),
            "signal_sample.json": [{"symbol": "BTC"}],  # missing fields
        })
        try:
            result = ev.evaluate()
            sig_check = [c for c in result["checks"]
                         if c["check_id"] == "CHK-INTG-4"][0]
            self.assertFalse(sig_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_integrate_critical_blocker_in_acceptance(self):
        ev, tmpdir = self._make_evaluator({
            "acceptance_report.json": {
                "verdict": {"recommendation": "READY"},
                "checks": [],
                "blockers": [{"severity": "CRITICAL", "description": "bad"}],
            },
            "signal_sample.json": _minimal_signal_sample(),
            "quickstart_result.json": {"status": "ok"},
        })
        try:
            result = ev.evaluate()
            crit_check = [c for c in result["checks"]
                          if c["check_id"] == "CHK-INTG-7"][0]
            self.assertFalse(crit_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_integrate_checks_count(self):
        ev, tmpdir = self._make_evaluator({
            "acceptance_report.json": _minimal_acceptance(),
            "signal_sample.json": _minimal_signal_sample(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(len(result["checks"]), 7)
        finally:
            shutil.rmtree(tmpdir)

    def test_integrate_connectivity_fallback(self):
        """Connectivity PASS in acceptance substitutes for quickstart."""
        ev, tmpdir = self._make_evaluator({
            "acceptance_report.json": {
                "verdict": {"recommendation": "READY"},
                "checks": [{"name": "connectivity_check", "passed": True}],
                "blockers": [],
            },
            "signal_sample.json": _minimal_signal_sample(),
        })
        try:
            result = ev.evaluate()
            conn_check = [c for c in result["checks"]
                          if c["check_id"] == "CHK-INTG-6"][0]
            self.assertTrue(conn_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_integrate_source_artifacts(self):
        ev, tmpdir = self._make_evaluator({
            "acceptance_report.json": _minimal_acceptance(),
            "signal_sample.json": _minimal_signal_sample(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(len(result["source_artifacts"]), 3)
        finally:
            shutil.rmtree(tmpdir)


# ===========================================================================
# 7. TestMonitorEvaluator (10 tests)
# ===========================================================================
class TestMonitorEvaluator(unittest.TestCase):
    """Test the MONITOR stage evaluator."""

    def _make_evaluator(self, artifacts=None, prev_status="PASSED"):
        tmpdir = _make_tmpdir()
        if artifacts:
            for name, data in artifacts.items():
                _write_json(tmpdir, name, data)
        scanner = cl.ArtifactScanner(tmpdir)
        scanner.scan()
        evaluator = cl.MonitorEvaluator(scanner, prev_status=prev_status)
        return evaluator, tmpdir

    def test_monitor_passes(self):
        ev, tmpdir = self._make_evaluator({
            "drift_report.json": _minimal_drift(),
            "calibration_report.json": _minimal_calibration(),
            "resolved_signals.json": _minimal_resolved_signals(150),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "PASSED")
        finally:
            shutil.rmtree(tmpdir)

    def test_monitor_blocked_insufficient_signals(self):
        ev, tmpdir = self._make_evaluator({
            "drift_report.json": _minimal_drift(),
            "calibration_report.json": _minimal_calibration(),
            "resolved_signals.json": _minimal_resolved_signals(50),
        })
        try:
            result = ev.evaluate()
            sig_check = [c for c in result["checks"]
                         if c["check_id"] == "CHK-MNTR-1"][0]
            self.assertFalse(sig_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_monitor_drift_critical_fails(self):
        ev, tmpdir = self._make_evaluator({
            "drift_report.json": {"alert_severity": "CRITICAL",
                                  "detection_methods": [{"name": "CUSUM"}]},
            "calibration_report.json": _minimal_calibration(),
            "resolved_signals.json": _minimal_resolved_signals(150),
        })
        try:
            result = ev.evaluate()
            drift_check = [c for c in result["checks"]
                           if c["check_id"] == "CHK-MNTR-3"][0]
            self.assertFalse(drift_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_monitor_ece_above_threshold(self):
        ev, tmpdir = self._make_evaluator({
            "drift_report.json": _minimal_drift(),
            "calibration_report.json": {
                "ece": {"value": 0.25},
                "brier_score": 0.22,
                "per_symbol": {"BTC": {}},
            },
            "resolved_signals.json": _minimal_resolved_signals(150),
        })
        try:
            result = ev.evaluate()
            ece_check = [c for c in result["checks"]
                         if c["check_id"] == "CHK-MNTR-5"][0]
            self.assertFalse(ece_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_monitor_brier_above_threshold(self):
        ev, tmpdir = self._make_evaluator({
            "drift_report.json": _minimal_drift(),
            "calibration_report.json": {
                "ece": {"value": 0.10},
                "brier_score": 0.55,
                "per_symbol": {"BTC": {}},
            },
            "resolved_signals.json": _minimal_resolved_signals(150),
        })
        try:
            result = ev.evaluate()
            brier_check = [c for c in result["checks"]
                           if c["check_id"] == "CHK-MNTR-6"][0]
            self.assertFalse(brier_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_monitor_dict_ece_format(self):
        """ECE as dict with value key should be parsed correctly."""
        ev, tmpdir = self._make_evaluator({
            "drift_report.json": _minimal_drift(),
            "calibration_report.json": {
                "ece": {"value": 0.05},
                "brier_score": 0.22,
                "per_symbol": {"BTC": {}},
            },
            "resolved_signals.json": _minimal_resolved_signals(150),
        })
        try:
            result = ev.evaluate()
            ece_check = [c for c in result["checks"]
                         if c["check_id"] == "CHK-MNTR-5"][0]
            self.assertTrue(ece_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_monitor_detection_methods(self):
        ev, tmpdir = self._make_evaluator({
            "drift_report.json": {
                "alert_severity": "LOW",
                "detection_methods": [
                    {"name": "CUSUM", "triggered": False},
                    {"name": "SPRT", "triggered": False},
                ],
            },
            "calibration_report.json": _minimal_calibration(),
            "resolved_signals.json": _minimal_resolved_signals(150),
        })
        try:
            result = ev.evaluate()
            method_check = [c for c in result["checks"]
                            if c["check_id"] == "CHK-MNTR-8"][0]
            self.assertTrue(method_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_monitor_checks_count(self):
        ev, tmpdir = self._make_evaluator({
            "drift_report.json": _minimal_drift(),
            "calibration_report.json": _minimal_calibration(),
            "resolved_signals.json": _minimal_resolved_signals(150),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(len(result["checks"]), 8)
        finally:
            shutil.rmtree(tmpdir)

    def test_monitor_blocked_prereq_fail(self):
        ev, tmpdir = self._make_evaluator({
            "drift_report.json": _minimal_drift(),
            "calibration_report.json": _minimal_calibration(),
            "resolved_signals.json": _minimal_resolved_signals(150),
        }, prev_status="BLOCKED")
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_monitor_source_artifacts(self):
        ev, tmpdir = self._make_evaluator({
            "drift_report.json": _minimal_drift(),
            "calibration_report.json": _minimal_calibration(),
            "resolved_signals.json": _minimal_resolved_signals(150),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(len(result["source_artifacts"]), 2)
        finally:
            shutil.rmtree(tmpdir)


# ===========================================================================
# 8. TestTrustEvaluator (12 tests)
# ===========================================================================
class TestTrustEvaluator(unittest.TestCase):
    """Test the TRUST stage evaluator."""

    def _make_evaluator(self, artifacts=None, prev_status="PASSED"):
        tmpdir = _make_tmpdir()
        if artifacts:
            for name, data in artifacts.items():
                _write_json(tmpdir, name, data)
        scanner = cl.ArtifactScanner(tmpdir)
        scanner.scan()
        evaluator = cl.TrustEvaluator(scanner, prev_status=prev_status)
        return evaluator, tmpdir

    def test_trust_passes_all_artifacts(self):
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": _minimal_backtest(),
            "experience_report.json": _minimal_experience(),
            "integration_scorecard.json": _minimal_scorecard(),
            "forensic_report.json": _minimal_forensic(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "PASSED")
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_blocked_missing_backtest(self):
        ev, tmpdir = self._make_evaluator({
            "experience_report.json": _minimal_experience(),
            "integration_scorecard.json": _minimal_scorecard(),
            "forensic_report.json": _minimal_forensic(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_blocked_missing_experience(self):
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": _minimal_backtest(),
            "integration_scorecard.json": _minimal_scorecard(),
            "forensic_report.json": _minimal_forensic(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_blocked_missing_scorecard(self):
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": _minimal_backtest(),
            "experience_report.json": _minimal_experience(),
            "forensic_report.json": _minimal_forensic(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_blocked_missing_forensic(self):
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": _minimal_backtest(),
            "experience_report.json": _minimal_experience(),
            "integration_scorecard.json": _minimal_scorecard(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_dict_verdict_format(self):
        """Backtest verdict as dict with decision key."""
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": {
                "verdict": {"decision": "ADOPT"},
                "strategies": {"s1": {"metrics": {"accuracy": 60.0}}},
            },
            "experience_report.json": _minimal_experience(),
            "integration_scorecard.json": _minimal_scorecard(),
            "forensic_report.json": _minimal_forensic(),
        })
        try:
            result = ev.evaluate()
            bt_check = [c for c in result["checks"]
                        if c["check_id"] == "CHK-TRST-2"][0]
            self.assertTrue(bt_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_strategies_as_dict(self):
        """Strategies in dict format with metrics sub-dict."""
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": {
                "verdict": {"decision": "ADOPT"},
                "strategies": {
                    "follow_all": {"metrics": {"accuracy": 52.0}},
                    "high_conf": {"metrics": {"accuracy": 56.04}},
                },
            },
            "experience_report.json": _minimal_experience(),
            "integration_scorecard.json": _minimal_scorecard(),
            "forensic_report.json": _minimal_forensic(),
        })
        try:
            result = ev.evaluate()
            acc_check = [c for c in result["checks"]
                         if c["check_id"] == "CHK-TRST-3"][0]
            self.assertTrue(acc_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_accuracy_below_50_fails(self):
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": {
                "verdict": {"decision": "ADOPT"},
                "best_accuracy": 45.0,
            },
            "experience_report.json": _minimal_experience(),
            "integration_scorecard.json": _minimal_scorecard(),
            "forensic_report.json": _minimal_forensic(),
        })
        try:
            result = ev.evaluate()
            acc_check = [c for c in result["checks"]
                         if c["check_id"] == "CHK-TRST-3"][0]
            self.assertFalse(acc_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_satisfaction_mixed(self):
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": _minimal_backtest(),
            "experience_report.json": {
                "satisfaction_verdict": {"verdict": "MIXED"},
            },
            "integration_scorecard.json": _minimal_scorecard(),
            "forensic_report.json": _minimal_forensic(),
        })
        try:
            result = ev.evaluate()
            sat_check = [c for c in result["checks"]
                         if c["check_id"] == "CHK-TRST-5"][0]
            self.assertTrue(sat_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_checks_count(self):
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": _minimal_backtest(),
            "experience_report.json": _minimal_experience(),
            "integration_scorecard.json": _minimal_scorecard(),
            "forensic_report.json": _minimal_forensic(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(len(result["checks"]), 10)
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_blocked_prereq_fail(self):
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": _minimal_backtest(),
            "experience_report.json": _minimal_experience(),
            "integration_scorecard.json": _minimal_scorecard(),
            "forensic_report.json": _minimal_forensic(),
        }, prev_status="BLOCKED")
        try:
            result = ev.evaluate()
            self.assertEqual(result["status"], "BLOCKED")
        finally:
            shutil.rmtree(tmpdir)

    def test_trust_source_artifacts(self):
        ev, tmpdir = self._make_evaluator({
            "backtest_report.json": _minimal_backtest(),
            "experience_report.json": _minimal_experience(),
            "integration_scorecard.json": _minimal_scorecard(),
            "forensic_report.json": _minimal_forensic(),
        })
        try:
            result = ev.evaluate()
            self.assertEqual(len(result["source_artifacts"]), 4)
        finally:
            shutil.rmtree(tmpdir)


# ===========================================================================
# 9. TestLadderRunner (12 tests)
# ===========================================================================
class TestLadderRunner(unittest.TestCase):
    """Test the LadderRunner orchestrator."""

    def test_full_run_with_all_artifacts(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir)
            self.assertEqual(report["progress_summary"]["stages_passed"], 5)
            self.assertEqual(report["progress_summary"]["grade"], "A")
        finally:
            shutil.rmtree(tmpdir)

    def test_empty_dir_discover_blocked(self):
        tmpdir = _make_tmpdir()
        try:
            report = _run_full_report(tmpdir)
            self.assertEqual(report["current_stage"], "DISCOVER")
            self.assertEqual(report["stages"]["DISCOVER"]["status"], "BLOCKED")
            self.assertEqual(report["progress_summary"]["stages_passed"], 0)
            self.assertEqual(report["progress_summary"]["grade"], "F")
        finally:
            shutil.rmtree(tmpdir)

    def test_partial_artifacts_stops_at_evaluate(self):
        tmpdir = _make_tmpdir()
        try:
            _write_json(tmpdir, "discovery_result.json", _minimal_discovery())
            report = _run_full_report(tmpdir)
            self.assertEqual(report["stages"]["DISCOVER"]["status"], "PASSED")
            self.assertEqual(report["stages"]["EVALUATE"]["status"], "BLOCKED")
            self.assertEqual(report["current_stage"], "DISCOVER")
            self.assertEqual(report["progress_summary"]["stages_passed"], 1)
            self.assertEqual(report["progress_summary"]["grade"], "F")
        finally:
            shutil.rmtree(tmpdir)

    def test_partial_artifacts_stops_at_integrate(self):
        tmpdir = _make_tmpdir()
        try:
            _write_json(tmpdir, "discovery_result.json", _minimal_discovery())
            _write_json(tmpdir, "health_report.json", _minimal_health())
            _write_json(tmpdir, "trust_evaluation.json", _minimal_trust())
            report = _run_full_report(tmpdir)
            self.assertEqual(report["stages"]["DISCOVER"]["status"], "PASSED")
            self.assertEqual(report["stages"]["EVALUATE"]["status"], "PASSED")
            self.assertEqual(report["stages"]["INTEGRATE"]["status"], "BLOCKED")
            self.assertEqual(report["current_stage"], "EVALUATE")
            self.assertEqual(report["progress_summary"]["stages_passed"], 2)
            self.assertEqual(report["progress_summary"]["grade"], "D")
        finally:
            shutil.rmtree(tmpdir)

    def test_previous_hash_sets_chain(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            prev = "a" * 64
            report = _run_full_report(tmpdir, previous_hash=prev)
            self.assertEqual(report["hash_chain"]["previous_report_hash"], prev)
            self.assertEqual(report["hash_chain"]["chain_length"], 2)
        finally:
            shutil.rmtree(tmpdir)

    def test_no_previous_hash(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir)
            self.assertIsNone(report["hash_chain"]["previous_report_hash"])
            self.assertEqual(report["hash_chain"]["chain_length"], 1)
        finally:
            shutil.rmtree(tmpdir)

    def test_report_has_schema_version(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir)
            self.assertEqual(report["schema_version"], "1.0.0")
        finally:
            shutil.rmtree(tmpdir)

    def test_report_has_meta(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir, producer_id="sendoeth")
            self.assertEqual(report["meta"]["producer_id"], "sendoeth")
            self.assertRegex(report["meta"]["report_id"], r"^CAL-[A-F0-9]{12}$")
        finally:
            shutil.rmtree(tmpdir)

    def test_report_has_all_stages(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir)
            for sid in cl.STAGE_ORDER:
                self.assertIn(sid, report["stages"])
        finally:
            shutil.rmtree(tmpdir)

    def test_next_command_null_when_all_passed(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir)
            self.assertIsNone(report["next_command"])
        finally:
            shutil.rmtree(tmpdir)

    def test_next_command_set_when_blocked(self):
        tmpdir = _make_tmpdir()
        try:
            report = _run_full_report(tmpdir)
            self.assertIsNotNone(report["next_command"])
            self.assertIsInstance(report["next_command"], str)
        finally:
            shutil.rmtree(tmpdir)

    def test_report_has_limitations(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir)
            self.assertIsInstance(report["limitations"], list)
            self.assertTrue(len(report["limitations"]) >= 4)
        finally:
            shutil.rmtree(tmpdir)


# ===========================================================================
# 10. TestHashChainBuilder (8 tests)
# ===========================================================================
class TestHashChainBuilder(unittest.TestCase):
    """Test the HashChainBuilder."""

    def _make_report(self, previous_hash=None):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            return _run_full_report(tmpdir, previous_hash=previous_hash), tmpdir
        except Exception:
            shutil.rmtree(tmpdir)
            raise

    def test_content_hash_is_hex64(self):
        report, tmpdir = self._make_report()
        try:
            self.assertRegex(report["meta"]["content_hash"],
                             r"^[0-9a-f]{64}$")
        finally:
            shutil.rmtree(tmpdir)

    def test_report_hash_is_hex64(self):
        report, tmpdir = self._make_report()
        try:
            self.assertRegex(report["hash_chain"]["report_hash"],
                             r"^[0-9a-f]{64}$")
        finally:
            shutil.rmtree(tmpdir)

    def test_content_hash_recomputation(self):
        """Verify content hash can be recomputed using zero-then-fill."""
        report, tmpdir = self._make_report()
        try:
            reported = report["meta"]["content_hash"]
            computed = vl._compute_content_hash(report)
            self.assertEqual(reported, computed)
        finally:
            shutil.rmtree(tmpdir)

    def test_hash_determinism(self):
        """Same inputs should produce same hashes."""
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            # We can't test exact equality because timestamps differ,
            # but we can test that the hash chain structure is consistent
            report = _run_full_report(tmpdir)
            self.assertNotEqual(report["meta"]["content_hash"], "0" * 64)
            self.assertNotEqual(report["hash_chain"]["report_hash"], "0" * 64)
        finally:
            shutil.rmtree(tmpdir)

    def test_previous_hash_in_chain(self):
        prev = "b" * 64
        report, tmpdir = self._make_report(previous_hash=prev)
        try:
            self.assertEqual(report["hash_chain"]["previous_report_hash"], prev)
        finally:
            shutil.rmtree(tmpdir)

    def test_no_previous_hash_is_null(self):
        report, tmpdir = self._make_report(previous_hash=None)
        try:
            self.assertIsNone(report["hash_chain"]["previous_report_hash"])
        finally:
            shutil.rmtree(tmpdir)

    def test_stage_hashes_present(self):
        report, tmpdir = self._make_report()
        try:
            sh = report["hash_chain"]["stage_hashes"]
            for sid in cl.STAGE_ORDER:
                self.assertIn(sid, sh)
                self.assertRegex(sh[sid], r"^[0-9a-f]{64}$")
        finally:
            shutil.rmtree(tmpdir)

    def test_algorithm_is_sha256(self):
        report, tmpdir = self._make_report()
        try:
            self.assertEqual(report["hash_chain"]["algorithm"], "SHA-256")
        finally:
            shutil.rmtree(tmpdir)


# ===========================================================================
# 11. TestVerifier (12 tests)
# ===========================================================================
class TestVerifier(unittest.TestCase):
    """Test the LadderVerifier against valid and tampered reports."""

    def _make_valid_report(self):
        tmpdir = _make_tmpdir()
        _write_all_artifacts(tmpdir)
        report = _run_full_report(tmpdir)
        return report, tmpdir

    def test_valid_report_high_pass_rate(self):
        report, tmpdir = self._make_valid_report()
        try:
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            self.assertGreaterEqual(s["pct"], 95.0,
                                    "Valid report should pass 95%+ checks")
        finally:
            shutil.rmtree(tmpdir)

    def test_valid_report_grade_a_or_b(self):
        report, tmpdir = self._make_valid_report()
        try:
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            self.assertIn(s["grade"], ("A", "B"))
        finally:
            shutil.rmtree(tmpdir)

    def test_tampered_content_hash_fails(self):
        report, tmpdir = self._make_valid_report()
        try:
            report["meta"]["content_hash"] = "0" * 64
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            failed_names = [n for (c, n, p, d) in v.results if not p]
            self.assertTrue(
                any("content_hash" in n for n in failed_names),
                "Tampered content hash should be caught"
            )
        finally:
            shutil.rmtree(tmpdir)

    def test_tampered_stage_status_fails(self):
        report, tmpdir = self._make_valid_report()
        try:
            # Make DISCOVER say BLOCKED but keep everything else
            report["stages"]["DISCOVER"]["status"] = "BLOCKED"
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            self.assertGreater(s["failed"], 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_missing_schema_version_fails(self):
        report, tmpdir = self._make_valid_report()
        try:
            del report["schema_version"]
            v = vl.LadderVerifier(report)
            v.verify()
            failed_names = [n for (c, n, p, d) in v.results if not p]
            self.assertTrue(
                any("schema_version" in n for n in failed_names)
            )
        finally:
            shutil.rmtree(tmpdir)

    def test_empty_report_many_failures(self):
        v = vl.LadderVerifier({})
        v.verify()
        s = v.summary()
        self.assertGreater(s["failed"], 5)

    def test_verifier_summary_keys(self):
        report, tmpdir = self._make_valid_report()
        try:
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            for key in ("total", "passed", "failed", "pct", "grade", "categories"):
                self.assertIn(key, s)
        finally:
            shutil.rmtree(tmpdir)

    def test_verifier_categories_present(self):
        report, tmpdir = self._make_valid_report()
        try:
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            expected_cats = [
                "structure", "version", "meta", "stage_structure",
                "stage_ordering", "check_id_format",
            ]
            for cat in expected_cats:
                self.assertIn(cat, s["categories"],
                              "Missing category: {}".format(cat))
        finally:
            shutil.rmtree(tmpdir)

    def test_verifier_results_are_tuples(self):
        report, tmpdir = self._make_valid_report()
        try:
            v = vl.LadderVerifier(report)
            v.verify()
            for item in v.results:
                self.assertEqual(len(item), 4)
                cat, name, passed, detail = item
                self.assertIsInstance(cat, str)
                self.assertIsInstance(name, str)
                self.assertIsInstance(passed, bool)
                self.assertIsInstance(detail, str)
        finally:
            shutil.rmtree(tmpdir)

    def test_verifier_with_artifacts_dir(self):
        report, tmpdir = self._make_valid_report()
        try:
            v = vl.LadderVerifier(report, artifacts_dir=tmpdir)
            v.verify()
            s = v.summary()
            # Should have artifact checks
            self.assertIn("artifacts", s["categories"])
        finally:
            shutil.rmtree(tmpdir)

    def test_wrong_generator_version_caught(self):
        report, tmpdir = self._make_valid_report()
        try:
            report["meta"]["generator_version"] = "2.0.0"
            v = vl.LadderVerifier(report)
            v.verify()
            failed_names = [n for (c, n, p, d) in v.results if not p]
            self.assertTrue(
                any("generator_version" in n for n in failed_names)
            )
        finally:
            shutil.rmtree(tmpdir)

    def test_total_checks_count(self):
        report, tmpdir = self._make_valid_report()
        try:
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            self.assertGreater(s["total"], 100,
                               "Verifier should run 100+ checks")
        finally:
            shutil.rmtree(tmpdir)


# ===========================================================================
# 12. TestVerifierCategories (8 tests)
# ===========================================================================
class TestVerifierCategories(unittest.TestCase):
    """Test specific verifier category failure detection."""

    def _make_valid_report(self):
        tmpdir = _make_tmpdir()
        _write_all_artifacts(tmpdir)
        report = _run_full_report(tmpdir)
        return report, tmpdir

    def test_structure_catches_extra_field(self):
        report, tmpdir = self._make_valid_report()
        try:
            report["extra_field"] = "bad"
            v = vl.LadderVerifier(report)
            v.verify()
            structure_fails = [
                n for (c, n, p, d) in v.results
                if c == "structure" and not p
            ]
            self.assertTrue(len(structure_fails) > 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_hash_chain_catches_bad_algorithm(self):
        report, tmpdir = self._make_valid_report()
        try:
            report["hash_chain"]["algorithm"] = "MD5"
            v = vl.LadderVerifier(report)
            v.verify()
            hc_fails = [
                n for (c, n, p, d) in v.results
                if c == "hash_chain" and not p
            ]
            self.assertTrue(
                any("sha256" in n.lower() or "algorithm" in n.lower()
                    for n in hc_fails)
            )
        finally:
            shutil.rmtree(tmpdir)

    def test_limitations_catches_missing_bias(self):
        report, tmpdir = self._make_valid_report()
        try:
            # Deep copy to avoid mutating shared cl.LIMITATIONS reference
            report = copy.deepcopy(report)
            report["limitations"][0]["bias_direction"] = "INVALID"
            v = vl.LadderVerifier(report)
            v.verify()
            lim_fails = [
                n for (c, n, p, d) in v.results
                if c == "limitations" and not p
            ]
            self.assertTrue(len(lim_fails) > 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_progress_summary_catches_wrong_count(self):
        report, tmpdir = self._make_valid_report()
        try:
            report["progress_summary"]["stages_passed"] = 99
            v = vl.LadderVerifier(report)
            v.verify()
            ps_fails = [
                n for (c, n, p, d) in v.results
                if c == "progress_summary_logic" and not p
            ]
            self.assertTrue(len(ps_fails) > 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_meta_catches_bad_report_id(self):
        report, tmpdir = self._make_valid_report()
        try:
            report["meta"]["report_id"] = "INVALID-ID"
            v = vl.LadderVerifier(report)
            v.verify()
            meta_fails = [
                n for (c, n, p, d) in v.results
                if c == "meta" and not p
            ]
            self.assertTrue(len(meta_fails) > 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_receipt_integrity_catches_bad_hash(self):
        report, tmpdir = self._make_valid_report()
        try:
            report["stages"]["DISCOVER"]["receipt"]["stage_hash"] = "xyz"
            v = vl.LadderVerifier(report)
            v.verify()
            ri_fails = [
                n for (c, n, p, d) in v.results
                if c == "receipt_integrity" and not p
            ]
            self.assertTrue(len(ri_fails) > 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_stage_ordering_catches_inconsistency(self):
        report, tmpdir = self._make_valid_report()
        try:
            # Make EVALUATE PASSED but DISCOVER NOT_REACHED -> ordering violation
            report["stages"]["DISCOVER"]["status"] = "NOT_REACHED"
            report["stages"]["DISCOVER"]["receipt"]["passed"] = False
            v = vl.LadderVerifier(report)
            v.verify()
            so_fails = [
                n for (c, n, p, d) in v.results
                if c == "stage_ordering" and not p
            ]
            self.assertTrue(len(so_fails) > 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_cross_stage_consistency_all_pass(self):
        report, tmpdir = self._make_valid_report()
        try:
            v = vl.LadderVerifier(report)
            v.verify()
            cs_fails = [
                n for (c, n, p, d) in v.results
                if c == "cross_stage_consistency" and not p
            ]
            self.assertEqual(len(cs_fails), 0,
                             "Valid report should have 0 cross-stage failures")
        finally:
            shutil.rmtree(tmpdir)


# ===========================================================================
# 13. TestIntegration (10 tests)
# ===========================================================================
class TestIntegration(unittest.TestCase):
    """End-to-end generate->verify integration tests."""

    def test_full_generate_verify_cycle(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir)
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            self.assertIn(s["grade"], ("A", "B"))
        finally:
            shutil.rmtree(tmpdir)

    def test_partial_generate_verify(self):
        tmpdir = _make_tmpdir()
        try:
            _write_json(tmpdir, "discovery_result.json", _minimal_discovery())
            report = _run_full_report(tmpdir)
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            # Partial report should still have reasonable structure
            self.assertGreater(s["passed"], 50)
        finally:
            shutil.rmtree(tmpdir)

    def test_empty_generate_verify(self):
        tmpdir = _make_tmpdir()
        try:
            report = _run_full_report(tmpdir)
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            # Even empty should have valid structure
            self.assertGreater(s["passed"], 50)
        finally:
            shutil.rmtree(tmpdir)

    def test_generate_verify_with_artifacts_dir(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir)
            v = vl.LadderVerifier(report, artifacts_dir=tmpdir)
            v.verify()
            s = v.summary()
            self.assertIn("artifacts", s["categories"])
        finally:
            shutil.rmtree(tmpdir)

    def test_generate_verify_chain_continuity(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            prev = "c" * 64
            report = _run_full_report(tmpdir, previous_hash=prev)
            v = vl.LadderVerifier(report)
            v.verify()
            s = v.summary()
            self.assertIn(s["grade"], ("A", "B"))
        finally:
            shutil.rmtree(tmpdir)

    def test_report_json_round_trip(self):
        """Serialize to JSON and back, then verify."""
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir)
            json_str = json.dumps(report, indent=2, sort_keys=False)
            report2 = json.loads(json_str)
            v = vl.LadderVerifier(report2)
            v.verify()
            s = v.summary()
            self.assertIn(s["grade"], ("A", "B"))
        finally:
            shutil.rmtree(tmpdir)

    def test_content_hash_survives_round_trip(self):
        tmpdir = _make_tmpdir()
        try:
            _write_all_artifacts(tmpdir)
            report = _run_full_report(tmpdir)
            original_hash = report["meta"]["content_hash"]
            json_str = json.dumps(report, indent=2, sort_keys=False)
            report2 = json.loads(json_str)
            computed = vl._compute_content_hash(report2)
            self.assertEqual(original_hash, computed)
        finally:
            shutil.rmtree(tmpdir)

    def test_stages_3_passed_grade_c(self):
        """Exactly 3 stages passed should give grade C."""
        tmpdir = _make_tmpdir()
        try:
            _write_json(tmpdir, "discovery_result.json", _minimal_discovery())
            _write_json(tmpdir, "health_report.json", _minimal_health())
            _write_json(tmpdir, "trust_evaluation.json", _minimal_trust())
            _write_json(tmpdir, "acceptance_report.json", _minimal_acceptance())
            _write_json(tmpdir, "signal_sample.json", _minimal_signal_sample())
            _write_json(tmpdir, "quickstart_result.json", {"status": "ok"})
            report = _run_full_report(tmpdir)
            # DISCOVER, EVALUATE, INTEGRATE should pass, MONITOR should block
            self.assertEqual(report["progress_summary"]["stages_passed"], 3)
            self.assertEqual(report["progress_summary"]["grade"], "C")
        finally:
            shutil.rmtree(tmpdir)

    def test_stages_4_passed_grade_b(self):
        """Exactly 4 stages passed should give grade B."""
        tmpdir = _make_tmpdir()
        try:
            _write_json(tmpdir, "discovery_result.json", _minimal_discovery())
            _write_json(tmpdir, "health_report.json", _minimal_health())
            _write_json(tmpdir, "trust_evaluation.json", _minimal_trust())
            _write_json(tmpdir, "acceptance_report.json", _minimal_acceptance())
            _write_json(tmpdir, "signal_sample.json", _minimal_signal_sample())
            _write_json(tmpdir, "quickstart_result.json", {"status": "ok"})
            _write_json(tmpdir, "drift_report.json", _minimal_drift())
            _write_json(tmpdir, "calibration_report.json", _minimal_calibration())
            _write_json(tmpdir, "resolved_signals.json",
                        _minimal_resolved_signals(150))
            report = _run_full_report(tmpdir)
            self.assertEqual(report["progress_summary"]["stages_passed"], 4)
            self.assertEqual(report["progress_summary"]["grade"], "B")
        finally:
            shutil.rmtree(tmpdir)

    def test_real_artifacts_if_available(self):
        """Run full cycle with real consumer_artifacts if present."""
        if not os.path.isdir(ARTIFACTS_DIR):
            self.skipTest("Real artifacts dir not found")
        report = _run_full_report(ARTIFACTS_DIR, producer_id="sendoeth")
        v = vl.LadderVerifier(report, artifacts_dir=ARTIFACTS_DIR)
        v.verify()
        s = v.summary()
        self.assertGreater(s["total"], 100)
        self.assertIn(s["grade"], ("A", "B"))


# ===========================================================================
# 14. TestEdgeCases (8 tests)
# ===========================================================================
class TestEdgeCases(unittest.TestCase):
    """Test edge cases: all passed, all blocked, empty, null verdicts."""

    def test_make_not_reached(self):
        result = cl.StageEvaluator.make_not_reached("TRUST")
        self.assertEqual(result["stage_id"], "TRUST")
        self.assertEqual(result["status"], "NOT_REACHED")
        self.assertEqual(result["checks"], [])
        self.assertFalse(result["receipt"]["passed"])

    def test_all_stages_blocked_after_discover(self):
        tmpdir = _make_tmpdir()
        try:
            report = _run_full_report(tmpdir)
            # DISCOVER blocked -> everything after is NOT_REACHED
            for sid in ["EVALUATE", "INTEGRATE", "MONITOR", "TRUST"]:
                self.assertEqual(report["stages"][sid]["status"], "NOT_REACHED")
        finally:
            shutil.rmtree(tmpdir)

    def test_null_verdict_in_trust(self):
        """Trust evaluation with null/missing verdict."""
        tmpdir = _make_tmpdir()
        try:
            _write_json(tmpdir, "trust_evaluation.json", {
                "verdict": None,
                "risk_factors": [],
            })
            scanner = cl.ArtifactScanner(tmpdir)
            scanner.scan()
            ev = cl.EvaluateEvaluator(scanner, prev_status="PASSED")
            result = ev.evaluate()
            # Should not crash; verdict check should fail
            verdict_check = [c for c in result["checks"]
                             if c["check_id"] == "CHK-EVAL-5"][0]
            self.assertFalse(verdict_check["passed"])
        finally:
            shutil.rmtree(tmpdir)

    def test_empty_artifacts_dir(self):
        tmpdir = _make_tmpdir()
        try:
            scanner = cl.ArtifactScanner(tmpdir)
            result = scanner.scan()
            self.assertEqual(len([v for v in result.values() if v is not None]), 0)
        finally:
            shutil.rmtree(tmpdir)

    def test_grade_map_all_values(self):
        """GRADE_MAP covers 0-5."""
        for n in range(6):
            self.assertIn(n, cl.GRADE_MAP)

    def test_stage_order_count(self):
        self.assertEqual(len(cl.STAGE_ORDER), 5)

    def test_stage_abbrev_complete(self):
        for sid in cl.STAGE_ORDER:
            self.assertIn(sid, cl.STAGE_ABBREV)

    def test_verifier_helpers(self):
        """Test verifier helper functions."""
        self.assertTrue(vl._is_hex64("a" * 64))
        self.assertFalse(vl._is_hex64("a" * 63))
        self.assertFalse(vl._is_hex64("G" * 64))
        self.assertTrue(vl._is_iso_datetime("2026-04-27T00:00:00Z"))
        self.assertFalse(vl._is_iso_datetime("not-a-date"))
        self.assertEqual(vl._grade_letter(99.0), "A")
        self.assertEqual(vl._grade_letter(95.0), "B")
        self.assertEqual(vl._grade_letter(80.0), "C")
        self.assertEqual(vl._grade_letter(60.0), "D")
        self.assertEqual(vl._grade_letter(40.0), "F")


# ===========================================================================
# 15. TestStageEvaluatorBase (5 bonus tests)
# ===========================================================================
class TestStageEvaluatorBase(unittest.TestCase):
    """Test StageEvaluator base class methods."""

    def setUp(self):
        self.tmpdir = _make_tmpdir()
        self.scanner = cl.ArtifactScanner(self.tmpdir)
        self.scanner.scan()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_mk_check_format(self):
        ev = cl.DiscoverEvaluator(self.scanner, prev_status=None)
        check = ev._mk_check(1, "Test check", True, "detail text", "TestTool")
        self.assertEqual(check["check_id"], "CHK-DISC-1")
        self.assertTrue(check["passed"])

    def test_mk_blocker_format(self):
        ev = cl.EvaluateEvaluator(self.scanner, prev_status="PASSED")
        blocker = ev._mk_blocker(1, "HIGH", "Some issue")
        self.assertEqual(blocker["blocker_id"], "BLK-EVAL-1")
        self.assertEqual(blocker["severity"], "HIGH")
        self.assertEqual(blocker["stage_blocked"], "EVALUATE")

    def test_mk_remediation_format(self):
        ev = cl.IntegrateEvaluator(self.scanner, prev_status="PASSED")
        rem = ev._mk_remediation(1, "python3 fix.py", "Fix it", "BLK-INTG-1")
        self.assertEqual(rem["remediation_id"], "REM-INTG-1")
        self.assertEqual(rem["resolves_blocker"], "BLK-INTG-1")

    def test_mk_prerequisite_format(self):
        ev = cl.MonitorEvaluator(self.scanner, prev_status="PASSED")
        prereq = ev._mk_prerequisite(1, "Prior stage passed", True)
        self.assertEqual(prereq["id"], "PRE-MNTR-1")
        self.assertTrue(prereq["met"])

    def test_mk_criterion_format(self):
        ev = cl.TrustEvaluator(self.scanner, prev_status="PASSED")
        crit = ev._mk_criterion(1, "All good", True, "Evidence text")
        self.assertEqual(crit["id"], "CRI-TRST-1")
        self.assertEqual(crit["evidence"], "Evidence text")


# ===========================================================================
# 16. TestConstants (4 bonus tests)
# ===========================================================================
class TestConstants(unittest.TestCase):
    """Test module-level constants."""

    def test_generator_version(self):
        self.assertEqual(cl.GENERATOR_VERSION, "1.0.0")

    def test_schema_version(self):
        self.assertEqual(cl.SCHEMA_VERSION, "1.0.0")

    def test_limitations_count(self):
        self.assertGreaterEqual(len(cl.LIMITATIONS), 4)

    def test_limitations_structure(self):
        for lim in cl.LIMITATIONS:
            self.assertIn("id", lim)
            self.assertIn("description", lim)
            self.assertIn("bias_direction", lim)
            self.assertIn("bias_magnitude", lim)
            self.assertIn(lim["bias_direction"],
                          {"OVERSTATED_READINESS", "UNDERSTATED_READINESS",
                           "INDETERMINATE"})


if __name__ == "__main__":
    unittest.main()
