#!/usr/bin/env python3
"""
Consumer Adoption Ladder Runner (climb_ladder.py)

Evaluates a consumer's adoption progress through 5 sequential stages:
  DISCOVER -> EVALUATE -> INTEGRATE -> MONITOR -> TRUST

Takes a directory of consumer artifacts (JSON files from various PF tools)
and stops at the first unmet gate, telling the consumer exactly what to do next.

Zero external dependencies — Python 3 stdlib only.

Usage:
    python3 climb_ladder.py \
        --artifacts ./consumer_artifacts/ \
        --producer sendoeth \
        -o adoption_ladder_report.json \
        --summary
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GENERATOR_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"

STAGE_ORDER = ["DISCOVER", "EVALUATE", "INTEGRATE", "MONITOR", "TRUST"]

STAGE_ABBREV = {
    "DISCOVER": "DISC",
    "EVALUATE": "EVAL",
    "INTEGRATE": "INTG",
    "MONITOR": "MNTR",
    "TRUST": "TRST",
}

GRADE_MAP = {5: "A", 4: "B", 3: "C", 2: "D", 1: "F", 0: "F"}

REPO_URLS = {
    "discovery-protocol": "https://github.com/sendoeth/pf-discovery-protocol",
    "health-monitor": "https://github.com/sendoeth/pf-health-monitor",
    "trust-gateway": "https://github.com/sendoeth/pf-trust-gateway",
    "acceptance-test": "https://github.com/sendoeth/pf-acceptance-test",
    "consumer-quickstart": "https://github.com/sendoeth/pf-consumer-quickstart",
    "signal-schema": "https://github.com/sendoeth/pf-signal-schema",
    "consumer-drift-monitor": "https://github.com/sendoeth/pf-consumer-drift-monitor",
    "consumer-calibrator": "https://github.com/sendoeth/pf-consumer-calibrator",
    "consumer-backtest": "https://github.com/sendoeth/pf-consumer-backtest",
    "experience-replay": "https://github.com/sendoeth/pf-experience-replay",
    "integration-scorecard": "https://github.com/sendoeth/pf-integration-scorecard",
    "signal-forensics": "https://github.com/sendoeth/pf-signal-forensics",
}

LIMITATIONS = [
    {
        "id": "L01",
        "description": (
            "Artifact file detection by filename only — misnamed files "
            "silently missed."
        ),
        "bias_direction": "UNDERSTATED_READINESS",
        "bias_magnitude": "MODERATE",
    },
    {
        "id": "L02",
        "description": (
            "No live endpoint testing — checks static artifacts only, "
            "not live API connectivity."
        ),
        "bias_direction": "OVERSTATED_READINESS",
        "bias_magnitude": "MODERATE",
    },
    {
        "id": "L03",
        "description": (
            "Single snapshot — adoption ladder reflects a point-in-time, "
            "not continuous monitoring."
        ),
        "bias_direction": "INDETERMINATE",
        "bias_magnitude": "LOW",
    },
    {
        "id": "L04",
        "description": (
            "Threshold sensitivity — grade boundaries (health C, ECE 0.20, "
            "accuracy 50%) are conventions not proven optimal."
        ),
        "bias_direction": "INDETERMINATE",
        "bias_magnitude": "MODERATE",
    },
    {
        "id": "L05",
        "description": (
            "Sequential gating — a failure in DISCOVER blocks all subsequent "
            "stages, even if later-stage artifacts are present and healthy."
        ),
        "bias_direction": "UNDERSTATED_READINESS",
        "bias_magnitude": "LOW",
    },
    {
        "id": "L06",
        "description": (
            "Synthetic-only coverage — stage checks validate structure and "
            "thresholds, not end-to-end signal consumption."
        ),
        "bias_direction": "OVERSTATED_READINESS",
        "bias_magnitude": "HIGH",
    },
]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _sha256(data):
    """Return lowercase hex SHA-256 of *data* (bytes or str)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _now_iso():
    """ISO-8601 timestamp in UTC with Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _report_id():
    """Generate CAL-XXXXXXXXXXXX (12 uppercase hex chars from timestamp hash)."""
    raw = _sha256(str(datetime.now(timezone.utc).timestamp()))
    return "CAL-" + raw[:12].upper()


def _round6(val):
    """Round a float to 6 decimal places."""
    if isinstance(val, float):
        return round(val, 6)
    return val


def _safe_get(d, *keys, default=None):
    """Traverse nested dict safely."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur


def _grade_ord(g):
    """Convert letter grade to ordinal for comparison (A=0, F=5)."""
    return {"A": 0, "B": 1, "C": 2, "D": 3, "F": 5}.get(str(g).upper(), 5)


# ---------------------------------------------------------------------------
# ArtifactScanner
# ---------------------------------------------------------------------------

class ArtifactScanner:
    """Scans an artifacts directory for known filenames, returns parsed JSON."""

    KNOWN_FILES = [
        "discovery_result.json",
        "registry.json",
        "health_report.json",
        "trust_evaluation.json",
        "acceptance_report.json",
        "quickstart_result.json",
        "signal_sample.json",
        "drift_report.json",
        "calibration_report.json",
        "resolved_signals.json",
        "backtest_report.json",
        "experience_report.json",
        "integration_scorecard.json",
        "forensic_report.json",
    ]

    def __init__(self, artifacts_dir):
        self.artifacts_dir = os.path.abspath(artifacts_dir)
        self._cache = {}
        self._raw_cache = {}

    def scan(self):
        """Load all known files. Returns dict {name: parsed_json | None}."""
        for fname in self.KNOWN_FILES:
            fpath = os.path.join(self.artifacts_dir, fname)
            if os.path.isfile(fpath):
                try:
                    raw = open(fpath, "r", encoding="utf-8").read()
                    self._raw_cache[fname] = raw
                    self._cache[fname] = json.loads(raw)
                except (json.JSONDecodeError, OSError):
                    self._cache[fname] = None
                    self._raw_cache[fname] = ""
            else:
                self._cache[fname] = None
                self._raw_cache[fname] = ""
        return self._cache

    def get(self, name):
        """Return parsed JSON for an artifact or None."""
        return self._cache.get(name)

    def raw(self, name):
        """Return raw file content (str) for hashing, or empty string."""
        return self._raw_cache.get(name, "")

    def exists(self, name):
        """True if artifact was found and parsed successfully."""
        return self._cache.get(name) is not None

    def raw_contents_for_stage(self, names):
        """Concatenate raw file contents for a list of artifact names."""
        parts = []
        for n in names:
            parts.append(self.raw(n))
        return "".join(parts)


# ---------------------------------------------------------------------------
# ReceiptBuilder
# ---------------------------------------------------------------------------

class ReceiptBuilder:
    """Computes per-stage receipts with SHA-256 hashes."""

    @staticmethod
    def build(stage_id, checks, scanner, artifact_names, passed):
        ts = _now_iso()
        checks_canonical = json.dumps(checks, indent=2, sort_keys=True)
        stage_hash = _sha256(checks_canonical)
        inputs_raw = scanner.raw_contents_for_stage(artifact_names)
        inputs_hash = _sha256(inputs_raw) if inputs_raw else _sha256("")
        return {
            "stage_hash": stage_hash,
            "inputs_hash": inputs_hash,
            "timestamp": ts,
            "passed": passed,
        }


# ---------------------------------------------------------------------------
# StageEvaluator base class
# ---------------------------------------------------------------------------

class StageEvaluator:
    """Base class for stage evaluators."""

    STAGE_ID = None
    ARTIFACT_NAMES = []

    def __init__(self, scanner, prev_status=None):
        self.scanner = scanner
        self.prev_status = prev_status  # status of previous stage

    @property
    def abbrev(self):
        return STAGE_ABBREV[self.STAGE_ID]

    def _mk_check(self, n, name, passed, detail, tool):
        return {
            "check_id": "CHK-{}-{}".format(self.abbrev, n),
            "name": name,
            "passed": passed,
            "detail": detail,
            "tool": tool,
        }

    def _mk_blocker(self, n, severity, description):
        return {
            "blocker_id": "BLK-{}-{}".format(self.abbrev, n),
            "severity": severity,
            "description": description,
            "stage_blocked": self.STAGE_ID,
        }

    def _mk_remediation(self, n, command, description, resolves=None):
        return {
            "remediation_id": "REM-{}-{}".format(self.abbrev, n),
            "command": command,
            "description": description,
            "resolves_blocker": resolves,
        }

    def _mk_prerequisite(self, n, description, met):
        return {
            "id": "PRE-{}-{}".format(self.abbrev, n),
            "description": description,
            "met": met,
        }

    def _mk_criterion(self, n, description, met, evidence=None):
        return {
            "id": "CRI-{}-{}".format(self.abbrev, n),
            "description": description,
            "met": met,
            "evidence": evidence,
        }

    def _mk_source(self, n, name, url, role):
        return {
            "artifact_id": "ART-{}-{}".format(self.abbrev, n),
            "name": name,
            "url": url,
            "role": role,
        }

    def check_prerequisites(self):
        """Return list of prerequisite dicts. Override in subclasses."""
        return []

    def run_checks(self):
        """Return list of check_result dicts. Override in subclasses."""
        raise NotImplementedError

    def evaluate_completion(self, checks):
        """Return list of criterion dicts. Override in subclasses."""
        raise NotImplementedError

    def get_blockers(self, checks):
        """Return list of blocker dicts. Override in subclasses."""
        raise NotImplementedError

    def get_remediation(self, blockers):
        """Return list of remediation_item dicts. Override in subclasses."""
        raise NotImplementedError

    def get_source_artifacts(self):
        """Return list of source_artifact dicts. Override in subclasses."""
        raise NotImplementedError

    def evaluate(self):
        """Run the full stage evaluation, return stage_result dict."""
        prerequisites = self.check_prerequisites()
        prereqs_met = all(p["met"] for p in prerequisites) if prerequisites else True

        if not prereqs_met:
            # Stage cannot run — prerequisites not met
            checks = []
            criteria = []
            blockers = [
                self._mk_blocker(
                    1, "CRITICAL",
                    "Prerequisites not met: prior stage must PASS first"
                )
            ]
            remediation = self.get_remediation(blockers)
            sources = self.get_source_artifacts()
            receipt = ReceiptBuilder.build(
                self.STAGE_ID, checks, self.scanner,
                self.ARTIFACT_NAMES, False
            )
            return {
                "stage_id": self.STAGE_ID,
                "status": "BLOCKED",
                "prerequisites": prerequisites,
                "completion_criteria": criteria,
                "checks": checks,
                "blockers": blockers,
                "remediation": remediation,
                "source_artifacts": sources,
                "receipt": receipt,
            }

        checks = self.run_checks()
        criteria = self.evaluate_completion(checks)
        blockers = self.get_blockers(checks)
        remediation = self.get_remediation(blockers)
        sources = self.get_source_artifacts()

        all_criteria_met = all(c["met"] for c in criteria) if criteria else False
        passed = all_criteria_met and len(blockers) == 0
        status = "PASSED" if passed else "BLOCKED"

        receipt = ReceiptBuilder.build(
            self.STAGE_ID, checks, self.scanner,
            self.ARTIFACT_NAMES, passed
        )

        return {
            "stage_id": self.STAGE_ID,
            "status": status,
            "prerequisites": prerequisites,
            "completion_criteria": criteria,
            "checks": checks,
            "blockers": blockers,
            "remediation": remediation,
            "source_artifacts": sources,
            "receipt": receipt,
        }

    @staticmethod
    def make_not_reached(stage_id):
        """Build a NOT_REACHED stage_result with no checks."""
        abbrev = STAGE_ABBREV[stage_id]
        ts = _now_iso()
        empty_hash = _sha256("")
        return {
            "stage_id": stage_id,
            "status": "NOT_REACHED",
            "prerequisites": [],
            "completion_criteria": [],
            "checks": [],
            "blockers": [],
            "remediation": [],
            "source_artifacts": [],
            "receipt": {
                "stage_hash": empty_hash,
                "inputs_hash": empty_hash,
                "timestamp": ts,
                "passed": False,
            },
        }


# ---------------------------------------------------------------------------
# Stage 1: DISCOVER
# ---------------------------------------------------------------------------

class DiscoverEvaluator(StageEvaluator):
    STAGE_ID = "DISCOVER"
    ARTIFACT_NAMES = ["discovery_result.json", "registry.json"]

    def _get_discovery(self):
        """Return the discovery data — try discovery_result.json then registry.json."""
        d = self.scanner.get("discovery_result.json")
        if d is not None:
            return d, "discovery_result.json"
        d = self.scanner.get("registry.json")
        if d is not None:
            return d, "registry.json"
        return None, None

    def _find_producers(self, data):
        """Extract producer entries from discovery data (flexible)."""
        if data is None:
            return []
        if isinstance(data, list):
            return data
        for key in ("producers", "results", "entries", "registry"):
            v = data.get(key) if isinstance(data, dict) else None
            if isinstance(v, list):
                return v
        # The data itself may be a single producer
        if isinstance(data, dict) and ("producer_id" in data or "endpoint" in data):
            return [data]
        return []

    def run_checks(self):
        checks = []
        data, fname = self._get_discovery()

        # CHK-DISC-1: file exists and valid JSON
        c1 = data is not None
        checks.append(self._mk_check(
            1, "Discovery result file exists and is valid JSON",
            c1,
            "Found {}".format(fname) if c1 else "Neither discovery_result.json nor registry.json found",
            "ArtifactScanner"
        ))

        producers = self._find_producers(data) if c1 else []

        # CHK-DISC-2: at least one producer entry
        c2 = len(producers) > 0
        checks.append(self._mk_check(
            2, "At least one producer entry found",
            c2,
            "{} producer(s) found".format(len(producers)) if c2 else "No producer entries found",
            "DiscoverEvaluator"
        ))

        # For remaining checks, inspect first producer (or data itself)
        prod = producers[0] if producers else (data if isinstance(data, dict) else {})

        # CHK-DISC-3: producer has reputation grade
        grade = _safe_get(prod, "reputation_grade") or _safe_get(prod, "grade") or \
                _safe_get(prod, "reputation", "grade") or \
                _safe_get(prod, "reputation_summary", "grade")
        c3 = grade is not None and str(grade).strip() != ""
        checks.append(self._mk_check(
            3, "Producer has a reputation grade (A-F)",
            c3,
            "Grade: {}".format(grade) if c3 else "No reputation grade found",
            "DiscoverEvaluator"
        ))

        # CHK-DISC-4: endpoint/URL present and non-empty
        endpoint = _safe_get(prod, "endpoint") or _safe_get(prod, "url") or \
                   _safe_get(prod, "api_url") or _safe_get(prod, "base_url") or \
                   _safe_get(prod, "endpoint_url") or _safe_get(prod, "repository_url")
        c4 = endpoint is not None and str(endpoint).strip() != ""
        checks.append(self._mk_check(
            4, "Producer endpoint/URL is present and non-empty",
            c4,
            "Endpoint: {}".format(endpoint) if c4 else "No endpoint found",
            "DiscoverEvaluator"
        ))

        # CHK-DISC-5: published signal schema reference
        schema_ref = _safe_get(prod, "schema_ref") or _safe_get(prod, "signal_schema") or \
                     _safe_get(prod, "schema") or _safe_get(prod, "schema_url") or \
                     _safe_get(prod, "supported_protocols", "signal_schema") or \
                     _safe_get(prod, "supported_protocols")
        c5 = schema_ref is not None and str(schema_ref).strip() != ""
        checks.append(self._mk_check(
            5, "Producer has published signal schema reference",
            c5,
            "Schema ref: {}".format(schema_ref) if c5 else "No schema reference found",
            "DiscoverEvaluator"
        ))

        return checks

    def evaluate_completion(self, checks):
        # Producer found with grade and endpoint present
        passed_ids = {c["check_id"] for c in checks if c["passed"]}
        has_producer = "CHK-DISC-2" in passed_ids
        has_grade = "CHK-DISC-3" in passed_ids
        has_endpoint = "CHK-DISC-4" in passed_ids
        met = has_producer and has_grade and has_endpoint
        evidence = None
        if met:
            evidence = "Producer found with grade and endpoint present"
        return [
            self._mk_criterion(
                1,
                "Producer found with reputation grade and endpoint present",
                met,
                evidence,
            )
        ]

    def get_blockers(self, checks):
        blockers = []
        n = 1
        for c in checks:
            if not c["passed"]:
                sev = "CRITICAL" if c["check_id"] in ("CHK-DISC-1", "CHK-DISC-2") else "HIGH"
                blockers.append(self._mk_blocker(n, sev, c["detail"]))
                n += 1
        return blockers

    def get_remediation(self, blockers):
        rems = []
        cmd = (
            "python3 discover_producers.py --registry registry.json "
            "--filters '{\"min_reputation\": \"C\"}' -o discovery_result.json"
        )
        if blockers:
            rems.append(self._mk_remediation(
                1, cmd,
                "Run producer discovery to populate discovery_result.json",
                blockers[0]["blocker_id"] if blockers else None,
            ))
        return rems

    def get_source_artifacts(self):
        return [
            self._mk_source(
                1, "pf-discovery-protocol",
                REPO_URLS["discovery-protocol"],
                "Producer discovery and registry management",
            )
        ]


# ---------------------------------------------------------------------------
# Stage 2: EVALUATE
# ---------------------------------------------------------------------------

class EvaluateEvaluator(StageEvaluator):
    STAGE_ID = "EVALUATE"
    ARTIFACT_NAMES = ["health_report.json", "trust_evaluation.json"]

    def check_prerequisites(self):
        met = self.prev_status == "PASSED"
        return [
            self._mk_prerequisite(1, "DISCOVER stage must be PASSED", met)
        ]

    def run_checks(self):
        checks = []
        health = self.scanner.get("health_report.json")
        trust = self.scanner.get("trust_evaluation.json")

        # CHK-EVAL-1: health report exists
        c1 = health is not None
        checks.append(self._mk_check(
            1, "Health report exists and is valid JSON",
            c1,
            "health_report.json loaded" if c1 else "health_report.json not found or invalid",
            "ArtifactScanner",
        ))

        # CHK-EVAL-2: health composite grade C or better
        h_grade = None
        if c1:
            h_grade = _safe_get(health, "composite_grade") or \
                      _safe_get(health, "grade") or \
                      _safe_get(health, "health", "grade") or \
                      _safe_get(health, "summary", "grade") or \
                      _safe_get(health, "composite", "grade")
        c2 = h_grade is not None and _grade_ord(h_grade) <= _grade_ord("C")
        checks.append(self._mk_check(
            2, "Health composite grade is C or better",
            c2,
            "Health grade: {}".format(h_grade) if h_grade else "No health grade found",
            "EvaluateEvaluator",
        ))

        # CHK-EVAL-3: no hard gate failures (liveness, schema)
        hard_gates_ok = True
        gate_detail = "No hard gate failures detected"
        if c1 and isinstance(health, dict):
            dimensions = _safe_get(health, "dimensions") or \
                         _safe_get(health, "checks") or {}
            if isinstance(dimensions, dict):
                for gate_key in ("liveness", "schema_compliance", "schema"):
                    gate = dimensions.get(gate_key)
                    if isinstance(gate, dict):
                        gate_passed = gate.get("passed", gate.get("status") != "FAIL")
                        if gate_passed is False or gate.get("status") == "FAIL":
                            hard_gates_ok = False
                            gate_detail = "Hard gate failure: {}".format(gate_key)
                            break
            # Also check top-level hard_gates array
            hg = _safe_get(health, "hard_gates")
            if isinstance(hg, list):
                for g in hg:
                    if isinstance(g, dict) and g.get("passed") is False:
                        hard_gates_ok = False
                        gate_detail = "Hard gate failure: {}".format(g.get("name", "unknown"))
                        break
        c3 = c1 and hard_gates_ok
        checks.append(self._mk_check(
            3, "No hard gate failures in health (liveness, schema)",
            c3, gate_detail, "EvaluateEvaluator",
        ))

        # CHK-EVAL-4: trust evaluation exists
        c4 = trust is not None
        checks.append(self._mk_check(
            4, "Trust evaluation exists and is valid JSON",
            c4,
            "trust_evaluation.json loaded" if c4 else "trust_evaluation.json not found or invalid",
            "ArtifactScanner",
        ))

        # CHK-EVAL-5: trust verdict ADOPT or ADOPT_WITH_CAVEATS
        verdict = None
        if c4:
            raw_verdict = _safe_get(trust, "verdict")
            if isinstance(raw_verdict, dict):
                verdict = raw_verdict.get("recommendation") or raw_verdict.get("verdict")
            elif isinstance(raw_verdict, str):
                verdict = raw_verdict
            if verdict is None:
                verdict = _safe_get(trust, "trust_verdict") or \
                          _safe_get(trust, "evaluation", "verdict") or \
                          _safe_get(trust, "verdict", "recommendation")
        c5 = verdict in ("ADOPT", "ADOPT_WITH_CAVEATS")
        checks.append(self._mk_check(
            5, "Trust verdict is ADOPT or ADOPT_WITH_CAVEATS",
            c5,
            "Verdict: {}".format(verdict) if verdict else "No trust verdict found",
            "EvaluateEvaluator",
        ))

        # CHK-EVAL-6: risk factors documented
        risk_factors = None
        if c4:
            risk_factors = _safe_get(trust, "risk_factors") or \
                           _safe_get(trust, "risks")
        has_risks = isinstance(risk_factors, list)
        # If CAVEATS, risk factors must not be empty
        if verdict == "ADOPT_WITH_CAVEATS":
            c6 = has_risks and len(risk_factors) > 0
        else:
            c6 = has_risks
        checks.append(self._mk_check(
            6, "Risk factors are documented",
            c6,
            "{} risk factor(s)".format(len(risk_factors)) if has_risks else "No risk factors array",
            "EvaluateEvaluator",
        ))

        # CHK-EVAL-7: integration checklist present
        checklist = None
        if c4:
            checklist = _safe_get(trust, "integration_checklist") or \
                        _safe_get(trust, "checklist")
        c7 = isinstance(checklist, list) and len(checklist) > 0
        checks.append(self._mk_check(
            7, "Integration checklist present in trust evaluation",
            c7,
            "{} checklist item(s)".format(len(checklist)) if c7 else "No integration checklist",
            "EvaluateEvaluator",
        ))

        return checks

    def evaluate_completion(self, checks):
        passed_ids = {c["check_id"] for c in checks if c["passed"]}
        grade_ok = "CHK-EVAL-2" in passed_ids
        verdict_ok = "CHK-EVAL-5" in passed_ids
        met = grade_ok and verdict_ok
        evidence = None
        if met:
            evidence = "Health grade C+ and trust verdict ADOPT or ADOPT_WITH_CAVEATS"
        return [
            self._mk_criterion(
                1,
                "Health grade C+ and trust verdict is ADOPT or ADOPT_WITH_CAVEATS",
                met,
                evidence,
            )
        ]

    def get_blockers(self, checks):
        blockers = []
        n = 1
        for c in checks:
            if not c["passed"]:
                sev = "CRITICAL" if c["check_id"] in (
                    "CHK-EVAL-1", "CHK-EVAL-3", "CHK-EVAL-4", "CHK-EVAL-5"
                ) else "HIGH"
                blockers.append(self._mk_blocker(n, sev, c["detail"]))
                n += 1
        return blockers

    def get_remediation(self, blockers):
        rems = []
        n = 1
        # Check which artifacts are missing
        health_missing = not self.scanner.exists("health_report.json")
        trust_missing = not self.scanner.exists("trust_evaluation.json")

        if health_missing or any(
            "health" in b["description"].lower() or "gate" in b["description"].lower()
            for b in blockers
        ):
            rems.append(self._mk_remediation(
                n,
                "python3 check_health.py artifacts/ -o health_report.json",
                "Generate health report for the producer",
                blockers[0]["blocker_id"] if blockers else None,
            ))
            n += 1
        if trust_missing or any(
            "trust" in b["description"].lower() or "verdict" in b["description"].lower()
            for b in blockers
        ):
            rems.append(self._mk_remediation(
                n,
                "python3 evaluate_trust.py --health-report health_report.json "
                "--proof-surface proof_surface.json -o trust_evaluation.json",
                "Generate trust evaluation for the producer",
                blockers[n - 2]["blocker_id"] if len(blockers) > n - 2 else (
                    blockers[0]["blocker_id"] if blockers else None
                ),
            ))
            n += 1

        # Fallback if no specific remediation matched but blockers exist
        if not rems and blockers:
            rems.append(self._mk_remediation(
                1,
                "python3 check_health.py artifacts/ -o health_report.json",
                "Generate health report for the producer",
                blockers[0]["blocker_id"],
            ))

        return rems

    def get_source_artifacts(self):
        return [
            self._mk_source(
                1, "pf-health-monitor",
                REPO_URLS["health-monitor"],
                "Producer health monitoring",
            ),
            self._mk_source(
                2, "pf-trust-gateway",
                REPO_URLS["trust-gateway"],
                "Producer trust evaluation",
            ),
        ]


# ---------------------------------------------------------------------------
# Stage 3: INTEGRATE
# ---------------------------------------------------------------------------

class IntegrateEvaluator(StageEvaluator):
    STAGE_ID = "INTEGRATE"
    ARTIFACT_NAMES = [
        "acceptance_report.json", "quickstart_result.json", "signal_sample.json"
    ]

    def check_prerequisites(self):
        met = self.prev_status == "PASSED"
        return [
            self._mk_prerequisite(1, "EVALUATE stage must be PASSED", met)
        ]

    def run_checks(self):
        checks = []
        acceptance = self.scanner.get("acceptance_report.json")
        quickstart = self.scanner.get("quickstart_result.json")
        signal_sample = self.scanner.get("signal_sample.json")

        # CHK-INTG-1: acceptance report exists
        c1 = acceptance is not None
        checks.append(self._mk_check(
            1, "Acceptance report exists and is valid JSON",
            c1,
            "acceptance_report.json loaded" if c1 else "acceptance_report.json not found or invalid",
            "ArtifactScanner",
        ))

        # CHK-INTG-2: acceptance verdict READY or PARTIAL
        verdict = None
        if c1:
            raw_verdict = _safe_get(acceptance, "verdict")
            if isinstance(raw_verdict, dict):
                verdict = raw_verdict.get("recommendation") or raw_verdict.get("verdict")
            elif isinstance(raw_verdict, str):
                verdict = raw_verdict
            if verdict is None:
                verdict = _safe_get(acceptance, "acceptance_verdict") or \
                          _safe_get(acceptance, "result", "verdict") or \
                          _safe_get(acceptance, "verdict", "recommendation")
        c2 = verdict in ("READY", "PARTIAL")
        checks.append(self._mk_check(
            2, "Acceptance verdict is READY or PARTIAL",
            c2,
            "Verdict: {}".format(verdict) if verdict else "No acceptance verdict found",
            "IntegrateEvaluator",
        ))

        # CHK-INTG-3: signal sample exists
        c3 = signal_sample is not None
        checks.append(self._mk_check(
            3, "Signal sample exists and is valid JSON",
            c3,
            "signal_sample.json loaded" if c3 else "signal_sample.json not found or invalid",
            "ArtifactScanner",
        ))

        # CHK-INTG-4: signal sample contains at least 1 signal with required fields
        signals = []
        if c3:
            if isinstance(signal_sample, list):
                signals = signal_sample
            elif isinstance(signal_sample, dict):
                signals = _safe_get(signal_sample, "signals") or \
                          _safe_get(signal_sample, "data") or []
                if not isinstance(signals, list):
                    signals = [signal_sample]
        required_fields = {"symbol", "direction", "confidence", "timestamp"}
        valid_signals = [
            s for s in signals
            if isinstance(s, dict) and required_fields.issubset(set(s.keys()))
        ]
        c4 = len(valid_signals) > 0
        checks.append(self._mk_check(
            4, "Signal sample contains at least 1 signal with required fields",
            c4,
            "{} valid signal(s) with required fields".format(len(valid_signals))
            if c3 else "No signal sample to inspect",
            "IntegrateEvaluator",
        ))

        # CHK-INTG-5: schema validation on signal sample
        schema_fields = {"symbol", "direction", "confidence", "horizon_hours", "timestamp"}
        schema_valid = [
            s for s in signals
            if isinstance(s, dict) and schema_fields.issubset(set(s.keys()))
        ]
        c5 = len(schema_valid) > 0
        checks.append(self._mk_check(
            5, "Schema validation passes on signal sample",
            c5,
            "{} signal(s) pass full schema field check".format(len(schema_valid))
            if c3 else "No signal sample for schema validation",
            "IntegrateEvaluator",
        ))

        # CHK-INTG-6: quickstart result OR acceptance connectivity pass
        connectivity_pass = False
        if c1 and isinstance(acceptance, dict):
            acc_checks = _safe_get(acceptance, "checks") or \
                         _safe_get(acceptance, "results") or {}
            if isinstance(acc_checks, list):
                for ac in acc_checks:
                    if isinstance(ac, dict):
                        name = (ac.get("name") or ac.get("check_name") or "").lower()
                        if "connect" in name and ac.get("passed", False):
                            connectivity_pass = True
                            break
            elif isinstance(acc_checks, dict):
                # Dict format: {check_name: {score: ..., passed: ...}}
                for cname, cval in acc_checks.items():
                    if "connect" in cname.lower() and isinstance(cval, dict):
                        score = cval.get("score", 0)
                        if cval.get("passed", False) or (isinstance(score, (int, float)) and score >= 0.5):
                            connectivity_pass = True
                            break
            # Also check top-level connectivity field
            conn = _safe_get(acceptance, "connectivity")
            if isinstance(conn, dict) and conn.get("passed", False):
                connectivity_pass = True
        c6 = quickstart is not None or connectivity_pass
        detail6 = ""
        if quickstart is not None:
            detail6 = "quickstart_result.json found"
        elif connectivity_pass:
            detail6 = "Acceptance test shows connectivity PASS"
        else:
            detail6 = "No quickstart result and no connectivity PASS in acceptance"
        checks.append(self._mk_check(
            6, "Quickstart result exists OR acceptance connectivity PASS",
            c6, detail6, "IntegrateEvaluator",
        ))

        # CHK-INTG-7: no CRITICAL blockers in acceptance report
        critical_found = False
        if c1 and isinstance(acceptance, dict):
            acc_blockers = _safe_get(acceptance, "blockers") or []
            if isinstance(acc_blockers, list):
                for ab in acc_blockers:
                    if isinstance(ab, dict) and ab.get("severity") == "CRITICAL":
                        critical_found = True
                        break
            # Also check remediation or issues
            acc_issues = _safe_get(acceptance, "issues") or []
            if isinstance(acc_issues, list):
                for ai in acc_issues:
                    if isinstance(ai, dict) and ai.get("severity") == "CRITICAL":
                        critical_found = True
                        break
        c7 = c1 and not critical_found
        checks.append(self._mk_check(
            7, "No CRITICAL blockers in acceptance report",
            c7,
            "No CRITICAL blockers" if c7 else (
                "CRITICAL blocker found in acceptance report" if critical_found
                else "acceptance_report.json not available"
            ),
            "IntegrateEvaluator",
        ))

        return checks

    def evaluate_completion(self, checks):
        passed_ids = {c["check_id"] for c in checks if c["passed"]}
        verdict_ok = "CHK-INTG-2" in passed_ids
        sample_ok = "CHK-INTG-4" in passed_ids
        no_critical = "CHK-INTG-7" in passed_ids
        met = verdict_ok and sample_ok and no_critical
        evidence = None
        if met:
            evidence = "Acceptance READY/PARTIAL, signal sample valid, no critical blockers"
        return [
            self._mk_criterion(
                1,
                "Acceptance READY/PARTIAL, signal sample valid, no critical blockers",
                met,
                evidence,
            )
        ]

    def get_blockers(self, checks):
        blockers = []
        n = 1
        for c in checks:
            if not c["passed"]:
                sev = "CRITICAL" if c["check_id"] in (
                    "CHK-INTG-1", "CHK-INTG-2", "CHK-INTG-7"
                ) else "HIGH"
                blockers.append(self._mk_blocker(n, sev, c["detail"]))
                n += 1
        return blockers

    def get_remediation(self, blockers):
        rems = []
        if blockers:
            rems.append(self._mk_remediation(
                1,
                "python3 acceptance_test.py --signal-sample signal_sample.json "
                "--health-report health_report.json -o acceptance_report.json",
                "Run acceptance test to verify integration readiness",
                blockers[0]["blocker_id"],
            ))
        return rems

    def get_source_artifacts(self):
        return [
            self._mk_source(
                1, "pf-acceptance-test",
                REPO_URLS["acceptance-test"],
                "Integration acceptance testing",
            ),
            self._mk_source(
                2, "pf-consumer-quickstart",
                REPO_URLS["consumer-quickstart"],
                "Quick-start consumer integration",
            ),
            self._mk_source(
                3, "pf-signal-schema",
                REPO_URLS["signal-schema"],
                "Signal schema definition and validation",
            ),
        ]


# ---------------------------------------------------------------------------
# Stage 4: MONITOR
# ---------------------------------------------------------------------------

class MonitorEvaluator(StageEvaluator):
    STAGE_ID = "MONITOR"
    ARTIFACT_NAMES = [
        "drift_report.json", "calibration_report.json", "resolved_signals.json"
    ]

    def check_prerequisites(self):
        met = self.prev_status == "PASSED"
        return [
            self._mk_prerequisite(1, "INTEGRATE stage must be PASSED", met)
        ]

    def run_checks(self):
        checks = []
        drift = self.scanner.get("drift_report.json")
        calibration = self.scanner.get("calibration_report.json")
        resolved = self.scanner.get("resolved_signals.json")

        # CHK-MNTR-1: resolved signals file with at least 100 signals
        signal_count = 0
        if resolved is not None:
            if isinstance(resolved, list):
                signal_count = len(resolved)
            elif isinstance(resolved, dict):
                sig_list = _safe_get(resolved, "signals") or \
                           _safe_get(resolved, "data") or \
                           _safe_get(resolved, "resolved_signals") or []
                signal_count = len(sig_list) if isinstance(sig_list, list) else 0
                # Also check count field
                if signal_count == 0:
                    signal_count = _safe_get(resolved, "count") or \
                                   _safe_get(resolved, "total") or 0
        c1 = resolved is not None and signal_count >= 100
        checks.append(self._mk_check(
            1, "Resolved signals file exists with at least 100 signals",
            c1,
            "{} resolved signals".format(signal_count) if resolved is not None
            else "resolved_signals.json not found",
            "MonitorEvaluator",
        ))

        # CHK-MNTR-2: drift report exists
        c2 = drift is not None
        checks.append(self._mk_check(
            2, "Drift report exists and is valid JSON",
            c2,
            "drift_report.json loaded" if c2 else "drift_report.json not found or invalid",
            "ArtifactScanner",
        ))

        # CHK-MNTR-3: drift alert severity not CRITICAL
        drift_severity = None
        if c2:
            drift_severity = _safe_get(drift, "alert_severity") or \
                             _safe_get(drift, "severity") or \
                             _safe_get(drift, "drift_summary", "severity") or \
                             _safe_get(drift, "summary", "alert_severity") or \
                             _safe_get(drift, "alert_summary", "overall_severity")
        c3 = c2 and drift_severity != "CRITICAL"
        checks.append(self._mk_check(
            3, "Drift alert severity is not CRITICAL",
            c3,
            "Drift severity: {}".format(drift_severity) if drift_severity
            else ("No severity field found" if c2 else "drift_report.json not available"),
            "MonitorEvaluator",
        ))

        # CHK-MNTR-4: calibration report exists
        c4 = calibration is not None
        checks.append(self._mk_check(
            4, "Calibration report exists and is valid JSON",
            c4,
            "calibration_report.json loaded" if c4
            else "calibration_report.json not found or invalid",
            "ArtifactScanner",
        ))

        # CHK-MNTR-5: ECE below 0.20
        ece = None
        if c4:
            raw_ece = _safe_get(calibration, "ece")
            if isinstance(raw_ece, dict):
                ece = raw_ece.get("value")
            elif isinstance(raw_ece, (int, float)):
                ece = raw_ece
            if ece is None:
                ece = _safe_get(calibration, "expected_calibration_error") or \
                      _safe_get(calibration, "calibration", "ece") or \
                      _safe_get(calibration, "summary", "ece") or \
                      _safe_get(calibration, "metrics", "ece") or \
                      _safe_get(calibration, "ece", "value")
        c5 = False
        if ece is not None:
            try:
                c5 = float(ece) < 0.20
            except (ValueError, TypeError):
                pass
        checks.append(self._mk_check(
            5, "ECE (calibration error) is below 0.20",
            c5,
            "ECE: {}".format(_round6(float(ece)) if ece is not None else "N/A")
            if c4 else "calibration_report.json not available",
            "MonitorEvaluator",
        ))

        # CHK-MNTR-6: Brier score below 0.50
        brier = None
        if c4:
            brier = _safe_get(calibration, "brier_score") or \
                    _safe_get(calibration, "brier") or \
                    _safe_get(calibration, "calibration", "brier_score") or \
                    _safe_get(calibration, "summary", "brier_score") or \
                    _safe_get(calibration, "metrics", "brier_score") or \
                    _safe_get(calibration, "brier_decomposition", "brier_score")
        c6 = False
        if brier is not None:
            try:
                c6 = float(brier) < 0.50
            except (ValueError, TypeError):
                pass
        checks.append(self._mk_check(
            6, "Brier score is below 0.50",
            c6,
            "Brier: {}".format(_round6(float(brier)) if brier is not None else "N/A")
            if c4 else "calibration_report.json not available",
            "MonitorEvaluator",
        ))

        # CHK-MNTR-7: at least one per-symbol calibration entry
        per_symbol = None
        if c4:
            per_symbol = _safe_get(calibration, "per_symbol") or \
                         _safe_get(calibration, "symbol_calibration") or \
                         _safe_get(calibration, "by_symbol") or \
                         _safe_get(calibration, "symbols")
        c7 = False
        if isinstance(per_symbol, dict) and len(per_symbol) > 0:
            c7 = True
        elif isinstance(per_symbol, list) and len(per_symbol) > 0:
            c7 = True
        symbol_count = 0
        if isinstance(per_symbol, dict):
            symbol_count = len(per_symbol)
        elif isinstance(per_symbol, list):
            symbol_count = len(per_symbol)
        checks.append(self._mk_check(
            7, "At least one per-symbol calibration entry exists",
            c7,
            "{} symbol calibration entries".format(symbol_count) if c4
            else "calibration_report.json not available",
            "MonitorEvaluator",
        ))

        # CHK-MNTR-8: drift detection methods present (CUSUM and/or SPRT)
        methods = None
        if c2:
            methods = _safe_get(drift, "detection_methods") or \
                      _safe_get(drift, "methods") or \
                      _safe_get(drift, "detectors")
        c8 = False
        methods_str = ""
        if isinstance(methods, list):
            method_names = [
                (m.get("name") or m.get("method") or str(m)).upper()
                if isinstance(m, dict) else str(m).upper()
                for m in methods
            ]
            c8 = any("CUSUM" in mn for mn in method_names) or \
                 any("SPRT" in mn for mn in method_names)
            methods_str = ", ".join(method_names)
        elif isinstance(methods, dict):
            keys_upper = [k.upper() for k in methods.keys()]
            c8 = any("CUSUM" in k for k in keys_upper) or \
                 any("SPRT" in k for k in keys_upper)
            methods_str = ", ".join(keys_upper)
        elif methods is None and c2 and isinstance(drift, dict):
            # Check for top-level keys containing CUSUM/SPRT
            drift_keys = [k.upper() for k in drift.keys()]
            has_cusum = any("CUSUM" in k for k in drift_keys)
            has_sprt = any("SPRT" in k for k in drift_keys)
            c8 = has_cusum or has_sprt
            found = []
            if has_cusum:
                found.append("CUSUM")
            if has_sprt:
                found.append("SPRT")
            methods_str = ", ".join(found) if found else ""
        checks.append(self._mk_check(
            8, "Drift detection methods are present (CUSUM and/or SPRT)",
            c8,
            "Methods: {}".format(methods_str) if methods_str
            else ("No detection methods found" if c2 else "drift_report.json not available"),
            "MonitorEvaluator",
        ))

        return checks

    def evaluate_completion(self, checks):
        passed_ids = {c["check_id"] for c in checks if c["passed"]}
        drift_ok = "CHK-MNTR-3" in passed_ids
        cal_ok = "CHK-MNTR-5" in passed_ids or "CHK-MNTR-6" in passed_ids
        resolved_ok = "CHK-MNTR-1" in passed_ids
        met = drift_ok and cal_ok and resolved_ok
        evidence = None
        if met:
            evidence = "Drift not critical, calibration at least FAIR, resolved signals available"
        return [
            self._mk_criterion(
                1,
                "Drift not critical, calibration at least FAIR, resolved signals available",
                met,
                evidence,
            )
        ]

    def get_blockers(self, checks):
        blockers = []
        n = 1
        for c in checks:
            if not c["passed"]:
                sev = "CRITICAL" if c["check_id"] in (
                    "CHK-MNTR-1", "CHK-MNTR-3"
                ) else "HIGH"
                blockers.append(self._mk_blocker(n, sev, c["detail"]))
                n += 1
        return blockers

    def get_remediation(self, blockers):
        rems = []
        n = 1
        if not self.scanner.exists("resolved_signals.json"):
            rems.append(self._mk_remediation(
                n,
                "python3 backtest_runner.py resolved_signals.json -o backtest_report.json",
                "Obtain resolved signals data (at least 100 signals)",
                blockers[0]["blocker_id"] if blockers else None,
            ))
            n += 1
        if not self.scanner.exists("drift_report.json") or any(
            "drift" in b["description"].lower() for b in blockers
        ):
            rems.append(self._mk_remediation(
                n,
                "python3 monitor_drift.py --signals resolved_signals.json -o drift_report.json",
                "Generate drift report for signal quality monitoring",
                blockers[0]["blocker_id"] if blockers and not rems else (
                    blockers[1]["blocker_id"] if len(blockers) > 1 else (
                        blockers[0]["blocker_id"] if blockers else None
                    )
                ),
            ))
            n += 1
        if not self.scanner.exists("calibration_report.json") or any(
            "calibration" in b["description"].lower() or "ece" in b["description"].lower()
            or "brier" in b["description"].lower()
            for b in blockers
        ):
            rems.append(self._mk_remediation(
                n,
                "python3 calibrate_confidence.py --signals resolved_signals.json "
                "-o calibration_report.json",
                "Generate calibration report for confidence assessment",
                blockers[-1]["blocker_id"] if blockers else None,
            ))
            n += 1

        # Fallback
        if not rems and blockers:
            rems.append(self._mk_remediation(
                1,
                "python3 monitor_drift.py --signals resolved_signals.json -o drift_report.json",
                "Generate drift report for signal quality monitoring",
                blockers[0]["blocker_id"],
            ))

        return rems

    def get_source_artifacts(self):
        return [
            self._mk_source(
                1, "pf-consumer-drift-monitor",
                REPO_URLS["consumer-drift-monitor"],
                "Signal drift detection",
            ),
            self._mk_source(
                2, "pf-consumer-calibrator",
                REPO_URLS["consumer-calibrator"],
                "Confidence calibration analysis",
            ),
        ]


# ---------------------------------------------------------------------------
# Stage 5: TRUST
# ---------------------------------------------------------------------------

class TrustEvaluator(StageEvaluator):
    STAGE_ID = "TRUST"
    ARTIFACT_NAMES = [
        "backtest_report.json", "experience_report.json",
        "integration_scorecard.json", "forensic_report.json",
    ]

    def check_prerequisites(self):
        met = self.prev_status == "PASSED"
        return [
            self._mk_prerequisite(1, "MONITOR stage must be PASSED", met)
        ]

    def run_checks(self):
        checks = []
        backtest = self.scanner.get("backtest_report.json")
        experience = self.scanner.get("experience_report.json")
        scorecard = self.scanner.get("integration_scorecard.json")
        forensic = self.scanner.get("forensic_report.json")

        # CHK-TRST-1: backtest report exists
        c1 = backtest is not None
        checks.append(self._mk_check(
            1, "Backtest report exists and is valid JSON",
            c1,
            "backtest_report.json loaded" if c1
            else "backtest_report.json not found or invalid",
            "ArtifactScanner",
        ))

        # CHK-TRST-2: backtest verdict ADOPT
        bt_verdict = None
        if c1:
            raw_verdict = _safe_get(backtest, "verdict")
            if isinstance(raw_verdict, dict):
                bt_verdict = raw_verdict.get("decision") or raw_verdict.get("recommendation") or \
                             raw_verdict.get("verdict")
            elif isinstance(raw_verdict, str):
                bt_verdict = raw_verdict
            if bt_verdict is None:
                bt_verdict = _safe_get(backtest, "backtest_verdict") or \
                             _safe_get(backtest, "summary", "verdict") or \
                             _safe_get(backtest, "verdict", "decision")
        c2 = bt_verdict == "ADOPT"
        checks.append(self._mk_check(
            2, "Backtest verdict is ADOPT",
            c2,
            "Backtest verdict: {}".format(bt_verdict) if bt_verdict
            else "No backtest verdict found",
            "TrustEvaluator",
        ))

        # CHK-TRST-3: best strategy accuracy > 50%
        best_acc = None
        if c1:
            best_acc = _safe_get(backtest, "best_accuracy") or \
                       _safe_get(backtest, "summary", "best_accuracy")
            # Search in strategies (list or dict)
            if best_acc is None:
                strategies = _safe_get(backtest, "strategies") or {}
                accs = []
                if isinstance(strategies, list):
                    for s in strategies:
                        if isinstance(s, dict):
                            a = s.get("accuracy") or s.get("hit_rate")
                            if a is not None:
                                try:
                                    accs.append(float(a))
                                except (ValueError, TypeError):
                                    pass
                elif isinstance(strategies, dict):
                    for sname, sdata in strategies.items():
                        if isinstance(sdata, dict):
                            # Check metrics sub-dict first, then top-level
                            metrics = sdata.get("metrics") or {}
                            a = metrics.get("accuracy") if isinstance(metrics, dict) else None
                            if a is None:
                                a = sdata.get("accuracy") or sdata.get("hit_rate")
                            if a is not None:
                                try:
                                    accs.append(float(a))
                                except (ValueError, TypeError):
                                    pass
                if accs:
                    best_acc = max(accs)
        c3 = False
        if best_acc is not None:
            try:
                c3 = float(best_acc) > 50.0 or float(best_acc) > 0.50
                # Handle both percentage and fraction representations
                val = float(best_acc)
                c3 = val > 50.0 if val > 1.0 else val > 0.50
            except (ValueError, TypeError):
                pass
        checks.append(self._mk_check(
            3, "Best strategy accuracy > 50%",
            c3,
            "Best accuracy: {}".format(
                _round6(float(best_acc)) if best_acc is not None else "N/A"
            ),
            "TrustEvaluator",
        ))

        # CHK-TRST-4: experience report exists
        c4 = experience is not None
        checks.append(self._mk_check(
            4, "Experience report exists and is valid JSON",
            c4,
            "experience_report.json loaded" if c4
            else "experience_report.json not found or invalid",
            "ArtifactScanner",
        ))

        # CHK-TRST-5: satisfaction SATISFIED or MIXED
        satisfaction = None
        if c4:
            raw_sat = _safe_get(experience, "satisfaction_verdict")
            if isinstance(raw_sat, dict):
                satisfaction = raw_sat.get("verdict") or raw_sat.get("satisfaction")
            elif isinstance(raw_sat, str):
                satisfaction = raw_sat
            if satisfaction is None:
                satisfaction = _safe_get(experience, "satisfaction") or \
                               _safe_get(experience, "verdict") or \
                               _safe_get(experience, "summary", "satisfaction") or \
                               _safe_get(experience, "satisfaction_verdict", "verdict")
        c5 = satisfaction in ("SATISFIED", "MIXED")
        checks.append(self._mk_check(
            5, "Experience satisfaction is SATISFIED or MIXED",
            c5,
            "Satisfaction: {}".format(satisfaction) if satisfaction
            else "No satisfaction verdict found",
            "TrustEvaluator",
        ))

        # CHK-TRST-6: integration scorecard exists
        c6 = scorecard is not None
        checks.append(self._mk_check(
            6, "Integration scorecard exists and is valid JSON",
            c6,
            "integration_scorecard.json loaded" if c6
            else "integration_scorecard.json not found or invalid",
            "ArtifactScanner",
        ))

        # CHK-TRST-7: scorecard readiness READY or PARTIAL
        sc_readiness = None
        if c6:
            raw_ov = _safe_get(scorecard, "overall_verdict")
            if isinstance(raw_ov, dict):
                sc_readiness = raw_ov.get("readiness") or raw_ov.get("recommendation")
            if sc_readiness is None:
                sc_readiness = _safe_get(scorecard, "readiness") or \
                               _safe_get(scorecard, "verdict") or \
                               _safe_get(scorecard, "readiness_verdict") or \
                               _safe_get(scorecard, "summary", "readiness") or \
                               _safe_get(scorecard, "overall_verdict", "readiness")
        c7 = sc_readiness in ("READY", "PARTIAL")
        checks.append(self._mk_check(
            7, "Scorecard readiness is READY or PARTIAL",
            c7,
            "Readiness: {}".format(sc_readiness) if sc_readiness
            else "No readiness verdict found",
            "TrustEvaluator",
        ))

        # CHK-TRST-8: scorecard composite grade C or better
        sc_grade = None
        if c6:
            raw_ov = _safe_get(scorecard, "overall_verdict")
            if isinstance(raw_ov, dict) and sc_grade is None:
                sc_grade = raw_ov.get("grade")
            if sc_grade is None:
                sc_grade = _safe_get(scorecard, "composite_grade") or \
                           _safe_get(scorecard, "grade") or \
                           _safe_get(scorecard, "summary", "grade") or \
                           _safe_get(scorecard, "overall_verdict", "grade")
        c8 = sc_grade is not None and _grade_ord(sc_grade) <= _grade_ord("C")
        checks.append(self._mk_check(
            8, "Scorecard composite grade is C or better",
            c8,
            "Scorecard grade: {}".format(sc_grade) if sc_grade
            else "No scorecard grade found",
            "TrustEvaluator",
        ))

        # CHK-TRST-9: cross-consistency checks present (at least 4)
        cross_checks = None
        if c6:
            cross_checks = _safe_get(scorecard, "cross_consistency_checks") or \
                           _safe_get(scorecard, "cross_checks") or \
                           _safe_get(scorecard, "consistency_checks")
        cc_count = 0
        if isinstance(cross_checks, list):
            cc_count = len(cross_checks)
        elif isinstance(cross_checks, dict):
            cc_count = len(cross_checks)
        c9 = cc_count >= 4
        checks.append(self._mk_check(
            9, "Cross-consistency checks are present (at least 4)",
            c9,
            "{} cross-consistency checks".format(cc_count) if c6
            else "integration_scorecard.json not available",
            "TrustEvaluator",
        ))

        # CHK-TRST-10: forensic report with failure mode ranking
        c10_detail = ""
        has_failure_modes = False
        if forensic is not None:
            failure_modes = _safe_get(forensic, "failure_mode_ranking") or \
                            _safe_get(forensic, "failure_modes") or \
                            _safe_get(forensic, "failure_ranking")
            has_failure_modes = (
                isinstance(failure_modes, (list, dict)) and len(failure_modes) > 0
            )
            c10_detail = "Forensic report with {} failure mode(s)".format(
                len(failure_modes) if isinstance(failure_modes, (list, dict)) else 0
            )
        else:
            c10_detail = "forensic_report.json not found or invalid"
        c10 = forensic is not None and has_failure_modes
        checks.append(self._mk_check(
            10, "Forensic report exists with failure mode ranking",
            c10, c10_detail, "TrustEvaluator",
        ))

        return checks

    def evaluate_completion(self, checks):
        passed_ids = {c["check_id"] for c in checks if c["passed"]}
        bt_ok = "CHK-TRST-2" in passed_ids
        exp_ok = "CHK-TRST-5" in passed_ids
        sc_ok = "CHK-TRST-7" in passed_ids and "CHK-TRST-8" in passed_ids
        forensic_ok = "CHK-TRST-10" in passed_ids
        met = bt_ok and exp_ok and sc_ok and forensic_ok
        evidence = None
        if met:
            evidence = (
                "Backtest ADOPT, experience SATISFIED/MIXED, scorecard "
                "READY/PARTIAL grade C+, forensics available"
            )
        return [
            self._mk_criterion(
                1,
                "Backtest ADOPT, experience SATISFIED/MIXED, scorecard "
                "READY/PARTIAL grade C+, forensics available",
                met,
                evidence,
            )
        ]

    def get_blockers(self, checks):
        blockers = []
        n = 1
        for c in checks:
            if not c["passed"]:
                sev = "CRITICAL" if c["check_id"] in (
                    "CHK-TRST-1", "CHK-TRST-2"
                ) else "HIGH"
                blockers.append(self._mk_blocker(n, sev, c["detail"]))
                n += 1
        return blockers

    def get_remediation(self, blockers):
        rems = []
        n = 1
        if not self.scanner.exists("backtest_report.json") or any(
            "backtest" in b["description"].lower() for b in blockers
        ):
            rems.append(self._mk_remediation(
                n,
                "python3 backtest_runner.py resolved_signals.json -o backtest_report.json",
                "Run backtest to evaluate signal profitability",
                blockers[0]["blocker_id"] if blockers else None,
            ))
            n += 1
        if not self.scanner.exists("experience_report.json") or any(
            "experience" in b["description"].lower() or "satisfaction" in b["description"].lower()
            for b in blockers
        ):
            rems.append(self._mk_remediation(
                n,
                "python3 replay_experience.py --artifacts artifacts/ -o experience_report.json",
                "Generate experience replay report",
                blockers[n - 2]["blocker_id"] if len(blockers) > n - 2 else (
                    blockers[0]["blocker_id"] if blockers else None
                ),
            ))
            n += 1
        if not self.scanner.exists("integration_scorecard.json") or any(
            "scorecard" in b["description"].lower() or "readiness" in b["description"].lower()
            or "cross-consistency" in b["description"].lower()
            for b in blockers
        ):
            rems.append(self._mk_remediation(
                n,
                "python3 score_integration.py --artifacts artifacts/ -o integration_scorecard.json",
                "Generate integration scorecard",
                blockers[-1]["blocker_id"] if blockers else None,
            ))
            n += 1
        if not self.scanner.exists("forensic_report.json") or any(
            "forensic" in b["description"].lower() or "failure mode" in b["description"].lower()
            for b in blockers
        ):
            rems.append(self._mk_remediation(
                n,
                "python3 trace_signal.py --signals resolved_signals.json -o forensic_report.json",
                "Generate signal forensics report with failure mode ranking",
                blockers[-1]["blocker_id"] if blockers else None,
            ))
            n += 1

        # Fallback
        if not rems and blockers:
            rems.append(self._mk_remediation(
                1,
                "python3 backtest_runner.py resolved_signals.json -o backtest_report.json",
                "Run backtest to evaluate signal profitability",
                blockers[0]["blocker_id"],
            ))

        return rems

    def get_source_artifacts(self):
        return [
            self._mk_source(
                1, "pf-consumer-backtest",
                REPO_URLS["consumer-backtest"],
                "Historical signal backtesting",
            ),
            self._mk_source(
                2, "pf-experience-replay",
                REPO_URLS["experience-replay"],
                "Integration experience replay",
            ),
            self._mk_source(
                3, "pf-integration-scorecard",
                REPO_URLS["integration-scorecard"],
                "Cross-protocol integration scoring",
            ),
            self._mk_source(
                4, "pf-signal-forensics",
                REPO_URLS["signal-forensics"],
                "Signal lifecycle forensic analysis",
            ),
        ]


# ---------------------------------------------------------------------------
# HashChainBuilder
# ---------------------------------------------------------------------------

class HashChainBuilder:
    """Builds the hash chain section of the report."""

    @staticmethod
    def build(report, previous_hash=None):
        """Compute report_hash and content_hash with zero-then-fill pattern."""
        # Collect stage hashes
        stage_hashes = {}
        for sid in STAGE_ORDER:
            stage_data = report.get("stages", {}).get(sid, {})
            receipt = stage_data.get("receipt", {})
            stage_hashes[sid] = receipt.get("stage_hash", _sha256(""))

        chain_length = 1
        if previous_hash is not None:
            # Attempt to infer chain length — assume 1 more than previous
            chain_length = 2  # default; caller can override if needed

        hash_chain = {
            "algorithm": "SHA-256",
            "report_hash": "0" * 64,
            "previous_report_hash": previous_hash,
            "chain_length": chain_length if previous_hash else 1,
            "stage_hashes": stage_hashes,
        }
        report["hash_chain"] = hash_chain

        # Zero content_hash, serialize, compute, fill back
        report["meta"]["content_hash"] = "0" * 64
        serialized = json.dumps(report, indent=2, sort_keys=True)
        content_hash = _sha256(serialized)
        report["meta"]["content_hash"] = content_hash

        # Now compute report_hash over the full report including content_hash
        report["hash_chain"]["report_hash"] = "0" * 64
        serialized2 = json.dumps(report, indent=2, sort_keys=True)
        report_hash = _sha256(serialized2)
        report["hash_chain"]["report_hash"] = report_hash

        return report


# ---------------------------------------------------------------------------
# LadderRunner
# ---------------------------------------------------------------------------

EVALUATOR_MAP = {
    "DISCOVER": DiscoverEvaluator,
    "EVALUATE": EvaluateEvaluator,
    "INTEGRATE": IntegrateEvaluator,
    "MONITOR": MonitorEvaluator,
    "TRUST": TrustEvaluator,
}


class LadderRunner:
    """Orchestrates all 5 stages in order."""

    def __init__(self, artifacts_dir, producer_id, previous_hash=None):
        self.artifacts_dir = artifacts_dir
        self.producer_id = producer_id
        self.previous_hash = previous_hash
        self.scanner = ArtifactScanner(artifacts_dir)

    def run(self):
        self.scanner.scan()

        stages = {}
        prev_status = None
        current_stage = "DISCOVER"
        blocked = False

        for sid in STAGE_ORDER:
            if blocked:
                stages[sid] = StageEvaluator.make_not_reached(sid)
                continue

            cls = EVALUATOR_MAP[sid]
            evaluator = cls(self.scanner, prev_status=prev_status)
            result = evaluator.evaluate()
            stages[sid] = result

            if result["status"] == "PASSED":
                current_stage = sid
                prev_status = "PASSED"
            else:
                # BLOCKED — mark remaining as NOT_REACHED
                blocked = True
                prev_status = "BLOCKED"

        # Find next_command: first remediation of first BLOCKED stage
        next_command = None
        if current_stage != "TRUST" or stages["TRUST"]["status"] != "PASSED":
            for sid in STAGE_ORDER:
                s = stages[sid]
                if s["status"] == "BLOCKED":
                    if s["remediation"]:
                        next_command = s["remediation"][0]["command"]
                    break

        # If DISCOVER is BLOCKED, current_stage remains "DISCOVER"
        # (already handled above since current_stage starts as "DISCOVER")
        # If all PASSED, next_command is null (already None)

        # Progress summary
        total_checks = 0
        checks_passed = 0
        stages_passed = 0
        stages_blocked = 0
        stages_not_reached = 0
        for sid in STAGE_ORDER:
            s = stages[sid]
            total_checks += len(s["checks"])
            checks_passed += sum(1 for c in s["checks"] if c["passed"])
            if s["status"] == "PASSED":
                stages_passed += 1
            elif s["status"] == "BLOCKED":
                stages_blocked += 1
            elif s["status"] == "NOT_REACHED":
                stages_not_reached += 1

        completion_pct = _round6((checks_passed / total_checks * 100) if total_checks > 0 else 0.0)
        grade = GRADE_MAP.get(stages_passed, "F")

        report = {
            "schema_version": SCHEMA_VERSION,
            "meta": {
                "report_id": _report_id(),
                "generated_at": _now_iso(),
                "generator_version": GENERATOR_VERSION,
                "content_hash": "0" * 64,
                "artifacts_dir": os.path.abspath(self.artifacts_dir),
                "producer_id": self.producer_id,
            },
            "stages": stages,
            "current_stage": current_stage,
            "next_command": next_command,
            "progress_summary": {
                "stages_passed": stages_passed,
                "stages_blocked": stages_blocked,
                "stages_not_reached": stages_not_reached,
                "total_checks": total_checks,
                "checks_passed": checks_passed,
                "completion_pct": completion_pct,
                "grade": grade,
            },
            "hash_chain": {},
            "limitations": LIMITATIONS,
        }

        # Build hash chain (fills content_hash and report_hash)
        report = HashChainBuilder.build(report, self.previous_hash)

        return report


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def print_summary(report):
    """Print human-readable adoption ladder summary."""
    meta = report["meta"]
    summary = report["progress_summary"]
    producer = meta["producer_id"]
    current = report["current_stage"]
    next_cmd = report["next_command"]
    grade = summary["grade"]
    pct = summary["completion_pct"]
    stages_passed = summary["stages_passed"]

    bar = "=" * 72

    lines = [
        bar,
        "  CONSUMER ADOPTION LADDER",
        bar,
        "  Producer:    {}".format(producer),
        "  Current:     {} ({} of 5 stages passed)".format(current, stages_passed),
    ]
    if next_cmd:
        lines.append("  Next:        {}".format(next_cmd))
    else:
        lines.append("  Next:        (all stages passed — no further action needed)")
    lines.append("  Grade:       {} ({:.1f}%)".format(grade, pct))
    lines.append("")

    for sid in STAGE_ORDER:
        stage = report["stages"][sid]
        status = stage["status"]
        checks = stage["checks"]
        passed_count = sum(1 for c in checks if c["passed"])
        total_count = len(checks)

        marker = ""
        if status == "PASSED":
            status_label = "[PASSED]"
            check_str = "{}/{} checks".format(passed_count, total_count)
            suffix = " ok"
        elif status == "BLOCKED":
            status_label = "[BLOCKED]"
            check_str = "{}/{} checks".format(passed_count, total_count)
            marker = " <-- YOU ARE HERE"
            suffix = ""
        elif status == "NOT_REACHED":
            status_label = "[NOT_REACHED]"
            check_str = ""
            suffix = ""
        else:
            status_label = "[{}]".format(status)
            check_str = ""
            suffix = ""

        line = "  {:<13}{:<14}{}{}".format(sid, status_label, check_str, suffix)
        if marker:
            line += marker
        lines.append(line)

        if status == "BLOCKED":
            # Show blockers
            for b in stage["blockers"]:
                lines.append("    Blockers:  {}".format(b["description"]))
            # Show first remediation
            if stage["remediation"]:
                lines.append("    Next cmd:  {}".format(
                    stage["remediation"][0]["command"]
                ))

    lines.append(bar)

    print("\n".join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Consumer Adoption Ladder Runner — evaluate adoption "
                    "progress through 5 sequential stages.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            "  python3 climb_ladder.py \\\n"
            "    --artifacts ./consumer_artifacts/ \\\n"
            "    --producer sendoeth \\\n"
            "    -o adoption_ladder_report.json \\\n"
            "    --summary\n"
        ),
    )
    parser.add_argument(
        "--artifacts", required=True,
        help="Path to directory containing consumer artifact JSON files",
    )
    parser.add_argument(
        "--producer", required=True,
        help="Producer ID string (e.g. sendoeth)",
    )
    parser.add_argument(
        "-o", "--output", required=True,
        help="Output file path for the adoption ladder report JSON",
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Print a human-readable summary table to stdout",
    )
    parser.add_argument(
        "--previous-hash", default=None,
        help="Previous report hash for chain continuity (64 hex chars)",
    )

    args = parser.parse_args()

    # Validate artifacts directory
    if not os.path.isdir(args.artifacts):
        print("Error: artifacts directory not found: {}".format(args.artifacts),
              file=sys.stderr)
        sys.exit(1)

    # Validate previous hash format
    prev_hash = args.previous_hash
    if prev_hash is not None:
        prev_hash = prev_hash.strip().lower()
        if len(prev_hash) != 64 or not all(c in "0123456789abcdef" for c in prev_hash):
            print("Error: --previous-hash must be 64 lowercase hex characters",
                  file=sys.stderr)
            sys.exit(1)

    runner = LadderRunner(args.artifacts, args.producer, previous_hash=prev_hash)
    report = runner.run()

    # Write output
    out_dir = os.path.dirname(os.path.abspath(args.output))
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=False)

    if args.summary:
        print_summary(report)

    # Print basic result to stderr
    summary = report["progress_summary"]
    print(
        "Adoption ladder: {} — {} ({}/{} stages passed, grade {})".format(
            args.producer,
            report["current_stage"],
            summary["stages_passed"],
            5,
            summary["grade"],
        ),
        file=sys.stderr,
    )
    print("Report written to: {}".format(os.path.abspath(args.output)),
          file=sys.stderr)


if __name__ == "__main__":
    main()
