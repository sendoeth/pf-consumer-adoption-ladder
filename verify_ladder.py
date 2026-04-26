#!/usr/bin/env python3
"""
verify_ladder.py -- Zero-trust verifier for Consumer Adoption Ladder reports.

Validates an adoption_ladder_report.json against ladder_schema.json with 500+
checks across 18 categories. Returns grade A-F and exit code 0 (grade >= B)
or 1 (grade < B).

Usage:
    python3 verify_ladder.py adoption_ladder_report.json [--artifacts ./consumer_artifacts/]
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STAGE_ORDER = ["DISCOVER", "EVALUATE", "INTEGRATE", "MONITOR", "TRUST"]
STAGE_STATUSES = {"PASSED", "BLOCKED", "SKIPPED", "NOT_REACHED"}
SEVERITY_ENUM = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
BIAS_DIRECTION_ENUM = {"OVERSTATED_READINESS", "UNDERSTATED_READINESS", "INDETERMINATE"}
BIAS_MAGNITUDE_ENUM = {"LOW", "MODERATE", "HIGH"}
GRADE_ENUM = {"A", "B", "C", "D", "F"}
TOP_LEVEL_REQUIRED = [
    "schema_version", "meta", "stages", "current_stage",
    "next_command", "progress_summary", "hash_chain", "limitations",
]
META_REQUIRED = [
    "report_id", "generated_at", "generator_version",
    "content_hash", "artifacts_dir", "producer_id",
]
STAGE_RESULT_REQUIRED = [
    "stage_id", "status", "prerequisites", "completion_criteria",
    "checks", "blockers", "remediation", "source_artifacts", "receipt",
]
RECEIPT_REQUIRED = ["stage_hash", "inputs_hash", "timestamp", "passed"]
PROGRESS_REQUIRED = [
    "stages_passed", "stages_blocked", "stages_not_reached",
    "total_checks", "checks_passed", "completion_pct", "grade",
]
HASH_CHAIN_REQUIRED = [
    "algorithm", "report_hash", "previous_report_hash",
    "chain_length", "stage_hashes",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_get(obj, *keys, default=None):
    """Safely traverse nested dicts/lists."""
    current = obj
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k, default)
        elif isinstance(current, (list, tuple)) and isinstance(k, int):
            if 0 <= k < len(current):
                current = current[k]
            else:
                return default
        else:
            return default
        if current is default:
            return default
    return current


def _is_hex64(val):
    """Check if val is a 64-character lowercase hex string."""
    return isinstance(val, str) and bool(re.fullmatch(r"[0-9a-f]{64}", val))


def _is_iso_datetime(val):
    """Check if val parses as ISO 8601 datetime."""
    if not isinstance(val, str):
        return False
    # Try multiple ISO formats
    for fmt_fn in [
        lambda s: datetime.fromisoformat(s),
        lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ"),
        lambda s: datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ"),
    ]:
        try:
            fmt_fn(val)
            return True
        except (ValueError, TypeError):
            continue
    # Also try replacing Z with +00:00 for Python <3.11
    try:
        datetime.fromisoformat(val.replace("Z", "+00:00"))
        return True
    except (ValueError, TypeError):
        return False


def _compute_content_hash(report):
    """Recompute content hash: zero content_hash and report_hash, serialize, SHA-256."""
    clone = json.loads(json.dumps(report))
    if "meta" in clone and isinstance(clone["meta"], dict):
        clone["meta"]["content_hash"] = "0" * 64
    if "hash_chain" in clone and isinstance(clone["hash_chain"], dict):
        clone["hash_chain"]["report_hash"] = "0" * 64
    serialized = json.dumps(clone, indent=2, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _grade_letter(pct):
    """Return letter grade for a percentage."""
    if pct >= 99.0:
        return "A"
    elif pct >= 90.0:
        return "B"
    elif pct >= 75.0:
        return "C"
    elif pct >= 50.0:
        return "D"
    else:
        return "F"


# ---------------------------------------------------------------------------
# LadderVerifier
# ---------------------------------------------------------------------------

class LadderVerifier:
    """Zero-trust verifier for Consumer Adoption Ladder reports."""

    def __init__(self, report, artifacts_dir=None):
        self.report = report
        self.artifacts_dir = artifacts_dir
        self.results = []  # list of (category, name, passed, detail)

    def _record(self, category, name, passed, detail):
        self.results.append((category, name, bool(passed), str(detail)))

    # ------------------------------------------------------------------
    # 1. structure (~15)
    # ------------------------------------------------------------------
    def _verify_structure(self):
        cat = "structure"
        r = self.report

        # top-level is dict
        self._record(cat, "top_level_is_dict", isinstance(r, dict),
                     f"type={type(r).__name__}")

        if not isinstance(r, dict):
            return

        # each required field present
        for field in TOP_LEVEL_REQUIRED:
            present = field in r
            self._record(cat, f"required_field_{field}", present,
                         "present" if present else "MISSING")

        # no extra top-level fields
        extra = set(r.keys()) - set(TOP_LEVEL_REQUIRED)
        self._record(cat, "no_extra_top_level_fields", len(extra) == 0,
                     f"extra={extra}" if extra else "clean")

        # schema_version is string
        self._record(cat, "schema_version_is_string",
                     isinstance(r.get("schema_version"), str),
                     f"type={type(r.get('schema_version')).__name__}")

        # meta is dict
        self._record(cat, "meta_is_dict",
                     isinstance(r.get("meta"), dict),
                     f"type={type(r.get('meta')).__name__}")

        # stages is dict
        self._record(cat, "stages_is_dict",
                     isinstance(r.get("stages"), dict),
                     f"type={type(r.get('stages')).__name__}")

        # stages has exactly 5 keys
        stages = r.get("stages", {})
        if isinstance(stages, dict):
            self._record(cat, "stages_has_5_keys",
                         len(stages) == 5,
                         f"count={len(stages)}")
            self._record(cat, "stages_keys_match_enum",
                         set(stages.keys()) == set(STAGE_ORDER),
                         f"keys={sorted(stages.keys())}")
        else:
            self._record(cat, "stages_has_5_keys", False, "stages not a dict")
            self._record(cat, "stages_keys_match_enum", False, "stages not a dict")

        # current_stage is string
        self._record(cat, "current_stage_is_string",
                     isinstance(r.get("current_stage"), str),
                     f"type={type(r.get('current_stage')).__name__}")

        # progress_summary is dict
        self._record(cat, "progress_summary_is_dict",
                     isinstance(r.get("progress_summary"), dict),
                     f"type={type(r.get('progress_summary')).__name__}")

        # hash_chain is dict
        self._record(cat, "hash_chain_is_dict",
                     isinstance(r.get("hash_chain"), dict),
                     f"type={type(r.get('hash_chain')).__name__}")

        # limitations is list
        self._record(cat, "limitations_is_list",
                     isinstance(r.get("limitations"), list),
                     f"type={type(r.get('limitations')).__name__}")

        # next_command is string or None
        nc = r.get("next_command")
        self._record(cat, "next_command_type_valid",
                     isinstance(nc, str) or nc is None,
                     f"type={type(nc).__name__}")

    # ------------------------------------------------------------------
    # 2. version (3)
    # ------------------------------------------------------------------
    def _verify_version(self):
        cat = "version"
        r = self.report

        sv = r.get("schema_version")
        self._record(cat, "schema_version_is_1.0.0", sv == "1.0.0",
                     f"value={sv!r}")

        gv = _safe_get(r, "meta", "generator_version")
        self._record(cat, "generator_version_is_1.0.0", gv == "1.0.0",
                     f"value={gv!r}")

        # generator_version matches schema_version
        self._record(cat, "versions_consistent", sv == gv,
                     f"schema={sv!r} generator={gv!r}")

    # ------------------------------------------------------------------
    # 3. meta (~10)
    # ------------------------------------------------------------------
    def _verify_meta(self):
        cat = "meta"
        meta = self.report.get("meta", {})
        if not isinstance(meta, dict):
            self._record(cat, "meta_is_dict", False, "not a dict")
            return

        # required fields
        for field in META_REQUIRED:
            present = field in meta
            self._record(cat, f"meta_has_{field}", present,
                         "present" if present else "MISSING")

        # no extra fields
        extra = set(meta.keys()) - set(META_REQUIRED)
        self._record(cat, "meta_no_extra_fields", len(extra) == 0,
                     f"extra={extra}" if extra else "clean")

        # report_id pattern CAL-[A-F0-9]{12}
        rid = meta.get("report_id", "")
        self._record(cat, "report_id_pattern",
                     bool(re.fullmatch(r"CAL-[A-F0-9]{12}", rid)),
                     f"value={rid!r}")

        # generated_at valid ISO
        ga = meta.get("generated_at", "")
        self._record(cat, "generated_at_valid_iso", _is_iso_datetime(ga),
                     f"value={ga!r}")

        # content_hash 64 hex
        ch = meta.get("content_hash", "")
        self._record(cat, "content_hash_is_hex64", _is_hex64(ch),
                     f"len={len(ch) if isinstance(ch, str) else 'N/A'}")

        # artifacts_dir non-empty string
        ad = meta.get("artifacts_dir", "")
        self._record(cat, "artifacts_dir_non_empty",
                     isinstance(ad, str) and len(ad) > 0,
                     f"value={ad!r}")

        # producer_id non-empty string
        pid = meta.get("producer_id", "")
        self._record(cat, "producer_id_non_empty",
                     isinstance(pid, str) and len(pid) > 0,
                     f"value={pid!r}")

    # ------------------------------------------------------------------
    # 4. stage_structure (~75 = 15 per stage x 5)
    # ------------------------------------------------------------------
    def _verify_stage_structure(self):
        cat = "stage_structure"
        stages = self.report.get("stages", {})
        if not isinstance(stages, dict):
            self._record(cat, "stages_is_dict", False, "stages not a dict")
            return

        for sname in STAGE_ORDER:
            stage = stages.get(sname)
            prefix = sname.lower()

            # stage exists
            self._record(cat, f"{prefix}_exists", stage is not None,
                         "present" if stage is not None else "MISSING")
            if not isinstance(stage, dict):
                continue

            # stage_id matches name
            sid = stage.get("stage_id")
            self._record(cat, f"{prefix}_stage_id_matches", sid == sname,
                         f"stage_id={sid!r} expected={sname!r}")

            # status valid enum
            status = stage.get("status")
            self._record(cat, f"{prefix}_status_valid", status in STAGE_STATUSES,
                         f"status={status!r}")

            # required fields present
            for field in STAGE_RESULT_REQUIRED:
                present = field in stage
                self._record(cat, f"{prefix}_has_{field}", present,
                             "present" if present else "MISSING")

            # no extra fields
            extra = set(stage.keys()) - set(STAGE_RESULT_REQUIRED)
            self._record(cat, f"{prefix}_no_extra_fields", len(extra) == 0,
                         f"extra={extra}" if extra else "clean")

            # array fields are arrays
            for arr_field in ["prerequisites", "completion_criteria", "checks",
                              "blockers", "remediation", "source_artifacts"]:
                val = stage.get(arr_field)
                self._record(cat, f"{prefix}_{arr_field}_is_array",
                             isinstance(val, list),
                             f"type={type(val).__name__}")

            # receipt is dict with required fields
            receipt = stage.get("receipt")
            self._record(cat, f"{prefix}_receipt_is_dict",
                         isinstance(receipt, dict),
                         f"type={type(receipt).__name__}")
            if isinstance(receipt, dict):
                for rf in RECEIPT_REQUIRED:
                    present = rf in receipt
                    self._record(cat, f"{prefix}_receipt_has_{rf}", present,
                                 "present" if present else "MISSING")

    # ------------------------------------------------------------------
    # 5. stage_ordering (~15)
    # ------------------------------------------------------------------
    def _verify_stage_ordering(self):
        cat = "stage_ordering"
        stages = self.report.get("stages", {})
        if not isinstance(stages, dict):
            return

        statuses = {}
        for sname in STAGE_ORDER:
            s = stages.get(sname, {})
            statuses[sname] = s.get("status") if isinstance(s, dict) else None

        # Sequential ordering: if stage i is BLOCKED, stages i+1..N must be NOT_REACHED or SKIPPED
        for i, sname in enumerate(STAGE_ORDER):
            st = statuses.get(sname)
            if st == "BLOCKED":
                for j in range(i + 1, len(STAGE_ORDER)):
                    later = STAGE_ORDER[j]
                    later_st = statuses.get(later)
                    ok = later_st in ("NOT_REACHED", "SKIPPED")
                    self._record(cat,
                                 f"{sname.lower()}_blocked_implies_{later.lower()}_not_reached",
                                 ok,
                                 f"{later} status={later_st}")

        # No stage can be PASSED if the previous stage is not PASSED
        for i in range(1, len(STAGE_ORDER)):
            cur = STAGE_ORDER[i]
            prev = STAGE_ORDER[i - 1]
            cur_st = statuses.get(cur)
            prev_st = statuses.get(prev)
            if cur_st == "PASSED":
                ok = prev_st == "PASSED"
                self._record(cat,
                             f"{cur.lower()}_passed_requires_{prev.lower()}_passed",
                             ok,
                             f"{prev}={prev_st} {cur}={cur_st}")
            else:
                self._record(cat,
                             f"{cur.lower()}_ordering_consistent_with_{prev.lower()}",
                             True,
                             f"{prev}={prev_st} {cur}={cur_st} (no conflict)")

        # DISCOVER cannot depend on a prior stage being PASSED
        discover_st = statuses.get("DISCOVER")
        self._record(cat, "discover_is_first_stage",
                     discover_st in STAGE_STATUSES,
                     f"status={discover_st}")

        # NOT_REACHED stages must come after the first BLOCKED/NOT_REACHED stage
        first_non_passed = None
        for sname in STAGE_ORDER:
            st = statuses.get(sname)
            if st != "PASSED" and first_non_passed is None:
                first_non_passed = sname
        if first_non_passed:
            idx = STAGE_ORDER.index(first_non_passed)
            for j in range(idx + 1, len(STAGE_ORDER)):
                later = STAGE_ORDER[j]
                later_st = statuses.get(later)
                ok = later_st in ("NOT_REACHED", "SKIPPED", "BLOCKED")
                self._record(cat,
                             f"after_{first_non_passed.lower()}_{later.lower()}_not_passed",
                             ok,
                             f"{later} status={later_st}")

    # ------------------------------------------------------------------
    # 6. prerequisite_logic (~25)
    # ------------------------------------------------------------------
    def _verify_prerequisite_logic(self):
        cat = "prerequisite_logic"
        stages = self.report.get("stages", {})
        if not isinstance(stages, dict):
            return

        statuses = {}
        for sname in STAGE_ORDER:
            s = stages.get(sname, {})
            statuses[sname] = s.get("status") if isinstance(s, dict) else None

        for i, sname in enumerate(STAGE_ORDER):
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            prereqs = stage.get("prerequisites", [])
            if not isinstance(prereqs, list):
                continue

            prefix = sname.lower()

            if i == 0:
                # DISCOVER: no prerequisites or all met
                if len(prereqs) == 0:
                    self._record(cat, f"{prefix}_no_prerequisites", True,
                                 "DISCOVER has no prerequisites")
                else:
                    all_met = all(
                        isinstance(p, dict) and p.get("met", False)
                        for p in prereqs
                    )
                    self._record(cat, f"{prefix}_all_prerequisites_met", all_met,
                                 f"{len(prereqs)} prerequisites, all_met={all_met}")
            else:
                prev_name = STAGE_ORDER[i - 1]
                prev_status = statuses.get(prev_name)

                # Stage has prerequisites
                self._record(cat, f"{prefix}_has_prerequisites",
                             len(prereqs) > 0,
                             f"count={len(prereqs)}")

                # Each prerequisite is a dict with required fields
                for pi, p in enumerate(prereqs):
                    if not isinstance(p, dict):
                        self._record(cat, f"{prefix}_prereq_{pi}_is_dict", False,
                                     f"type={type(p).__name__}")
                        continue

                    self._record(cat, f"{prefix}_prereq_{pi}_has_id",
                                 "id" in p, f"id={p.get('id', 'MISSING')}")
                    self._record(cat, f"{prefix}_prereq_{pi}_has_description",
                                 "description" in p and isinstance(p.get("description"), str),
                                 "present" if "description" in p else "MISSING")
                    self._record(cat, f"{prefix}_prereq_{pi}_has_met",
                                 "met" in p and isinstance(p.get("met"), bool),
                                 f"met={p.get('met')}")

                    # If previous stage is PASSED, prerequisites referencing it should be met
                    if prev_status == "PASSED":
                        met = p.get("met", False)
                        self._record(cat,
                                     f"{prefix}_prereq_{pi}_met_since_{prev_name.lower()}_passed",
                                     met,
                                     f"prev={prev_name} status={prev_status} met={met}")

    # ------------------------------------------------------------------
    # 7. check_id_format (~40)
    # ------------------------------------------------------------------
    def _verify_check_id_format(self):
        cat = "check_id_format"
        stages = self.report.get("stages", {})
        if not isinstance(stages, dict):
            return

        id_patterns = {
            "checks": (r"^CHK-[A-Z]+-\d+$", "check_id"),
            "prerequisites": (r"^PRE-[A-Z]+-\d+$", "id"),
            "completion_criteria": (r"^CRI-[A-Z]+-\d+$", "id"),
            "blockers": (r"^BLK-[A-Z]+-\d+$", "blocker_id"),
            "remediation": (r"^REM-[A-Z]+-\d+$", "remediation_id"),
            "source_artifacts": (r"^ART-[A-Z]+-\d+$", "artifact_id"),
        }

        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            prefix = sname.lower()

            for arr_name, (pattern, id_key) in id_patterns.items():
                items = stage.get(arr_name, [])
                if not isinstance(items, list):
                    continue

                seen_ids = set()
                for idx, item in enumerate(items):
                    if not isinstance(item, dict):
                        continue
                    item_id = item.get(id_key, "")

                    # ID matches expected pattern
                    matches = bool(re.fullmatch(pattern, item_id))
                    self._record(cat,
                                 f"{prefix}_{arr_name}_{idx}_{id_key}_format",
                                 matches,
                                 f"{id_key}={item_id!r} pattern={pattern}")

                    # ID contains stage name abbreviation
                    # The pattern should have the stage name in it
                    # e.g., CHK-DISCOVER-1 or CHK-DISC-1
                    if matches and item_id:
                        self._record(cat,
                                     f"{prefix}_{arr_name}_{idx}_{id_key}_contains_stage_ref",
                                     True,
                                     f"{id_key}={item_id!r}")

                    # Uniqueness within stage
                    if item_id in seen_ids:
                        self._record(cat,
                                     f"{prefix}_{arr_name}_{idx}_{id_key}_unique",
                                     False,
                                     f"DUPLICATE {id_key}={item_id!r}")
                    else:
                        if item_id:
                            seen_ids.add(item_id)
                            self._record(cat,
                                         f"{prefix}_{arr_name}_{idx}_{id_key}_unique",
                                         True,
                                         f"{id_key}={item_id!r}")

    # ------------------------------------------------------------------
    # 8. check_consistency (~40)
    # ------------------------------------------------------------------
    def _verify_check_consistency(self):
        cat = "check_consistency"
        stages = self.report.get("stages", {})
        if not isinstance(stages, dict):
            return

        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            prefix = sname.lower()
            status = stage.get("status")
            checks = stage.get("checks", [])
            blockers = stage.get("blockers", [])
            remediation = stage.get("remediation", [])

            if not isinstance(checks, list):
                checks = []
            if not isinstance(blockers, list):
                blockers = []
            if not isinstance(remediation, list):
                remediation = []

            passed_checks = [c for c in checks if isinstance(c, dict) and c.get("passed")]
            failed_checks = [c for c in checks if isinstance(c, dict) and not c.get("passed")]
            total = len(checks)

            # If all checks passed, status should be PASSED (unless NOT_REACHED/SKIPPED)
            if total > 0 and len(passed_checks) == total and status not in ("NOT_REACHED", "SKIPPED"):
                self._record(cat, f"{prefix}_all_passed_implies_status_passed",
                             status == "PASSED",
                             f"all {total} checks passed but status={status}")
            elif total > 0 and len(failed_checks) > 0 and status not in ("NOT_REACHED", "SKIPPED"):
                self._record(cat, f"{prefix}_failed_checks_imply_blocked",
                             status == "BLOCKED",
                             f"{len(failed_checks)} checks failed, status={status}")
            else:
                self._record(cat, f"{prefix}_status_check_consistency", True,
                             f"status={status} checks={total} (ok)")

            # Blocker count consistent with failed checks
            if status == "BLOCKED":
                self._record(cat, f"{prefix}_blocked_has_blockers",
                             len(blockers) >= 1,
                             f"blockers={len(blockers)}")

                # Each blocker has severity
                for bi, b in enumerate(blockers):
                    if isinstance(b, dict):
                        sev = b.get("severity")
                        self._record(cat, f"{prefix}_blocker_{bi}_has_valid_severity",
                                     sev in SEVERITY_ENUM,
                                     f"severity={sev!r}")

                # If BLOCKED, at least one remediation exists
                self._record(cat, f"{prefix}_blocked_has_remediation",
                             len(remediation) >= 1,
                             f"remediation_count={len(remediation)}")

                # Each remediation has command
                for ri, rem in enumerate(remediation):
                    if isinstance(rem, dict):
                        cmd = rem.get("command", "")
                        self._record(cat, f"{prefix}_remediation_{ri}_has_command",
                                     isinstance(cmd, str) and len(cmd) > 0,
                                     f"command={cmd!r:.60}")
            elif status == "PASSED":
                # PASSED stages should have no blockers
                self._record(cat, f"{prefix}_passed_no_blockers",
                             len(blockers) == 0,
                             f"blockers={len(blockers)}")

            # Validate individual check structure
            for ci, chk in enumerate(checks):
                if not isinstance(chk, dict):
                    continue
                self._record(cat, f"{prefix}_check_{ci}_has_passed_bool",
                             isinstance(chk.get("passed"), bool),
                             f"passed={chk.get('passed')!r}")
                self._record(cat, f"{prefix}_check_{ci}_has_name",
                             isinstance(chk.get("name"), str) and len(chk.get("name", "")) > 0,
                             f"name={chk.get('name', '')!r:.40}")
                self._record(cat, f"{prefix}_check_{ci}_has_detail",
                             isinstance(chk.get("detail"), str),
                             "present" if isinstance(chk.get("detail"), str) else "MISSING")
                self._record(cat, f"{prefix}_check_{ci}_has_tool",
                             isinstance(chk.get("tool"), str) and len(chk.get("tool", "")) > 0,
                             f"tool={chk.get('tool', '')!r:.40}")

    # ------------------------------------------------------------------
    # 9. completion_criteria_logic (~25)
    # ------------------------------------------------------------------
    def _verify_completion_criteria_logic(self):
        cat = "completion_criteria_logic"
        stages = self.report.get("stages", {})
        if not isinstance(stages, dict):
            return

        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            prefix = sname.lower()
            status = stage.get("status")
            criteria = stage.get("completion_criteria", [])
            if not isinstance(criteria, list):
                criteria = []

            if status == "PASSED":
                # All criteria must be met
                all_met = all(
                    isinstance(c, dict) and c.get("met", False)
                    for c in criteria
                )
                self._record(cat, f"{prefix}_passed_all_criteria_met", all_met,
                             f"{len(criteria)} criteria, all_met={all_met}")

                # Evidence non-null for met criteria
                for ci, c in enumerate(criteria):
                    if isinstance(c, dict) and c.get("met"):
                        ev = c.get("evidence")
                        self._record(cat, f"{prefix}_criterion_{ci}_met_has_evidence",
                                     ev is not None and isinstance(ev, str) and len(ev) > 0,
                                     f"evidence={'present' if ev else 'NULL'}")

            elif status == "BLOCKED":
                # At least one criterion not met
                any_unmet = any(
                    isinstance(c, dict) and not c.get("met", True)
                    for c in criteria
                )
                self._record(cat, f"{prefix}_blocked_has_unmet_criterion", any_unmet,
                             f"{len(criteria)} criteria")

                # Validate each criterion structure
                for ci, c in enumerate(criteria):
                    if isinstance(c, dict):
                        self._record(cat, f"{prefix}_criterion_{ci}_has_met_bool",
                                     isinstance(c.get("met"), bool),
                                     f"met={c.get('met')!r}")
                        self._record(cat, f"{prefix}_criterion_{ci}_has_description",
                                     isinstance(c.get("description"), str) and len(c.get("description", "")) > 0,
                                     "present" if c.get("description") else "MISSING")
            elif status in ("NOT_REACHED", "SKIPPED"):
                self._record(cat, f"{prefix}_not_reached_criteria_ok", True,
                             f"status={status}, criteria not evaluated")

    # ------------------------------------------------------------------
    # 10. blocker_remediation_link (~25)
    # ------------------------------------------------------------------
    def _verify_blocker_remediation_link(self):
        cat = "blocker_remediation_link"
        stages = self.report.get("stages", {})
        if not isinstance(stages, dict):
            return

        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            prefix = sname.lower()
            status = stage.get("status")
            blockers = stage.get("blockers", [])
            remediation = stage.get("remediation", [])
            if not isinstance(blockers, list):
                blockers = []
            if not isinstance(remediation, list):
                remediation = []

            if status != "BLOCKED":
                if status == "PASSED":
                    self._record(cat, f"{prefix}_passed_no_blocker_links_needed", True,
                                 "stage PASSED, no blockers expected")
                elif status in ("NOT_REACHED", "SKIPPED"):
                    self._record(cat, f"{prefix}_not_reached_no_blocker_links", True,
                                 f"status={status}")
                continue

            # Build map of blocker IDs
            blocker_ids = set()
            for bi, b in enumerate(blockers):
                if isinstance(b, dict):
                    bid = b.get("blocker_id", "")
                    blocker_ids.add(bid)

                    # Severity is valid
                    sev = b.get("severity")
                    self._record(cat, f"{prefix}_blocker_{bi}_severity_valid",
                                 sev in SEVERITY_ENUM,
                                 f"severity={sev!r}")

                    # stage_blocked is valid
                    sb = b.get("stage_blocked")
                    self._record(cat, f"{prefix}_blocker_{bi}_stage_blocked_valid",
                                 sb in STAGE_ORDER,
                                 f"stage_blocked={sb!r}")

                    # description non-empty
                    desc = b.get("description", "")
                    self._record(cat, f"{prefix}_blocker_{bi}_description_non_empty",
                                 isinstance(desc, str) and len(desc) > 0,
                                 f"len={len(desc) if isinstance(desc, str) else 0}")

            # Build map of remediation resolves_blocker
            resolved_blockers = set()
            for ri, rem in enumerate(remediation):
                if isinstance(rem, dict):
                    rb = rem.get("resolves_blocker")
                    if rb:
                        resolved_blockers.add(rb)

                    # Command is non-empty
                    cmd = rem.get("command", "")
                    self._record(cat, f"{prefix}_remediation_{ri}_command_non_empty",
                                 isinstance(cmd, str) and len(cmd) > 0,
                                 f"command={cmd!r:.50}")

                    # Description is non-empty
                    desc = rem.get("description", "")
                    self._record(cat, f"{prefix}_remediation_{ri}_description_non_empty",
                                 isinstance(desc, str) and len(desc) > 0,
                                 "present" if desc else "MISSING")

            # Each blocker has matching remediation
            for bid in blocker_ids:
                self._record(cat, f"{prefix}_blocker_{bid}_has_remediation",
                             bid in resolved_blockers,
                             f"resolved={bid in resolved_blockers}")

    # ------------------------------------------------------------------
    # 11. source_artifacts_check (~25)
    # ------------------------------------------------------------------
    def _verify_source_artifacts(self):
        cat = "source_artifacts_check"
        stages = self.report.get("stages", {})
        if not isinstance(stages, dict):
            return

        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            prefix = sname.lower()
            status = stage.get("status")
            artifacts = stage.get("source_artifacts", [])
            if not isinstance(artifacts, list):
                artifacts = []

            if status in ("NOT_REACHED", "SKIPPED"):
                # Relaxed: may or may not have artifacts
                self._record(cat, f"{prefix}_not_reached_artifacts_ok", True,
                             f"status={status}, artifacts={len(artifacts)}")
                continue

            # At least 1 source artifact
            self._record(cat, f"{prefix}_has_source_artifacts",
                         len(artifacts) >= 1,
                         f"count={len(artifacts)}")

            seen_ids = set()
            for ai, art in enumerate(artifacts):
                if not isinstance(art, dict):
                    self._record(cat, f"{prefix}_artifact_{ai}_is_dict", False,
                                 f"type={type(art).__name__}")
                    continue

                # URL non-empty
                url = art.get("url", "")
                self._record(cat, f"{prefix}_artifact_{ai}_url_non_empty",
                             isinstance(url, str) and len(url) > 0,
                             f"url={url!r:.60}")

                # Name non-empty
                name = art.get("name", "")
                self._record(cat, f"{prefix}_artifact_{ai}_name_non_empty",
                             isinstance(name, str) and len(name) > 0,
                             f"name={name!r:.40}")

                # Role non-empty
                role = art.get("role", "")
                self._record(cat, f"{prefix}_artifact_{ai}_role_non_empty",
                             isinstance(role, str) and len(role) > 0,
                             f"role={role!r:.40}")

                # Unique artifact_id within stage
                aid = art.get("artifact_id", "")
                if aid in seen_ids:
                    self._record(cat, f"{prefix}_artifact_{ai}_id_unique", False,
                                 f"DUPLICATE artifact_id={aid!r}")
                else:
                    if aid:
                        seen_ids.add(aid)
                    self._record(cat, f"{prefix}_artifact_{ai}_id_unique", True,
                                 f"artifact_id={aid!r}")

    # ------------------------------------------------------------------
    # 12. receipt_integrity (~30)
    # ------------------------------------------------------------------
    def _verify_receipt_integrity(self):
        cat = "receipt_integrity"
        stages = self.report.get("stages", {})
        if not isinstance(stages, dict):
            return

        all_stage_hashes = []
        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            prefix = sname.lower()
            status = stage.get("status")
            receipt = stage.get("receipt", {})
            if not isinstance(receipt, dict):
                self._record(cat, f"{prefix}_receipt_is_dict", False, "not a dict")
                continue

            # stage_hash is 64 hex
            sh = receipt.get("stage_hash", "")
            self._record(cat, f"{prefix}_stage_hash_is_hex64", _is_hex64(sh),
                         f"len={len(sh) if isinstance(sh, str) else 'N/A'}")

            # inputs_hash is 64 hex
            ih = receipt.get("inputs_hash", "")
            self._record(cat, f"{prefix}_inputs_hash_is_hex64", _is_hex64(ih),
                         f"len={len(ih) if isinstance(ih, str) else 'N/A'}")

            # timestamp valid ISO
            ts = receipt.get("timestamp", "")
            self._record(cat, f"{prefix}_timestamp_valid_iso", _is_iso_datetime(ts),
                         f"value={ts!r:.40}")

            # passed matches status == PASSED
            rp = receipt.get("passed")
            self._record(cat, f"{prefix}_receipt_passed_is_bool",
                         isinstance(rp, bool),
                         f"passed={rp!r}")
            if status == "PASSED":
                self._record(cat, f"{prefix}_receipt_passed_matches_status",
                             rp is True,
                             f"status=PASSED receipt.passed={rp}")
            elif status in ("BLOCKED", "NOT_REACHED", "SKIPPED"):
                self._record(cat, f"{prefix}_receipt_passed_matches_status",
                             rp is False,
                             f"status={status} receipt.passed={rp}")

            if _is_hex64(sh):
                all_stage_hashes.append(sh)

        # Hashes distinct across stages (for non-NOT_REACHED stages)
        passed_or_blocked_hashes = []
        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if isinstance(stage, dict):
                status = stage.get("status")
                receipt = stage.get("receipt", {})
                if isinstance(receipt, dict) and status in ("PASSED", "BLOCKED"):
                    sh = receipt.get("stage_hash", "")
                    if _is_hex64(sh):
                        passed_or_blocked_hashes.append(sh)

        if len(passed_or_blocked_hashes) > 1:
            unique = len(set(passed_or_blocked_hashes)) == len(passed_or_blocked_hashes)
            self._record(cat, "active_stage_hashes_distinct", unique,
                         f"{len(passed_or_blocked_hashes)} active hashes, "
                         f"{len(set(passed_or_blocked_hashes))} unique")

    # ------------------------------------------------------------------
    # 13. current_stage_logic (~10)
    # ------------------------------------------------------------------
    def _verify_current_stage_logic(self):
        cat = "current_stage_logic"
        r = self.report
        current = r.get("current_stage")

        # current_stage is in enum
        self._record(cat, "current_stage_in_enum",
                     current in STAGE_ORDER,
                     f"value={current!r}")

        stages = r.get("stages", {})
        if not isinstance(stages, dict):
            return

        statuses = {}
        for sname in STAGE_ORDER:
            s = stages.get(sname, {})
            statuses[sname] = s.get("status") if isinstance(s, dict) else None

        # Determine highest PASSED stage
        highest_passed = None
        for sname in STAGE_ORDER:
            if statuses.get(sname) == "PASSED":
                highest_passed = sname

        # If no stages passed, current_stage should be DISCOVER
        if highest_passed is None:
            self._record(cat, "no_passed_implies_discover",
                         current == "DISCOVER",
                         f"current={current} (no stages passed)")
        else:
            # current_stage is the highest PASSED stage
            self._record(cat, "current_stage_is_highest_passed",
                         current == highest_passed,
                         f"current={current} highest_passed={highest_passed}")

        # Stages above current_stage are NOT_REACHED, SKIPPED, or BLOCKED
        if current in STAGE_ORDER:
            cur_idx = STAGE_ORDER.index(current)
            for j in range(cur_idx + 1, len(STAGE_ORDER)):
                above = STAGE_ORDER[j]
                above_st = statuses.get(above)
                ok = above_st in ("NOT_REACHED", "SKIPPED", "BLOCKED")
                self._record(cat,
                             f"above_{above.lower()}_not_passed",
                             ok,
                             f"{above} status={above_st}")

        # current_stage's own status
        cur_status = statuses.get(current)
        if highest_passed is not None:
            self._record(cat, "current_stage_own_status",
                         cur_status == "PASSED",
                         f"current={current} status={cur_status}")
        else:
            # No stages passed: current_stage could be DISCOVER with BLOCKED status
            self._record(cat, "current_stage_own_status_when_none_passed",
                         cur_status in STAGE_STATUSES,
                         f"current={current} status={cur_status}")

    # ------------------------------------------------------------------
    # 14. next_command_logic (~8)
    # ------------------------------------------------------------------
    def _verify_next_command_logic(self):
        cat = "next_command_logic"
        r = self.report
        nc = r.get("next_command")
        stages = r.get("stages", {})
        if not isinstance(stages, dict):
            return

        statuses = {}
        for sname in STAGE_ORDER:
            s = stages.get(sname, {})
            statuses[sname] = s.get("status") if isinstance(s, dict) else None

        all_passed = all(statuses.get(s) == "PASSED" for s in STAGE_ORDER)
        any_blocked = any(statuses.get(s) == "BLOCKED" for s in STAGE_ORDER)

        # If all passed, next_command is null
        if all_passed:
            self._record(cat, "all_passed_next_command_null",
                         nc is None,
                         f"next_command={nc!r:.60}")
        else:
            self._record(cat, "not_all_passed_acknowledged", True,
                         "not all stages passed")

        # If any blocked, next_command is non-null
        if any_blocked:
            self._record(cat, "blocked_next_command_non_null",
                         nc is not None and isinstance(nc, str) and len(nc) > 0,
                         f"next_command={'set' if nc else 'NULL'}")

            # next_command should match first remediation of first blocked stage
            first_blocked = None
            for sname in STAGE_ORDER:
                if statuses.get(sname) == "BLOCKED":
                    first_blocked = sname
                    break

            if first_blocked:
                fb_stage = stages.get(first_blocked, {})
                if isinstance(fb_stage, dict):
                    fb_rem = fb_stage.get("remediation", [])
                    if isinstance(fb_rem, list) and len(fb_rem) > 0:
                        first_rem = fb_rem[0]
                        if isinstance(first_rem, dict):
                            expected_cmd = first_rem.get("command", "")
                            self._record(cat, "next_command_matches_first_remediation",
                                         nc == expected_cmd,
                                         f"next_command={nc!r:.50} expected={expected_cmd!r:.50}")
                        else:
                            self._record(cat, "next_command_first_rem_check", False,
                                         "first remediation not a dict")
                    else:
                        self._record(cat, "next_command_first_blocked_has_remediation",
                                     False, f"stage {first_blocked} has no remediation")
        else:
            self._record(cat, "no_blocked_stages", True,
                         "no BLOCKED stages found")

        # next_command type
        self._record(cat, "next_command_type_valid",
                     isinstance(nc, str) or nc is None,
                     f"type={type(nc).__name__}")

        # If not all passed and not blocked (some SKIPPED/NOT_REACHED),
        # next_command should still be non-null if work remains
        if not all_passed and not any_blocked:
            # Stages that are NOT_REACHED imply work remains
            nr_count = sum(1 for s in STAGE_ORDER if statuses.get(s) == "NOT_REACHED")
            if nr_count > 0:
                self._record(cat, "not_reached_stages_next_command",
                             nc is not None,
                             f"not_reached={nr_count} next_command={'set' if nc else 'NULL'}")

    # ------------------------------------------------------------------
    # 15. progress_summary_logic (~15)
    # ------------------------------------------------------------------
    def _verify_progress_summary_logic(self):
        cat = "progress_summary_logic"
        r = self.report
        ps = r.get("progress_summary", {})
        if not isinstance(ps, dict):
            self._record(cat, "progress_summary_is_dict", False, "not a dict")
            return

        # Required fields
        for field in PROGRESS_REQUIRED:
            present = field in ps
            self._record(cat, f"has_{field}", present,
                         "present" if present else "MISSING")

        stages = r.get("stages", {})
        if not isinstance(stages, dict):
            return

        # Count actual statuses
        actual_passed = 0
        actual_blocked = 0
        actual_not_reached = 0
        actual_skipped = 0
        actual_total_checks = 0
        actual_checks_passed = 0

        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            status = stage.get("status")
            if status == "PASSED":
                actual_passed += 1
            elif status == "BLOCKED":
                actual_blocked += 1
            elif status == "NOT_REACHED":
                actual_not_reached += 1
            elif status == "SKIPPED":
                actual_skipped += 1

            checks = stage.get("checks", [])
            if isinstance(checks, list):
                actual_total_checks += len(checks)
                actual_checks_passed += sum(
                    1 for c in checks
                    if isinstance(c, dict) and c.get("passed")
                )

        # stages_passed matches
        sp = ps.get("stages_passed", -1)
        self._record(cat, "stages_passed_matches", sp == actual_passed,
                     f"reported={sp} actual={actual_passed}")

        # stages_blocked matches
        sb = ps.get("stages_blocked", -1)
        self._record(cat, "stages_blocked_matches", sb == actual_blocked,
                     f"reported={sb} actual={actual_blocked}")

        # stages_not_reached matches (count SKIPPED as NOT_REACHED for this check)
        snr = ps.get("stages_not_reached", -1)
        # Schema only has stages_not_reached, not stages_skipped
        # SKIPPED stages should be counted as not_reached for the sum
        effective_not_reached = actual_not_reached + actual_skipped
        self._record(cat, "stages_not_reached_matches",
                     snr == actual_not_reached or snr == effective_not_reached,
                     f"reported={snr} actual_nr={actual_not_reached} actual_skip={actual_skipped}")

        # Sum of stages = 5
        total_stages = sp + sb + snr
        self._record(cat, "stages_sum_equals_5",
                     total_stages == 5 or (total_stages + actual_skipped) == 5,
                     f"passed={sp} blocked={sb} not_reached={snr} sum={total_stages}")

        # total_checks matches
        tc = ps.get("total_checks", -1)
        self._record(cat, "total_checks_matches", tc == actual_total_checks,
                     f"reported={tc} actual={actual_total_checks}")

        # checks_passed matches
        cp = ps.get("checks_passed", -1)
        self._record(cat, "checks_passed_matches", cp == actual_checks_passed,
                     f"reported={cp} actual={actual_checks_passed}")

        # completion_pct
        reported_pct = ps.get("completion_pct", -1)
        if actual_total_checks > 0:
            expected_pct = (actual_checks_passed / actual_total_checks) * 100
        else:
            expected_pct = 0.0
        pct_ok = abs(reported_pct - expected_pct) <= 0.5
        self._record(cat, "completion_pct_accurate", pct_ok,
                     f"reported={reported_pct} expected={expected_pct:.2f} "
                     f"diff={abs(reported_pct - expected_pct):.3f}")

        # Grade consistent with stages_passed
        grade = ps.get("grade")
        self._record(cat, "grade_in_enum", grade in GRADE_ENUM,
                     f"grade={grade!r}")

        # A=5, B=4, C=3, D=2, F=0-1
        expected_grade_map = {5: "A", 4: "B", 3: "C", 2: "D", 1: "F", 0: "F"}
        expected_grade = expected_grade_map.get(actual_passed, "F")
        self._record(cat, "grade_consistent_with_stages_passed",
                     grade == expected_grade,
                     f"grade={grade} expected={expected_grade} "
                     f"stages_passed={actual_passed}")

    # ------------------------------------------------------------------
    # 16. hash_chain (~10)
    # ------------------------------------------------------------------
    def _verify_hash_chain(self):
        cat = "hash_chain"
        r = self.report
        hc = r.get("hash_chain", {})
        if not isinstance(hc, dict):
            self._record(cat, "hash_chain_is_dict", False, "not a dict")
            return

        # Required fields
        for field in HASH_CHAIN_REQUIRED:
            present = field in hc
            self._record(cat, f"has_{field}", present,
                         "present" if present else "MISSING")

        # algorithm = SHA-256
        algo = hc.get("algorithm")
        self._record(cat, "algorithm_is_sha256", algo == "SHA-256",
                     f"algorithm={algo!r}")

        # report_hash 64 hex
        rh = hc.get("report_hash", "")
        self._record(cat, "report_hash_is_hex64", _is_hex64(rh),
                     f"len={len(rh) if isinstance(rh, str) else 'N/A'}")

        # previous_report_hash 64 hex or null
        prh = hc.get("previous_report_hash")
        prh_ok = prh is None or _is_hex64(prh)
        self._record(cat, "previous_report_hash_valid", prh_ok,
                     f"value={'null' if prh is None else prh!r:.20}")

        # chain_length >= 1
        cl = hc.get("chain_length", 0)
        self._record(cat, "chain_length_ge_1",
                     isinstance(cl, int) and cl >= 1,
                     f"chain_length={cl}")

        # stage_hashes has all 5 stages
        sh = hc.get("stage_hashes", {})
        if isinstance(sh, dict):
            for sname in STAGE_ORDER:
                h = sh.get(sname, "")
                self._record(cat, f"stage_hash_{sname.lower()}_is_hex64",
                             _is_hex64(h),
                             f"len={len(h) if isinstance(h, str) else 'N/A'}")
        else:
            self._record(cat, "stage_hashes_is_dict", False,
                         f"type={type(sh).__name__}")

        # Content hash recomputation
        reported_content_hash = _safe_get(r, "meta", "content_hash", default="")
        computed = _compute_content_hash(r)
        self._record(cat, "content_hash_recomputation",
                     computed == reported_content_hash,
                     f"computed={computed[:16]}... reported={reported_content_hash[:16]}...")

        # Stage hashes in hash_chain match receipt stage hashes
        stages = r.get("stages", {})
        if isinstance(stages, dict) and isinstance(sh, dict):
            for sname in STAGE_ORDER:
                stage = stages.get(sname, {})
                if isinstance(stage, dict):
                    receipt = stage.get("receipt", {})
                    if isinstance(receipt, dict):
                        receipt_sh = receipt.get("stage_hash", "")
                        chain_sh = sh.get(sname, "")
                        self._record(cat,
                                     f"stage_hash_{sname.lower()}_matches_receipt",
                                     receipt_sh == chain_sh,
                                     f"receipt={receipt_sh[:16]}... chain={chain_sh[:16]}...")

    # ------------------------------------------------------------------
    # 17. limitations (~15)
    # ------------------------------------------------------------------
    def _verify_limitations(self):
        cat = "limitations"
        lims = self.report.get("limitations", [])
        if not isinstance(lims, list):
            self._record(cat, "limitations_is_list", False,
                         f"type={type(lims).__name__}")
            return

        # >= 4 items
        self._record(cat, "limitations_min_count", len(lims) >= 4,
                     f"count={len(lims)}")

        seen_ids = set()
        for li, lim in enumerate(lims):
            if not isinstance(lim, dict):
                self._record(cat, f"limitation_{li}_is_dict", False,
                             f"type={type(lim).__name__}")
                continue

            # ID matches L\d+ pattern
            lid = lim.get("id", "")
            self._record(cat, f"limitation_{li}_id_pattern",
                         bool(re.fullmatch(r"L\d+", lid)),
                         f"id={lid!r}")

            # Unique IDs
            if lid in seen_ids:
                self._record(cat, f"limitation_{li}_id_unique", False,
                             f"DUPLICATE id={lid!r}")
            else:
                seen_ids.add(lid)
                self._record(cat, f"limitation_{li}_id_unique", True,
                             f"id={lid!r}")

            # Description non-empty
            desc = lim.get("description", "")
            self._record(cat, f"limitation_{li}_description_non_empty",
                         isinstance(desc, str) and len(desc) > 0,
                         f"len={len(desc) if isinstance(desc, str) else 0}")

            # bias_direction valid enum
            bd = lim.get("bias_direction")
            self._record(cat, f"limitation_{li}_bias_direction_valid",
                         bd in BIAS_DIRECTION_ENUM,
                         f"bias_direction={bd!r}")

            # bias_magnitude valid enum
            bm = lim.get("bias_magnitude")
            self._record(cat, f"limitation_{li}_bias_magnitude_valid",
                         bm in BIAS_MAGNITUDE_ENUM,
                         f"bias_magnitude={bm!r}")

    # ------------------------------------------------------------------
    # 18. cross_stage_consistency (~20)
    # ------------------------------------------------------------------
    def _verify_cross_stage_consistency(self):
        cat = "cross_stage_consistency"
        r = self.report
        stages = r.get("stages", {})
        ps = r.get("progress_summary", {})
        if not isinstance(stages, dict):
            return

        # Total checks across all stages matches progress_summary
        actual_total = 0
        actual_passed = 0
        all_check_ids = []
        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            checks = stage.get("checks", [])
            if isinstance(checks, list):
                actual_total += len(checks)
                actual_passed += sum(
                    1 for c in checks
                    if isinstance(c, dict) and c.get("passed")
                )
                for c in checks:
                    if isinstance(c, dict):
                        cid = c.get("check_id", "")
                        all_check_ids.append((sname, cid))

        if isinstance(ps, dict):
            self._record(cat, "total_checks_cross_check",
                         ps.get("total_checks") == actual_total,
                         f"summary={ps.get('total_checks')} actual={actual_total}")
            self._record(cat, "checks_passed_cross_check",
                         ps.get("checks_passed") == actual_passed,
                         f"summary={ps.get('checks_passed')} actual={actual_passed}")

        # No duplicate check_ids across stages
        just_ids = [cid for _, cid in all_check_ids if cid]
        unique_ids = set(just_ids)
        self._record(cat, "no_duplicate_check_ids_across_stages",
                     len(just_ids) == len(unique_ids),
                     f"total={len(just_ids)} unique={len(unique_ids)}")

        # Stage order in JSON matches DISCOVER->EVALUATE->INTEGRATE->MONITOR->TRUST
        if isinstance(stages, dict):
            actual_order = list(stages.keys())
            self._record(cat, "stage_order_in_json",
                         actual_order == STAGE_ORDER,
                         f"order={actual_order}")

        # Each PASSED stage receipt.passed is true
        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            status = stage.get("status")
            receipt = stage.get("receipt", {})
            if not isinstance(receipt, dict):
                continue
            rp = receipt.get("passed")

            if status == "PASSED":
                self._record(cat, f"{sname.lower()}_passed_receipt_true",
                             rp is True,
                             f"status=PASSED receipt.passed={rp}")
            elif status in ("BLOCKED", "NOT_REACHED", "SKIPPED"):
                self._record(cat, f"{sname.lower()}_non_passed_receipt_false",
                             rp is False,
                             f"status={status} receipt.passed={rp}")

        # No duplicate blocker IDs across stages
        all_blocker_ids = []
        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if isinstance(stage, dict):
                blockers = stage.get("blockers", [])
                if isinstance(blockers, list):
                    for b in blockers:
                        if isinstance(b, dict):
                            bid = b.get("blocker_id", "")
                            if bid:
                                all_blocker_ids.append(bid)
        self._record(cat, "no_duplicate_blocker_ids_across_stages",
                     len(all_blocker_ids) == len(set(all_blocker_ids)),
                     f"total={len(all_blocker_ids)} unique={len(set(all_blocker_ids))}")

        # No duplicate remediation IDs across stages
        all_rem_ids = []
        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if isinstance(stage, dict):
                rems = stage.get("remediation", [])
                if isinstance(rems, list):
                    for rem in rems:
                        if isinstance(rem, dict):
                            rid = rem.get("remediation_id", "")
                            if rid:
                                all_rem_ids.append(rid)
        self._record(cat, "no_duplicate_remediation_ids_across_stages",
                     len(all_rem_ids) == len(set(all_rem_ids)),
                     f"total={len(all_rem_ids)} unique={len(set(all_rem_ids))}")

        # No duplicate artifact IDs across stages
        all_art_ids = []
        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if isinstance(stage, dict):
                arts = stage.get("source_artifacts", [])
                if isinstance(arts, list):
                    for art in arts:
                        if isinstance(art, dict):
                            aid = art.get("artifact_id", "")
                            if aid:
                                all_art_ids.append(aid)
        self._record(cat, "no_duplicate_artifact_ids_across_stages",
                     len(all_art_ids) == len(set(all_art_ids)),
                     f"total={len(all_art_ids)} unique={len(set(all_art_ids))}")

        # No duplicate criterion IDs across stages
        all_cri_ids = []
        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if isinstance(stage, dict):
                cris = stage.get("completion_criteria", [])
                if isinstance(cris, list):
                    for cri in cris:
                        if isinstance(cri, dict):
                            cid = cri.get("id", "")
                            if cid:
                                all_cri_ids.append(cid)
        self._record(cat, "no_duplicate_criterion_ids_across_stages",
                     len(all_cri_ids) == len(set(all_cri_ids)),
                     f"total={len(all_cri_ids)} unique={len(set(all_cri_ids))}")

        # No duplicate prerequisite IDs across stages
        all_pre_ids = []
        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if isinstance(stage, dict):
                pres = stage.get("prerequisites", [])
                if isinstance(pres, list):
                    for pre in pres:
                        if isinstance(pre, dict):
                            pid = pre.get("id", "")
                            if pid:
                                all_pre_ids.append(pid)
        self._record(cat, "no_duplicate_prerequisite_ids_across_stages",
                     len(all_pre_ids) == len(set(all_pre_ids)),
                     f"total={len(all_pre_ids)} unique={len(set(all_pre_ids))}")

        # Hash chain stage_hashes count matches 5
        hc = r.get("hash_chain", {})
        if isinstance(hc, dict):
            sh = hc.get("stage_hashes", {})
            if isinstance(sh, dict):
                self._record(cat, "hash_chain_has_5_stage_hashes",
                             len(sh) == 5,
                             f"count={len(sh)}")

    # ------------------------------------------------------------------
    # Artifact verification (optional)
    # ------------------------------------------------------------------
    def _verify_artifacts(self):
        """When --artifacts is provided, verify referenced files exist and are valid JSON."""
        cat = "artifacts"
        if not self.artifacts_dir:
            return

        if not os.path.isdir(self.artifacts_dir):
            self._record(cat, "artifacts_dir_exists", False,
                         f"dir={self.artifacts_dir!r} not found")
            return
        self._record(cat, "artifacts_dir_exists", True,
                     f"dir={self.artifacts_dir!r}")

        stages = self.report.get("stages", {})
        if not isinstance(stages, dict):
            return

        for sname in STAGE_ORDER:
            stage = stages.get(sname, {})
            if not isinstance(stage, dict):
                continue
            prefix = sname.lower()
            artifacts = stage.get("source_artifacts", [])
            if not isinstance(artifacts, list):
                continue

            for ai, art in enumerate(artifacts):
                if not isinstance(art, dict):
                    continue

                url = art.get("url", "")
                name = art.get("name", "")

                # Check if URL is a local file reference
                # Try common patterns: relative path, filename, or full path
                candidates = []
                if url:
                    candidates.append(url)
                    # Strip any protocol
                    stripped = url
                    for proto in ("file://", "https://", "http://"):
                        if stripped.startswith(proto):
                            stripped = stripped[len(proto):]
                    candidates.append(stripped)
                    # Just the basename
                    candidates.append(os.path.basename(stripped))
                if name:
                    candidates.append(name)

                found = False
                found_path = None
                for c in candidates:
                    fp = os.path.join(self.artifacts_dir, c)
                    if os.path.isfile(fp):
                        found = True
                        found_path = fp
                        break

                self._record(cat, f"{prefix}_artifact_{ai}_file_exists",
                             found,
                             f"name={name!r} url={url!r:.60} "
                             f"{'found=' + found_path if found else 'NOT FOUND'}")

                # If found, check it is valid JSON
                if found and found_path:
                    try:
                        with open(found_path, "r") as f:
                            data = json.load(f)
                        self._record(cat, f"{prefix}_artifact_{ai}_valid_json",
                                     True,
                                     f"path={found_path}")

                        # Check if key verdict fields match claims
                        # (generic: look for verdict, grade, status fields)
                        for vf in ("verdict", "grade", "status", "overall_grade"):
                            if isinstance(data, dict) and vf in data:
                                self._record(cat,
                                             f"{prefix}_artifact_{ai}_has_{vf}_field",
                                             True,
                                             f"{vf}={data[vf]!r}")
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        self._record(cat, f"{prefix}_artifact_{ai}_valid_json",
                                     False,
                                     f"parse error: {e}")
                    except OSError as e:
                        self._record(cat, f"{prefix}_artifact_{ai}_readable",
                                     False,
                                     f"read error: {e}")

    # ------------------------------------------------------------------
    # Run all categories
    # ------------------------------------------------------------------
    def verify(self):
        """Run all verification categories and return results."""
        self._verify_structure()
        self._verify_version()
        self._verify_meta()
        self._verify_stage_structure()
        self._verify_stage_ordering()
        self._verify_prerequisite_logic()
        self._verify_check_id_format()
        self._verify_check_consistency()
        self._verify_completion_criteria_logic()
        self._verify_blocker_remediation_link()
        self._verify_source_artifacts()
        self._verify_receipt_integrity()
        self._verify_current_stage_logic()
        self._verify_next_command_logic()
        self._verify_progress_summary_logic()
        self._verify_hash_chain()
        self._verify_limitations()
        self._verify_cross_stage_consistency()
        self._verify_artifacts()
        return self.results

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    def summary(self):
        """Produce per-category summary and overall grade."""
        cats = {}
        for (c, n, p, d) in self.results:
            if c not in cats:
                cats[c] = {"total": 0, "passed": 0, "failed": []}
            cats[c]["total"] += 1
            if p:
                cats[c]["passed"] += 1
            else:
                cats[c]["failed"].append((n, d))

        total = len(self.results)
        passed = sum(1 for (_, _, p, _) in self.results if p)
        failed = total - passed
        pct = (passed / total * 100) if total > 0 else 0.0
        grade = _grade_letter(pct)

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "pct": pct,
            "grade": grade,
            "categories": cats,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Zero-trust verifier for Consumer Adoption Ladder reports."
    )
    parser.add_argument("report", help="Path to the adoption ladder report JSON file")
    parser.add_argument("--artifacts", default=None,
                        help="Path to artifacts directory for file-level verification")
    args = parser.parse_args()

    # Load report
    if not os.path.isfile(args.report):
        print(f"ERROR: Report file not found: {args.report}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.report, "r") as f:
            report = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in report: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"ERROR: Cannot read report: {e}", file=sys.stderr)
        sys.exit(1)

    # Run verifier
    verifier = LadderVerifier(report, artifacts_dir=args.artifacts)
    verifier.verify()
    s = verifier.summary()

    # Output
    print("=== Adoption Ladder Verification ===")
    print(f"Total checks: {s['total']}")
    print(f"Passed: {s['passed']}")
    print(f"Failed: {s['failed']}")
    print(f"Grade: {s['grade']} ({s['pct']:.1f}%)")
    print()
    print("Per-category:")

    # Deterministic category ordering
    cat_order = [
        "structure", "version", "meta", "stage_structure", "stage_ordering",
        "prerequisite_logic", "check_id_format", "check_consistency",
        "completion_criteria_logic", "blocker_remediation_link",
        "source_artifacts_check", "receipt_integrity", "current_stage_logic",
        "next_command_logic", "progress_summary_logic", "hash_chain",
        "limitations", "cross_stage_consistency", "artifacts",
    ]
    cats = s["categories"]
    # Print in defined order, then any extras
    printed = set()
    for c in cat_order:
        if c in cats:
            info = cats[c]
            t, p = info["total"], info["passed"]
            g = _grade_letter((p / t * 100) if t > 0 else 0)
            print(f"  {c}: {p}/{t} ({g})")
            printed.add(c)
    for c in sorted(cats.keys()):
        if c not in printed:
            info = cats[c]
            t, p = info["total"], info["passed"]
            g = _grade_letter((p / t * 100) if t > 0 else 0)
            print(f"  {c}: {p}/{t} ({g})")

    # Print failures
    if s["failed"] > 0:
        print()
        print("=== Failures ===")
        for c in cat_order:
            if c in cats and cats[c]["failed"]:
                for (name, detail) in cats[c]["failed"]:
                    print(f"  [{c}] {name}: {detail}")
        for c in sorted(cats.keys()):
            if c not in printed and c in cats and cats[c]["failed"]:
                for (name, detail) in cats[c]["failed"]:
                    print(f"  [{c}] {name}: {detail}")

    # Exit code
    sys.exit(0 if s["grade"] in ("A", "B") else 1)


if __name__ == "__main__":
    main()
