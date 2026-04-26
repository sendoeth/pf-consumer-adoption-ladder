# pf-consumer-adoption-ladder

Zero-dependency consumer adoption ladder for the Post Fiat signal ecosystem. Evaluates a consumer's integration progress through 5 sequential stages and tells them exactly what to do next.

## Quick Start

```bash
# Generate adoption ladder report
python3 climb_ladder.py \
  --artifacts ./consumer_artifacts/ \
  --producer sendoeth \
  -o adoption_ladder_report.json \
  --summary

# Verify the report (695+ checks, 18 categories)
python3 verify_ladder.py adoption_ladder_report.json
```

## 5 Stages

| Stage | Gate | Key Artifacts | Checks |
|-------|------|---------------|--------|
| **DISCOVER** | Producer found with grade + endpoint | `discovery_result.json` | 5 |
| **EVALUATE** | Health grade C+, trust ADOPT/CAVEATS | `health_report.json`, `trust_evaluation.json` | 7 |
| **INTEGRATE** | Acceptance READY, signal sample valid | `acceptance_report.json`, `signal_sample.json` | 7 |
| **MONITOR** | Drift not critical, calibration OK | `drift_report.json`, `calibration_report.json`, `resolved_signals.json` | 8 |
| **TRUST** | Backtest ADOPT, experience SATISFIED, scorecard C+ | `backtest_report.json`, `experience_report.json`, `integration_scorecard.json`, `forensic_report.json` | 10 |

Stages are **sequentially gated** — a failure at any stage blocks all subsequent stages with `NOT_REACHED` status.

## Architecture

```
consumer_artifacts/          Input: JSON artifacts from PF consumer tools
        |
  climb_ladder.py            Generator: evaluates 5 stages, emits report
        |
  adoption_ladder_report.json  Output: dated report with verdicts
        |
  verify_ladder.py           Verifier: 695+ checks across 18 categories
```

### Generator (`climb_ladder.py`)

- `ArtifactScanner` — loads known artifact files from a directory
- `StageEvaluator` subclasses — `DiscoverEvaluator`, `EvaluateEvaluator`, `IntegrateEvaluator`, `MonitorEvaluator`, `TrustEvaluator`
- `LadderRunner` — orchestrates all 5 stages sequentially
- `HashChainBuilder` — SHA-256 content hash + report hash + per-stage hashes
- `ReceiptBuilder` — per-stage receipt with inputs_hash for auditability

### Verifier (`verify_ladder.py`)

18 verification categories, 695+ checks:

| Category | Checks | Description |
|----------|--------|-------------|
| structure | 20 | Top-level field presence and types |
| version | 3 | Schema and generator version |
| meta | 12 | Report ID pattern, timestamps, hashes |
| stage_structure | 120 | Per-stage required fields and types |
| stage_ordering | 5-15 | Sequential gating logic |
| prerequisite_logic | 21 | Prerequisite met/unmet consistency |
| check_id_format | 174 | CHK/PRE/CRI/BLK/REM/ART ID patterns |
| check_consistency | 158 | Check results match status |
| completion_criteria_logic | 10 | Criteria met/unmet logic |
| blocker_remediation_link | 5 | Each blocker has matching remediation |
| source_artifacts_check | 53 | Artifact URLs, names, roles |
| receipt_integrity | 26 | SHA-256 hashes, timestamps, status match |
| current_stage_logic | 3 | Current stage matches highest passed |
| next_command_logic | 3 | Next command matches first blocked remediation |
| progress_summary_logic | 16 | Counts, percentages, grade consistency |
| hash_chain | 20 | Content hash recomputation, stage hash cross-ref |
| limitations | 31 | Bias direction/magnitude enums |
| cross_stage_consistency | 15 | No duplicate IDs, receipt consistency |

Grade: A >= 99%, B >= 90%, C >= 75%, D >= 50%, F < 50%

## Report Structure

```json
{
  "schema_version": "1.0.0",
  "meta": {
    "report_id": "CAL-A1B2C3D4E5F6",
    "generated_at": "2026-04-27T...",
    "content_hash": "sha256..."
  },
  "stages": {
    "DISCOVER": { "status": "PASSED", "checks": [...], "receipt": {...} },
    "EVALUATE": { "status": "PASSED", ... },
    "INTEGRATE": { "status": "BLOCKED", "blockers": [...], "remediation": [...] },
    "MONITOR": { "status": "NOT_REACHED", ... },
    "TRUST": { "status": "NOT_REACHED", ... }
  },
  "current_stage": "EVALUATE",
  "next_command": "python3 acceptance_test.py ...",
  "progress_summary": { "stages_passed": 2, "grade": "D" },
  "hash_chain": { "algorithm": "SHA-256", ... },
  "limitations": [...]
}
```

Each stage contains:
- `prerequisites` — gating conditions from prior stages
- `completion_criteria` — what must be met to pass
- `checks` — individual check results with `check_id`, `passed`, `detail`, `tool`
- `blockers` — what prevents passing, with severity
- `remediation` — exact commands to fix blockers
- `source_artifacts` — URLs to the PF tools used
- `receipt` — SHA-256 stage_hash + inputs_hash for auditability

## Grade Map

| Stages Passed | Grade |
|--------------|-------|
| 5 | A |
| 4 | B |
| 3 | C |
| 2 | D |
| 0-1 | F |

## ID Patterns

- Check IDs: `CHK-DISC-1`, `CHK-EVAL-3`, `CHK-TRST-10`
- Prerequisites: `PRE-EVAL-1`, `PRE-INTG-1`
- Criteria: `CRI-DISC-1`, `CRI-TRST-1`
- Blockers: `BLK-DISC-1`, `BLK-MNTR-2`
- Remediation: `REM-DISC-1`, `REM-TRST-3`
- Artifacts: `ART-DISC-1`, `ART-TRST-4`
- Report ID: `CAL-[A-F0-9]{12}`

## Hash Chain

Reports support hash chaining for audit trails:

```bash
# First report
python3 climb_ladder.py --artifacts ./artifacts/ --producer sendoeth -o report_1.json

# Chained report
python3 climb_ladder.py --artifacts ./artifacts/ --producer sendoeth \
  --previous-hash <report_1_hash> -o report_2.json
```

## Limitations

| ID | Description | Bias Direction |
|----|-------------|---------------|
| L01 | Artifact file detection by filename only | UNDERSTATED_READINESS |
| L02 | No live endpoint testing — checks static artifacts only | OVERSTATED_READINESS |
| L03 | Single snapshot — not continuous monitoring | INDETERMINATE |
| L04 | Threshold sensitivity — grade boundaries are conventions | INDETERMINATE |
| L05 | Sequential gating blocks later stages even if healthy | UNDERSTATED_READINESS |
| L06 | Validates structure/thresholds, not end-to-end consumption | OVERSTATED_READINESS |

## Tests

```bash
python3 -m pytest tests/test_ladder.py -v
```

## Dependencies

Python 3.8+ stdlib only. Zero external dependencies.
