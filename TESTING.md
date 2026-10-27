# Testing Guide for pqblocks-cnsa-evidence

This document outlines the test methodology, execution instructions, component test suites, and coverage metrics for `pqblocks-cnsa-evidence`.

---

## Test Execution

Run the complete test suite with `pytest`:

```bash
pytest -v
```

To run with coverage reporting:

```bash
pytest --cov=pqblocks_cnsa_evidence --cov-report=term-missing
```

---

## Test Suite Summary

- **Total Collected**: 135 tests
- **Passing**: 135 passed
- **Warnings**: 9 expected `UserWarning`s (triggered by intentional garbage-input test fixtures)
- **Execution Time**: ~0.7 seconds
- **Statement Coverage**: 94% across 623 statements (39 missed)

### Coverage by Component

| Module | Statements | Missing | Coverage | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `__init__.py` | 3 | 0 | 100% | Top-level exports and public symbols |
| `migration_scheduler.py` | 2 | 0 | 100% | Convenience alias module |
| `narrative_emitter.py` | 2 | 0 | 100% | Convenience alias module |
| `parsers.py` | 616 | 39 | 94% | Complete parser, compiler, and emitter logic |
| **Total** | **623** | **39** | **94%** | |

---

## Detailed Test Modules

1. **Lockfile & CBOM Parsing**:
   - `tests/test_scan_parsers.py`: Tests parsing of CBOM JSON structures, Python lockfiles (`requirements.txt`, `pyproject.toml`, `setup.py`), Go (`go.mod`), JavaScript (`package-lock.json`), and Java (`pom.xml`).
   - `tests/test_parsers_edge.py`: Verifies resilience when encountering unusual dependency specifications, comments, and empty inputs.
   - `tests/test_g5_h3_loud.py`: Asserts loud warning behaviors when invalid or malformed data is supplied in lockfile fields.

2. **CycloneDX & CBOM Generation**:
   - `tests/test_Slice_2_SBOM_emitter.py`: Tests CycloneDX 1.6 structure, schema validation, and embedding of post-quantum properties.
   - `tests/test_Slice_3_Crypto_inventory.py`: Validates cryptographic asset extraction and categorization.

3. **Compliance & Scheduling Engines**:
   - `tests/test_Slice_4_Compliance_matrix.py`: Verifies CNSA 2.0 timeline evaluations and A through F grade determinations.
   - `tests/test_Slice_6_Migration_scheduler.py`: Tests timeline planning, phase calculation, and replacement prioritization.
   - `tests/test_migration_scheduler_coverage.py`: Exhaustive branch tests for calendar arithmetic and date boundary transitions.

4. **Narratives & Attestations**:
   - `tests/test_Slice_5_Narrative_emitter.py` & `test_Slice_5_Narrative_emitter_spec.py`: Verifies the presence of all five mandatory narrative sections (Exposed Keys, Retirement Milestones, Migration Strategy, Governance, and Exception Handling).
   - `tests/test_Slice_7_Executive_summary.py`: Validates executive brief formatting and risk rollups.
   - `tests/test_Slice_8_Attestation.py`: Verifies that SHA-256 attestation hashes are bit-identical and reproducible across repeated runs.
