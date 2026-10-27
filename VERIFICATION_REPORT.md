# Verification Report: pqblocks-cnsa-evidence

This report summarizes the verification of `pqblocks-cnsa-evidence` prior to release.

---

## Verification Summary

- **Status**: VERIFIED
- **Package**: `pqblocks-cnsa-evidence`
- **Release Version**: 0.1.0
- **Test Results**: 135 passed, 0 failed in 0.73s
- **Code Coverage**: 94% statement coverage (623 statements, 39 missed)
- **Supported Python Matrix**: CPython 3.11, 3.12, 3.13, 3.14
- **Packaging Validation**: `uv build` (sdist + wheel) and `twine check --strict` PASS
- **Leak Gate Audit**: 0 hits across all package files and built artifacts

---

## Verification Criteria & Evidence

### 1. Functional & Regulatory Test Execution
- The complete test suite was executed across all parser, compiler, and emitter modules.
- 135 tests passed without regressions.
- Multi-ecosystem lockfile parsers (Python, Go, JS, Maven) and CycloneDX 1.6 CBOM synthesis verified.
- Bit-identical reproducibility of cryptographic attestations verified.

### 2. Multi-Python Environment Verification
The package was verified across clean virtual environments for each supported Python minor version:
- Python 3.11: Wheel installation, test suite execution, and example runs PASS
- Python 3.12: Wheel installation, test suite execution, and example runs PASS
- Python 3.13: Wheel installation, test suite execution, and example runs PASS
- Python 3.14: Wheel installation, test suite execution, and example runs PASS

### 3. Build & Packaging Integrity
- Built source distribution (`.tar.gz`) and binary wheel (`.whl`) via `uv build`.
- Validated package metadata, dependencies, classifiers, and formatting with `twine check --strict`.
- Confirmed dependencies install cleanly from public PyPI without external repository requirements.

### 4. Leak Gate Audit
All source code, documentation, test files, and package metadata scanned:
- No internal repository paths or local developer filesystem references.
- No internal gate markers or rule IDs.
- Strict enforcement of the `PQBlocks` / `pqblocks-cnsa-evidence` public brand name.

---

## Verification Conclusion

`pqblocks-cnsa-evidence` meets all release gate standards. All compliance classification engines, report generators, and cryptographic attestations are verified with full traceability to real test executions.
