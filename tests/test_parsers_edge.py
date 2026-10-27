"""Edge case tests for parsers.py to cover missing lines from coverage report."""
import pytest
import sys

from pqblocks_cnsa_evidence.parsers import scan_parser


def test_scan_parser_non_dict_input():
    """Test line 80: TypeError raised when parsed_scan is not a dict (H3 fix)."""
    # Test with None
    with pytest.raises(TypeError, match="Expected dict for parsed_scan"):
        scan_parser(None)

    # Test with string
    with pytest.raises(TypeError, match="Expected dict for parsed_scan"):
        scan_parser("not a dict")

    # Test with integer
    with pytest.raises(TypeError, match="Expected dict for parsed_scan"):
        scan_parser(42)

    # Test with list
    with pytest.raises(TypeError, match="Expected dict for parsed_scan"):
        scan_parser([])


def test_scan_parser_invalid_grade_fallback():
    """Test line 117: grade fallback to 'F' when grade is invalid."""
    scan_json = {
        "algorithms": [
            {
                "name": "TEST-ALGO",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 128,
                "cnsA20_grade": "X",  # Invalid grade
                "break_year": 2035,
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {},
    }
    result = scan_parser(scan_json)
    assert result["algorithms"][0]["cnsA20Grade"] == "F"  # Should fallback to F


def test_scan_parser_invalid_key_size():
    """Test lines 122-123: key_size conversion failure."""
    scan_json = {
        "algorithms": [
            {
                "name": "TEST-ALGO",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": "not_a_number",
                "cnsA20_grade": "A",
                "break_year": 2035,
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {},
    }
    result = scan_parser(scan_json)
    assert result["algorithms"][0]["keySize"] == 0  # Should fallback to 0


def test_scan_parser_invalid_break_year():
    """Test lines 128-129: break_year conversion failure."""
    scan_json = {
        "algorithms": [
            {
                "name": "TEST-ALGO",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 128,
                "cnsA20_grade": "A",
                "break_year": "not_a_year",
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {},
    }
    result = scan_parser(scan_json)
    assert result["algorithms"][0]["breakYear"] == 0  # Should fallback to 0


def test_scan_parser_pqc_grades_dont_overwrite():
    """Test line 161: pqc_grades don't overwrite if already set."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-1024",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 1024,
                "cnsA20_grade": "A",
                "break_year": 2035,
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {"ML-KEM-1024": "A"},  # Already set from algorithm
    }
    result = scan_parser(scan_json)
    # The first algorithm sets pqc_grades["ML-KEM-1024"] = "A"
    # The loop should not overwrite it
    assert result["pqc_grades"]["ML-KEM-1024"] == "A"


def test_attestation_hash_excludes_timestamp():
    """H2: attestation_hash is bit-identical across distinct tool_timestamps."""
    import hashlib
    import json
    from pqblocks_cnsa_evidence.parsers import attestation_emitter

    def _h(s):
        return hashlib.sha256(s.encode()).hexdigest()

    kw = dict(
        sbom_sha256=_h("sbom"), inventory_sha256=_h("inv"),
        narrative_sha256=_h("nar"), compliance_sha256=_h("comp"),
        migration_plan_sha256=_h("mig"), executive_summary_sha256=_h("exe"),
        tool_version="0.1.0", scan_json_sha256=_h("{}"),
        lockfile_hashes={"requirements.txt": _h("req")},
    )
    a1 = attestation_emitter(tool_timestamp="2026-10-09T00:00:00Z", **kw)
    a2 = attestation_emitter(tool_timestamp="2026-10-09T00:00:01Z", **kw)
    assert "attestation_hash" in a1, "emitter must return attestation_hash field"
    assert a1["attestation_hash"] == a2["attestation_hash"]
    body = {k: v for k, v in a1.items() if k not in ("tool_timestamp", "attestation_hash")}
    assert a1["attestation_hash"] == hashlib.sha256(
        json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def test_scan_parser_dep_missing_keys_loud():
    """H3-residual: dep dicts without name/version raise loudly, never passthrough."""
    with pytest.raises(TypeError, match="Dependency entry"):
        scan_parser({
            "algorithms": [], "tls_endpoints": [],
            "dependencies": [{"a": 1}], "pqc_grades": {},
        })


def test_scan_parser_nonfinite_key_size_coerced():
    """M1: key_size=inf coerces to 0 instead of raw OverflowError."""
    result = scan_parser({
        "algorithms": [{
            "name": "ML-KEM-768", "type": "key-encapsulation", "mode": "PQC",
            "key_size": float("inf"), "cnsA20_grade": "A",
            "break_year": float("inf"),
        }],
        "tls_endpoints": [], "dependencies": [], "pqc_grades": {},
    })
    assert result["algorithms"][0]["keySize"] == 0
    assert result["algorithms"][0]["breakYear"] == 0
