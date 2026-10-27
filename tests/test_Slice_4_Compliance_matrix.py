"""
Tests for Slice 4: Compliance matrix - compliance_matrix_emitter() producing CNSA 2.0 compliance matrix.
Contract: Implement `compliance_matrix_emitter()`. Input: `ScanResult`. Output: 5-entry compliance matrix.
Tests: verify 5 requirements present; grades auto-derived from pqcframework thresholds; break-years from NIST IR 8413.
"""
import json
import pytest
import sys
from typing import TypedDict, Literal

# Import type definitions from spec/spec.md
class AlgorithmInfo(TypedDict):
    name: str  # e.g. "ML-KEM-1024", "ML-DSA-87", "AES-256", "SHA-384"
    type: Literal["key-encapsulation", "signature", "hash", "encryption"]
    mode: Literal["classical", "PQC", "hybrid"]
    keySize: int  # e.g. 1024, 87, 256, 384
    cnsA20Grade: Literal["A", "B", "C", "D", "F"]
    breakYear: int  # NIST IR 8413 estimate

class ScanResult(TypedDict):
    algorithms: list[AlgorithmInfo]
    tls_endpoints: list[dict]
    dependencies: list[dict]
    pqc_grades: dict[str, str]  # algorithm -> grade

class ComplianceMatrixEntry(TypedDict):
    requirement: Literal["key-establishment", "signature", "encryption", "hashing", "fallback"]
    algorithm: str
    evidence: Literal["found", "not-found", "partial"]
    grade: Literal["A", "B", "C", "D", "F"]
    breakYear: int

# Import the function we're testing
from pqblocks_cnsa_evidence.parsers import scan_parser


def test_compliance_matrix_emitter_empty_scan():
    """Test compliance_matrix_emitter with empty scan (edge case #1 from spec)."""
    # Create minimal scan result with no algorithms
    scan_result = scan_parser({
        "algorithms": [],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {}
    })
    
    # Import here to avoid circular issues at collection time
    from pqblocks_cnsa_evidence.parsers import compliance_matrix_emitter
    compliance_matrix = compliance_matrix_emitter(scan_result)
    
    # Verify output structure
    assert isinstance(compliance_matrix, dict)
    assert len(compliance_matrix) == 5  # 5 requirements
    
    # Verify all 5 requirements are present
    expected_requirements = ["key-establishment", "signature", "encryption", "hashing", "fallback"]
    for req in expected_requirements:
        assert req in compliance_matrix
        entry = compliance_matrix[req]
        assert isinstance(entry, dict)
        assert "requirement" in entry
        assert "algorithm" in entry
        assert "evidence" in entry
        assert "grade" in entry
        assert "breakYear" in entry
        
        # For empty scan, all should be not-found with default grade F and breakYear 0
        assert entry["requirement"] == req
        assert entry["algorithm"] == ""
        assert entry["evidence"] == "not-found"
        assert entry["grade"] == "F"
        assert entry["breakYear"] == 0


def test_compliance_matrix_emitter_with_algorithms():
    """Test compliance_matrix_emitter with scan containing algorithms."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-1024",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 1024,
                "cnsA20_grade": "A",
                "break_year": 2035
            },
            {
                "name": "ML-DSA-87",
                "type": "signature",
                "mode": "PQC",
                "key_size": 87,
                "cnsA20_grade": "A",
                "break_year": 2035
            },
            {
                "name": "AES-256",
                "type": "encryption",
                "mode": "classical",
                "key_size": 256,
                "cnsA20_grade": "B",
                "break_year": 2030
            },
            {
                "name": "SHA-384",
                "type": "hash",
                "mode": "classical",
                "key_size": 384,
                "cnsA20_grade": "B",
                "break_year": 2030
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {
            "ML-KEM-1024": "A",
            "ML-DSA-87": "A",
            "AES-256": "B",
            "SHA-384": "B"
        }
    }
    
    scan_result = scan_parser(scan_json)
    
    from pqblocks_cnsa_evidence.parsers import compliance_matrix_emitter
    compliance_matrix = compliance_matrix_emitter(scan_result)
    
    # Verify output structure
    assert isinstance(compliance_matrix, dict)
    assert len(compliance_matrix) == 5  # 5 requirements
    
    # Check key-establishment (should map to ML-KEM-1024)
    key_entry = compliance_matrix["key-establishment"]
    assert key_entry["requirement"] == "key-establishment"
    assert key_entry["algorithm"] == "ML-KEM-1024"
    assert key_entry["evidence"] == "found"
    assert key_entry["grade"] == "A"
    assert key_entry["breakYear"] == 2035
    
    # Check signature (should map to ML-DSA-87)
    sig_entry = compliance_matrix["signature"]
    assert sig_entry["requirement"] == "signature"
    assert sig_entry["algorithm"] == "ML-DSA-87"
    assert sig_entry["evidence"] == "found"
    assert sig_entry["grade"] == "A"
    assert sig_entry["breakYear"] == 2035
    
    # Check encryption (should map to AES-256)
    enc_entry = compliance_matrix["encryption"]
    assert enc_entry["requirement"] == "encryption"
    assert enc_entry["algorithm"] == "AES-256"
    assert enc_entry["evidence"] == "found"
    assert enc_entry["grade"] == "B"
    assert enc_entry["breakYear"] == 2030
    
    # Check hashing (should map to SHA-384)
    hash_entry = compliance_matrix["hashing"]
    assert hash_entry["requirement"] == "hashing"
    assert hash_entry["algorithm"] == "SHA-384"
    assert hash_entry["evidence"] == "found"
    assert hash_entry["grade"] == "B"
    assert hash_entry["breakYear"] == 2030
    
    # Check fallback (should be not-found since no fallback algorithm in scan)
    fallback_entry = compliance_matrix["fallback"]
    assert fallback_entry["requirement"] == "fallback"
    assert fallback_entry["algorithm"] == ""
    assert fallback_entry["evidence"] == "not-found"
    assert fallback_entry["grade"] == "F"
    assert fallback_entry["breakYear"] == 0


def test_compliance_matrix_emitter_grade_thresholds():
    """Test compliance_matrix_emitter correctly derives grades from pqcframework thresholds."""
    # Test boundary values for grades
    scan_json = {
        "algorithms": [
            {
                "name": "GRADE_A_ALGO",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 1024,
                "cnsA20_grade": "A",  # score >= 85
                "break_year": 2035
            },
            {
                "name": "GRADE_B_ALGO",
                "type": "signature",
                "mode": "PQC",
                "key_size": 87,
                "cnsA20_grade": "B",  # 70 <= score < 85
                "break_year": 2034
            },
            {
                "name": "GRADE_C_ALGO",
                "type": "encryption",
                "mode": "classical",
                "key_size": 256,
                "cnsA20_grade": "C",  # 55 <= score < 70
                "break_year": 2033
            },
            {
                "name": "GRADE_D_ALGO",
                "type": "hash",
                "mode": "classical",
                "key_size": 384,
                "cnsA20_grade": "D",  # 40 <= score < 55
                "break_year": 2032
            },
            {
                "name": "GRADE_F_ALGO",
                "type": "key-encapsulation",
                "mode": "hybrid",
                "key_size": 512,
                "cnsA20_grade": "F",  # score < 40
                "break_year": 2031
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {
            "GRADE_A_ALGO": "A",
            "GRADE_B_ALGO": "B",
            "GRADE_C_ALGO": "C",
            "GRADE_D_ALGO": "D",
            "GRADE_F_ALGO": "F"
        }
    }
    
    scan_result = scan_parser(scan_json)
    
    from pqblocks_cnsa_evidence.parsers import compliance_matrix_emitter
    compliance_matrix = compliance_matrix_emitter(scan_result)
    
    # Verify grades are correctly preserved
    assert compliance_matrix["key-establishment"]["grade"] == "A"
    assert compliance_matrix["signature"]["grade"] == "B"
    assert compliance_matrix["encryption"]["grade"] == "C"
    assert compliance_matrix["hashing"]["grade"] == "D"
    # Note: fallback will be not-found since we didn't map GRADE_F_ALGO to fallback requirement


def test_compliance_matrix_emitter_break_years_from_nist():
    """Test compliance_matrix_emitter correctly uses break-years from NIST IR 8413."""
    scan_json = {
        "algorithms": [
            {
                "name": "ALGORITHM_2025",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 1024,
                "cnsA20_grade": "A",
                "break_year": 2025  # From NIST IR 8413
            },
            {
                "name": "ALGORITHM_2030",
                "type": "signature",
                "mode": "PQC",
                "key_size": 87,
                "cnsA20_grade": "A",
                "break_year": 2030  # From NIST IR 8413
            },
            {
                "name": "ALGORITHM_2035",
                "type": "encryption",
                "mode": "classical",
                "key_size": 256,
                "cnsA20_grade": "B",
                "break_year": 2035  # From NIST IR 8413
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {
            "ALGORITHM_2025": "A",
            "ALGORITHM_2030": "A",
            "ALGORITHM_2035": "B"
        }
    }
    
    scan_result = scan_parser(scan_json)
    
    from pqblocks_cnsa_evidence.parsers import compliance_matrix_emitter
    compliance_matrix = compliance_matrix_emitter(scan_result)
    
    # Verify break years are correctly preserved from NIST IR 8413
    assert compliance_matrix["key-establishment"]["breakYear"] == 2025
    assert compliance_matrix["signature"]["breakYear"] == 2030
    assert compliance_matrix["encryption"]["breakYear"] == 2035


def test_compliance_matrix_emitter_partial_evidence():
    """Test compliance_matrix_emitter handles partial evidence (edge case #4, #10 from spec)."""
    scan_json = {
        "algorithms": [
            {
                "name": "PARTIAL_ALGORITHM",
                "type": "key-encapsulation",
                "mode": "unknown",  # Unknown mode -> will be treated as partial
                "key_size": 1024,
                "cnsA20_grade": "F",
                "break_year": 2030
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {
            "PARTIAL_ALGORITHM": "F"
        }
    }
    
    scan_result = scan_parser(scan_json)
    
    from pqblocks_cnsa_evidence.parsers import compliance_matrix_emitter
    compliance_matrix = compliance_matrix_emitter(scan_result)
    
    # For partial/unknown algorithms, evidence should be "partial"
    key_entry = compliance_matrix["key-establishment"]
    assert key_entry["evidence"] == "partial"
    assert key_entry["algorithm"] == "PARTIAL_ALGORITHM"
    assert key_entry["grade"] == "F"
    assert key_entry["breakYear"] == 2030


def test_compliance_matrix_emitter_deterministic_output():
    """Test that compliance_matrix_emitter produces deterministic output."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-1024",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 1024,
                "cnsA20_grade": "A",
                "break_year": 2035
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {
            "ML-KEM-1024": "A"
        }
    }
    
    scan_result = scan_parser(scan_json)
    
    from pqblocks_cnsa_evidence.parsers import compliance_matrix_emitter
    
    # Run 3 times
    matrix1 = compliance_matrix_emitter(scan_result)
    matrix2 = compliance_matrix_emitter(scan_result)
    matrix3 = compliance_matrix_emitter(scan_result)
    
    # All should be bit-identical
    assert matrix1 == matrix2 == matrix3, "Compliance matrix output is not deterministic across 3 runs"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])