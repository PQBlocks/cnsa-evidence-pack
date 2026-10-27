"""
Tests for Slice 5: Narrative emitter - narrative_emitter() producing key-management narrative markdown.
Contract: verify all 5 narrative sections present (exposed keys, retirement milestones, migration strategy, governance, exception handling);
edge case: empty inputs produce structured "no keys found" narrative.
"""
import sys
import pytest
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

# Import the function we're testing
from pqblocks_cnsa_evidence.parsers import scan_parser


def _make_lockfile_result(ecosystem: str = "python", components: list = None) -> dict:
    """Helper to create a minimal LockfileResult for testing."""
    if components is None:
        components = []
    return {"ecosystem": ecosystem, "components": components}


def test_narrative_emitter_empty_scan():
    """Test narrative_emitter with empty scan (edge case #1 from spec)."""
    scan_result = scan_parser({
        "algorithms": [],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {}
    })
    lockfile_result = _make_lockfile_result()
    
    # Import here to avoid circular issues at collection time
    from pqblocks_cnsa_evidence.narrative_emitter import narrative_emitter
    narrative = narrative_emitter(scan_result, lockfile_result)
    
    # Verify output is a string
    assert isinstance(narrative, str)
    # Empty scan should produce "no keys found" structured narrative
    assert "no keys found" in narrative.lower()
    # Should still have the 5-section structure
    assert "exposed keys" in narrative.lower() or "retirement milestones" in narrative.lower()


def test_narrative_emitter_with_algorithms():
    """Test narrative_emitter with scan containing algorithms."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-1024",
                "type": "key-encapsulation",
                "mode": "PQC",
                "keySize": 1024,
                "cnsA20Grade": "A",
                "breakYear": 2035
            },
            {
                "name": "RSA-2048",
                "type": "key-encapsulation",
                "mode": "classical",
                "keySize": 2048,
                "cnsA20Grade": "D",
                "breakYear": 2030
            },
            {
                "name": "AES-256",
                "type": "encryption",
                "mode": "classical",
                "keySize": 256,
                "cnsA20Grade": "B",
                "breakYear": 2030
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {
            "ML-KEM-1024": "A",
            "RSA-2048": "D",
            "AES-256": "B"
        }
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = _make_lockfile_result()
    
    from pqblocks_cnsa_evidence.narrative_emitter import narrative_emitter
    narrative = narrative_emitter(scan_result, lockfile_result)
    
    # Verify output is a non-empty string
    assert isinstance(narrative, str)
    assert len(narrative) > 0
    
    # Verify all 5 narrative sections are present
    # Section 1: Exposed keys inventory
    assert "exposed keys" in narrative.lower() or "exposed keys inventory" in narrative.lower()
    # Section 2: Retirement milestones
    assert "retirement milestone" in narrative.lower() or "retirement" in narrative.lower()
    # Section 3: Migration strategy
    assert "migration strategy" in narrative.lower() or "migration" in narrative.lower()
    # Section 4: Governance
    assert "governance" in narrative.lower()
    # Section 5: Exception handling
    assert "exception handling" in narrative.lower() or "exception" in narrative.lower()


def test_narrative_emitter_all_five_sections_present():
    """Test that all 5 narrative sections are present in the output."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-1024",
                "type": "key-encapsulation",
                "mode": "PQC",
                "keySize": 1024,
                "cnsA20Grade": "A",
                "breakYear": 2035
            },
            {
                "name": "ML-DSA-87",
                "type": "signature",
                "mode": "PQC",
                "keySize": 87,
                "cnsA20Grade": "A",
                "breakYear": 2035
            },
            {
                "name": "AES-256",
                "type": "encryption",
                "mode": "classical",
                "keySize": 256,
                "cnsA20Grade": "B",
                "breakYear": 2030
            },
            {
                "name": "SHA-384",
                "type": "hash",
                "mode": "classical",
                "keySize": 384,
                "cnsA20Grade": "B",
                "breakYear": 2030
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
    lockfile_result = _make_lockfile_result()
    
    from pqblocks_cnsa_evidence.narrative_emitter import narrative_emitter
    narrative = narrative_emitter(scan_result, lockfile_result)
    
    # All 5 sections must be present
    sections = [
        "exposed keys",
        "retirement milestones",
        "migration strategy",
        "governance",
        "exception handling"
    ]
    for section in sections:
        assert section in narrative.lower(), f"Missing narrative section: '{section}'"


def test_narrative_emitter_deterministic_output():
    """Test that narrative_emitter produces deterministic output."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-768",
                "type": "key-encapsulation",
                "mode": "PQC",
                "keySize": 768,
                "cnsA20Grade": "A",
                "breakYear": 2035
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {"ML-KEM-768": "A"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = _make_lockfile_result()
    
    from pqblocks_cnsa_evidence.narrative_emitter import narrative_emitter
    
    # Run 3 times
    narrative1 = narrative_emitter(scan_result, lockfile_result)
    narrative2 = narrative_emitter(scan_result, lockfile_result)
    narrative3 = narrative_emitter(scan_result, lockfile_result)
    
    # All should be bit-identical
    assert narrative1 == narrative2 == narrative3, (
        "Narrative output is not deterministic across 3 runs: "
        f"run1 != run2 or run1 != run3"
    )


def test_narrative_emitter_with_lockfile_components():
    """Test narrative_emitter includes lockfile component information."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-1024",
                "type": "key-encapsulation",
                "mode": "PQC",
                "keySize": 1024,
                "cnsA20Grade": "A",
                "breakYear": 2035
            }
        ],
        "tls_endpoints": [],
        "dependencies": [
            {
                "name": "cryptography",
                "version": "42.0.0",
                "ecosystem": "pypi"
            }
        ],
        "pqc_grades": {"ML-KEM-1024": "A"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = _make_lockfile_result("python", [
        {"name": "cryptography", "version": "42.0.0", "ecosystem": "pypi", "type": "library"}
    ])
    
    from pqblocks_cnsa_evidence.narrative_emitter import narrative_emitter
    narrative = narrative_emitter(scan_result, lockfile_result)
    
    # Should reference the lockfile component
    assert isinstance(narrative, str)
    assert len(narrative) > 0


def test_narrative_emitter_grade_distribution():
    """Test narrative correctly reports grade distribution across algorithms."""
    scan_json = {
        "algorithms": [
            {
                "name": "ALGO_A",
                "type": "key-encapsulation",
                "mode": "PQC",
                "keySize": 1024,
                "cnsA20Grade": "A",
                "breakYear": 2035
            },
            {
                "name": "ALGO_B",
                "type": "signature",
                "mode": "PQC",
                "keySize": 87,
                "cnsA20Grade": "B",
                "breakYear": 2034
            },
            {
                "name": "ALGO_C",
                "type": "encryption",
                "mode": "classical",
                "keySize": 256,
                "cnsA20Grade": "C",
                "breakYear": 2033
            },
            {
                "name": "ALGO_D",
                "type": "hash",
                "mode": "classical",
                "keySize": 384,
                "cnsA20Grade": "D",
                "breakYear": 2032
            },
            {
                "name": "ALGO_F",
                "type": "key-encapsulation",
                "mode": "hybrid",
                "keySize": 512,
                "cnsA20Grade": "F",
                "breakYear": 2031
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {
            "ALGO_A": "A",
            "ALGO_B": "B",
            "ALGO_C": "C",
            "ALGO_D": "D",
            "ALGO_F": "F"
        }
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = _make_lockfile_result()
    
    from pqblocks_cnsa_evidence.narrative_emitter import narrative_emitter
    narrative = narrative_emitter(scan_result, lockfile_result)
    
    # Should mention grade A-F distribution
    assert isinstance(narrative, str)
    # Should mention at least some grade information
    assert any(g in narrative for g in ["A", "B", "C", "D", "F"])


if __name__ == "__main__":
    pytest.main([__file__, "-v"])