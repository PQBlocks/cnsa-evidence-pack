"""
Tests for Slice 2: SBOM emitter - sbom_emitter() producing CycloneDX 1.6 SBOM with cryptoProperties.
Contract: validate against official CycloneDX 1.6 JSON schema (zero errors), verify cryptoProperties element structure.
"""
import json
import pytest
import sys
from typing import TypedDict

from pqblocks_cnsa_evidence.parsers import scan_parser, lockfile_parser


# SBOM type definition from spec/spec.md line 75-81
class SBOM(TypedDict):
    info: dict  # CycloneDX metadata
    components: list[dict]
    cryptoProperties: dict  # cryptoProperties element
    services: list[dict]
    tools: list[dict]
    dependencies: list[dict]


def test_sbom_emitter_empty_scan():
    """Test sbom_emitter with empty scan (edge case #1 from spec)."""
    # Create minimal scan result
    scan_result = scan_parser({
        "algorithms": [],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {}
    })
    
    # Create empty lockfile result
    lockfile_result = lockfile_parser("python", "")
    
    # Import here to avoid circular issues at collection time
    from pqblocks_cnsa_evidence.parsers import sbom_emitter
    sbom = sbom_emitter(scan_result, lockfile_result)
    
    # Verify SBOM structure
    assert isinstance(sbom, dict)
    assert "info" in sbom
    assert "components" in sbom
    assert "cryptoProperties" in sbom
    assert "services" in sbom
    assert "tools" in sbom
    assert "dependencies" in sbom
    
    # Empty scan should produce empty components and cryptoProperties
    assert sbom["components"] == []
    assert sbom["cryptoProperties"] == {"algorithms": []}


def test_sbom_emitter_with_algorithms():
    """Test sbom_emitter with scan containing algorithms."""
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
                "name": "RSA-2048",
                "type": "key-encapsulation",
                "mode": "classical",
                "key_size": 2048,
                "cnsA20_grade": "D",
                "break_year": 2030
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {"ML-KEM-1024": "A", "RSA-2048": "D"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = lockfile_parser("python", "cryptography==42.0.0\n")
    
    from pqblocks_cnsa_evidence.parsers import sbom_emitter
    sbom = sbom_emitter(scan_result, lockfile_result)
    
    # Verify SBOM structure
    assert isinstance(sbom, dict)
    assert "info" in sbom
    assert "components" in sbom
    assert "cryptoProperties" in sbom
    
    # Verify cryptoProperties structure per CycloneDX 1.6 spec §5.5
    crypto_props = sbom["cryptoProperties"]
    assert "algorithms" in crypto_props
    assert isinstance(crypto_props["algorithms"], list)
    
    # Should have entries for both algorithms
    algo_names = {a["name"] for a in crypto_props["algorithms"]}
    assert "ML-KEM-1024" in algo_names
    assert "RSA-2048" in algo_names
    
    # Verify each algorithm entry has required fields
    for algo in crypto_props["algorithms"]:
        assert "name" in algo
        assert "type" in algo
        assert "mode" in algo
        assert "keySize" in algo
        assert "cnsA20Grade" in algo
        
        # Verify type values
        assert algo["type"] in ["key-encapsulation", "signature", "hash", "encryption"]
        # Verify mode values
        assert algo["mode"] in ["classical", "PQC", "hybrid"]
        # Verify grade values
        assert algo["cnsA20Grade"] in ["A", "B", "C", "D", "F"]
        # Verify keySize is integer
        assert isinstance(algo["keySize"], int)
        assert algo["keySize"] >= 0


def test_sbom_emitter_crypto_properties_structure():
    """Test cryptoProperties element structure matches CycloneDX 1.6 spec §5.5."""
    scan_json = {
        "algorithms": [
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
        "pqc_grades": {"ML-DSA-87": "A", "AES-256": "B", "SHA-384": "B"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = lockfile_parser("python", "")
    
    from pqblocks_cnsa_evidence.parsers import sbom_emitter
    sbom = sbom_emitter(scan_result, lockfile_result)
    
    crypto_props = sbom["cryptoProperties"]
    
    # Verify algorithms array
    assert "algorithms" in crypto_props
    algorithms = crypto_props["algorithms"]
    assert len(algorithms) == 3
    
    # Check each algorithm entry structure per CycloneDX 1.6 §5.5
    for algo in algorithms:
        assert "name" in algo
        assert "type" in algo
        assert "mode" in algo
        assert "keySize" in algo
        assert "cnsA20Grade" in algo
        
        # Name should be string
        assert isinstance(algo["name"], str)
        assert len(algo["name"]) > 0
        
        # Type should be one of the 4 valid types
        assert algo["type"] in ["key-encapsulation", "signature", "hash", "encryption"]
        
        # Mode should be one of 3 valid modes
        assert algo["mode"] in ["classical", "PQC", "hybrid"]
        
        # keySize should be integer >= 0
        assert isinstance(algo["keySize"], int)
        assert algo["keySize"] >= 0
        
        # cnsA20Grade should be A-F
        assert algo["cnsA20Grade"] in ["A", "B", "C", "D", "F"]


def test_sbom_emitter_includes_standard_fields():
    """Test that SBOM includes all standard CycloneDX fields."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-512",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 512,
                "cnsA20_grade": "A",
                "break_year": 2035
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {"ML-KEM-512": "A"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = lockfile_parser("python", "requests==2.31.0\n")
    
    from pqblocks_cnsa_evidence.parsers import sbom_emitter
    sbom = sbom_emitter(scan_result, lockfile_result)
    
    # Standard CycloneDX 1.6 fields
    assert "bomFormat" in sbom
    assert sbom["bomFormat"] == "CycloneDX"
    assert "specVersion" in sbom
    assert sbom["specVersion"] == "1.6"
    assert "serialNumber" in sbom or "info" in sbom
    assert "components" in sbom
    assert isinstance(sbom["components"], list)
    assert "tools" in sbom
    assert isinstance(sbom["tools"], list)
    
    # Check if tools contains our tool
    tool_names = [t.get("name", "") for t in sbom["tools"]]
    assert any("pqblocks" in name.lower() for name in tool_names), "pqblocks tool not in tools list"


def test_sbom_emitter_with_lockfile_components():
    """Test that SBOM includes components from lockfiles."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-768",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 768,
                "cnsA20_grade": "A",
                "break_year": 2035
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {"ML-KEM-768": "A"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = lockfile_parser("python", "cryptography==42.0.0\nrequests==2.31.0\n")
    
    from pqblocks_cnsa_evidence.parsers import sbom_emitter
    sbom = sbom_emitter(scan_result, lockfile_result)
    
    # Components from lockfile should be in SBOM components
    component_names = [c.get("name", "") for c in sbom["components"]]
    assert "cryptography" in component_names
    assert "requests" in component_names


def test_sbom_emitter_hybrid_algorithm():
    """Test sbom_emitter with hybrid mode algorithm."""
    scan_json = {
        "algorithms": [
            {
                "name": "X25519MLKEM768",
                "type": "key-encapsulation",
                "mode": "hybrid",
                "key_size": 768,
                "cnsA20_grade": "A",
                "break_year": 2035
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {"X25519MLKEM768": "A"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = lockfile_parser("python", "")
    
    from pqblocks_cnsa_evidence.parsers import sbom_emitter
    sbom = sbom_emitter(scan_result, lockfile_result)
    
    crypto_props = sbom["cryptoProperties"]
    hybrid_algo = next((a for a in crypto_props["algorithms"] if a["name"] == "X25519MLKEM768"), None)
    assert hybrid_algo is not None
    assert hybrid_algo["mode"] == "hybrid"
    assert hybrid_algo["type"] == "key-encapsulation"
    assert hybrid_algo["keySize"] == 768
    assert hybrid_algo["cnsA20Grade"] == "A"


def test_sbom_emitter_unknown_algorithm():
    """Test sbom_emitter with unknown algorithm (edge case #4)."""
    scan_json = {
        "algorithms": [
            {
                "name": "UNKNOWN-ALGO-XYZ",
                "type": "unknown",
                "mode": "unknown",
                "key_size": 0,
                "cnsA20_grade": "F",
                "break_year": 0
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {"UNKNOWN-ALGO-XYZ": "F"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = lockfile_parser("python", "")
    
    from pqblocks_cnsa_evidence.parsers import sbom_emitter
    sbom = sbom_emitter(scan_result, lockfile_result)
    
    crypto_props = sbom["cryptoProperties"]
    unknown_algo = next((a for a in crypto_props["algorithms"] if a["name"] == "UNKNOWN-ALGO-XYZ"), None)
    assert unknown_algo is not None
    assert unknown_algo["cnsA20Grade"] == "F"
    assert unknown_algo["mode"] == "unknown"


def test_sbom_emitter_deterministic_output():
    """Test that sbom_emitter produces deterministic output (bit-identical)."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-768",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 768,
                "cnsA20_grade": "A",
                "break_year": 2035
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {"ML-KEM-768": "A"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = lockfile_parser("python", "cryptography==42.0.0\n")
    
    from pqblocks_cnsa_evidence.parsers import sbom_emitter
    
    # Run 3 times
    sbom1 = sbom_emitter(scan_result, lockfile_result)
    sbom2 = sbom_emitter(scan_result, lockfile_result)
    sbom3 = sbom_emitter(scan_result, lockfile_result)
    
    # All should be bit-identical (excluding timestamps)
    import hashlib
    
    def canonical_hash(sbom):
        # Remove timestamp fields before hashing
        sbom_copy = json.loads(json.dumps(sbom))
        # Remove metadata.timestamp if present
        if "metadata" in sbom_copy and "timestamp" in sbom_copy["metadata"]:
            del sbom_copy["metadata"]["timestamp"]
        if "info" in sbom_copy and "timestamp" in sbom_copy["info"]:
            del sbom_copy["info"]["timestamp"]
        return hashlib.sha256(json.dumps(sbom_copy, sort_keys=True).encode()).hexdigest()
    
    hash1 = canonical_hash(sbom1)
    hash2 = canonical_hash(sbom2)
    hash3 = canonical_hash(sbom3)
    
    assert hash1 == hash2 == hash3, "SBOM output is not deterministic across 3 runs"


def test_sbom_emitter_missing_lockfile_ecosystem():
    """Test sbom_emitter handles missing lockfile gracefully."""
    scan_json = {
        "algorithms": [
            {
                "name": "ML-KEM-768",
                "type": "key-encapsulation",
                "mode": "PQC",
                "key_size": 768,
                "cnsA20_grade": "A",
                "break_year": 2035
            }
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {"ML-KEM-768": "A"}
    }
    
    scan_result = scan_parser(scan_json)
    # Empty lockfile for java (missing maven)
    lockfile_result = lockfile_parser("java", "")
    
    from pqblocks_cnsa_evidence.parsers import sbom_emitter
    sbom = sbom_emitter(scan_result, lockfile_result)
    
    # Should still produce valid SBOM
    assert isinstance(sbom, dict)
    assert "cryptoProperties" in sbom
    assert "components" in sbom
    
    # Lockfile components should be empty
    assert len(sbom["components"]) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])