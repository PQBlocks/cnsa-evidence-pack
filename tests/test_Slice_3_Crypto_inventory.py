"""
Tests for Slice 3: Crypto inventory - crypto_inventory_emitter() producing flat algorithm-to-file inventory dict.
Contract: verify all algorithms from scan are listed; edge case: empty scan produces empty inventory.
"""
import json
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import the modules we need
from pqblocks_cnsa_evidence.parsers import scan_parser, lockfile_parser

def test_crypto_inventory_emitter_empty_scan():
    """Test crypto_inventory_emitter with empty scan (edge case from spec)."""
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
    from pqblocks_cnsa_evidence.parsers import crypto_inventory_emitter
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    
    # Verify inventory structure
    assert isinstance(inventory, dict)
    # Empty scan should produce empty inventory
    assert inventory == {}

def test_crypto_inventory_emitter_with_algorithms():
    """Test crypto_inventory_emitter with scan containing algorithms."""
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
    
    from pqblocks_cnsa_evidence.parsers import crypto_inventory_emitter
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    
    # Verify inventory structure
    assert isinstance(inventory, dict)
    # Should have entries for both algorithms
    assert "ML-KEM-1024" in inventory
    assert "RSA-2048" in inventory
    
    # Verify each algorithm entry has required fields
    for algo_name, algo_info in inventory.items():
        assert "files" in algo_info
        assert "keySize" in algo_info
        assert "breakYear" in algo_info
        assert "cnsA20Grade" in algo_info
        
        # Verify field types
        assert isinstance(algo_info["files"], list)
        assert isinstance(algo_info["keySize"], int)
        assert isinstance(algo_info["breakYear"], int)
        assert algo_info["cnsA20Grade"] in ["A", "B", "C", "D", "F"]
        
        # Verify specific values
        if algo_name == "ML-KEM-1024":
            assert algo_info["keySize"] == 1024
            assert algo_info["breakYear"] == 2035
            assert algo_info["cnsA20Grade"] == "A"
        elif algo_name == "RSA-2048":
            assert algo_info["keySize"] == 2048
            assert algo_info["breakYear"] == 2030
            assert algo_info["cnsA20Grade"] == "D"

def test_crypto_inventory_emitter_with_file_paths():
    """Test that crypto_inventory_emitter correctly maps algorithms to file paths."""
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
        "tls_endpoints": [
            {
                "host": "example.com",
                "port": 443,
                "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
                "file_path": "src/network/tls_config.py"
            }
        ],
        "dependencies": [
            {
                "name": "cryptography",
                "version": "42.0.0",
                "ecosystem": "pypi",
                "file_path": "requirements.txt"
            }
        ],
        "pqc_grades": {"ML-KEM-768": "A"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = lockfile_parser("python", "cryptography==42.0.0\n")
    
    from pqblocks_cnsa_evidence.parsers import crypto_inventory_emitter
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    
    # Verify the algorithm is present
    assert "ML-KEM-768" in inventory
    algo_info = inventory["ML-KEM-768"]
    
    # Should have collected file paths from both TLS endpoints and dependencies
    files = algo_info["files"]
    assert isinstance(files, list)
    assert len(files) >= 2  # At least TLS endpoint and dependency
    
    # Check that we have the expected file paths
    file_paths = set(files)
    assert "src/network/tls_config.py" in file_paths
    assert "requirements.txt" in file_paths

def test_crypto_inventory_emitter_multiple_same_algorithm():
    """Test crypto_inventory_emitter with multiple instances of same algorithm."""
    scan_json = {
        "algorithms": [
            {
                "name": "AES-256",
                "type": "encryption",
                "mode": "classical",
                "key_size": 256,
                "cnsA20_grade": "B",
                "break_year": 2030
            },
            {
                "name": "AES-256",  # Same algorithm, different context
                "type": "encryption",
                "mode": "classical",
                "key_size": 256,
                "cnsA20_grade": "B",
                "break_year": 2030
            }
        ],
        "tls_endpoints": [
            {
                "host": "server1.example.com",
                "port": 443,
                "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
                "file_path": "config/server1.yml"
            },
            {
                "host": "server2.example.com",
                "port": 443,
                "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
                "file_path": "config/server2.yml"
            }
        ],
        "dependencies": [],
        "pqc_grades": {"AES-256": "B"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = lockfile_parser("python", "")
    
    from pqblocks_cnsa_evidence.parsers import crypto_inventory_emitter
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    
    # Should have one entry for AES-256
    assert "AES-256" in inventory
    algo_info = inventory["AES-256"]
    
    # Should have collected both file paths
    files = algo_info["files"]
    assert isinstance(files, list)
    assert len(files) == 2
    assert "config/server1.yml" in files
    assert "config/server2.yml" in files
    
    # Other fields should be consistent
    assert algo_info["keySize"] == 256
    assert algo_info["breakYear"] == 2030
    assert algo_info["cnsA20Grade"] == "B"

def test_crypto_inventory_emitter_unknown_algorithm():
    """Test crypto_inventory_emitter with unknown algorithm (edge case #4)."""
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
    
    from pqblocks_cnsa_evidence.parsers import crypto_inventory_emitter
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    
    # Verify the unknown algorithm is present
    assert "UNKNOWN-ALGO-XYZ" in inventory
    algo_info = inventory["UNKNOWN-ALGO-XYZ"]
    
    # Should have the correct values
    assert algo_info["keySize"] == 0
    assert algo_info["breakYear"] == 0
    assert algo_info["cnsA20Grade"] == "F"
    assert isinstance(algo_info["files"], list)

def test_crypto_inventory_emitter_deterministic_output():
    """Test that crypto_inventory_emitter produces deterministic output."""
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
        "tls_endpoints": [
            {
                "host": "example.com",
                "port": 443,
                "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
                "file_path": "src/network/tls_config.py"
            }
        ],
        "dependencies": [
            {
                "name": "cryptography",
                "version": "42.0.0",
                "ecosystem": "pypi",
                "file_path": "requirements.txt"
            }
        ],
        "pqc_grades": {"ML-KEM-768": "A"}
    }
    
    scan_result = scan_parser(scan_json)
    lockfile_result = lockfile_parser("python", "cryptography==42.0.0\n")
    
    from pqblocks_cnsa_evidence.parsers import crypto_inventory_emitter
    
    # Run 3 times
    inventory1 = crypto_inventory_emitter(scan_result, lockfile_result)
    inventory2 = crypto_inventory_emitter(scan_result, lockfile_result)
    inventory3 = crypto_inventory_emitter(scan_result, lockfile_result)
    
    # All should be bit-identical
    assert inventory1 == inventory2 == inventory3

def test_crypto_inventory_emitter_missing_lockfile_ecosystem():
    """Test crypto_inventory_emitter handles missing lockfile gracefully."""
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
    
    from pqblocks_cnsa_evidence.parsers import crypto_inventory_emitter
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    
    # Should still produce valid inventory
    assert isinstance(inventory, dict)
    assert "ML-KEM-768" in inventory
    
    # Should have algorithm info but potentially fewer files (no lockfile deps)
    algo_info = inventory["ML-KEM-768"]
    assert algo_info["keySize"] == 768
    assert algo_info["breakYear"] == 2035
    assert algo_info["cnsA20Grade"] == "A"
    assert isinstance(algo_info["files"], list)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])