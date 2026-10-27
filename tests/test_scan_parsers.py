"""
Tests for Slice 1: Scan parsers - scan_parser() and lockfile_parser() for all 4 ecosystems.
Contract: verify output types, handle empty inputs, handle 1 edge case per ecosystem.
"""
import json
import pytest
from typing import Dict, Any

# Import the modules we'll implement
import sys

from pqblocks_cnsa_evidence.parsers import scan_parser, lockfile_parser


class TestScanParser:
    """Tests for scan_parser() function."""
    
    def test_scan_parser_empty_input(self):
        """Test scan_parser with empty scan JSON (edge case #1)."""
        empty_scan = {
            "algorithms": [],
            "tls_endpoints": [],
            "dependencies": [],
            "pqc_grades": {}
        }
        result = scan_parser(empty_scan)
        
        # Verify output type matches ScanResult TypedDict
        assert isinstance(result, dict)
        assert "algorithms" in result
        assert "tls_endpoints" in result
        assert "dependencies" in result
        assert "pqc_grades" in result
        assert result["algorithms"] == []
        assert result["tls_endpoints"] == []
        assert result["dependencies"] == []
        assert result["pqc_grades"] == {}
    
    def test_scan_parser_with_algorithms(self):
        """Test scan_parser with a typical scan JSON containing algorithms."""
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
            "tls_endpoints": [
                {"host": "example.com", "port": 443, "cipher_suites": ["TLS_AES_256_GCM_SHA384"]}
            ],
            "dependencies": [
                {"name": "cryptography", "version": "42.0.0", "ecosystem": "pypi"}
            ],
            "pqc_grades": {
                "ML-KEM-1024": "A",
                "RSA-2048": "D"
            }
        }
        result = scan_parser(scan_json)
        
        assert isinstance(result, dict)
        assert len(result["algorithms"]) == 2
        assert result["algorithms"][0]["name"] == "ML-KEM-1024"
        assert result["algorithms"][0]["type"] == "key-encapsulation"
        assert result["algorithms"][0]["mode"] == "PQC"
        assert result["algorithms"][0]["keySize"] == 1024
        assert result["algorithms"][0]["cnsA20Grade"] == "A"
        assert result["algorithms"][0]["breakYear"] == 2035
        
        assert len(result["tls_endpoints"]) == 1
        assert len(result["dependencies"]) == 1
        assert "ML-KEM-1024" in result["pqc_grades"]
    
    def test_scan_parser_unknown_algorithm(self):
        """Test scan_parser with unknown/unrecognized algorithm (edge case #4)."""
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
            "pqc_grades": {}
        }
        result = scan_parser(scan_json)
        
        assert len(result["algorithms"]) == 1
        assert result["algorithms"][0]["name"] == "UNKNOWN-ALGO-XYZ"
        assert result["algorithms"][0]["cnsA20Grade"] == "F"
        assert result["algorithms"][0]["mode"] == "unknown"


class TestLockfileParser:
    """Tests for lockfile_parser() function for all 4 ecosystems."""
    
    def test_lockfile_parser_python_requirements_txt(self):
        """Test lockfile_parser for Python requirements.txt (edge case: comments and blank lines)."""
        content = """
# This is a comment
requests==2.31.0
numpy>=1.24.0
# Another comment
cryptography==42.0.0

"""
        result = lockfile_parser("python", content)
        
        assert isinstance(result, dict)
        assert result["ecosystem"] == "python"
        assert "components" in result
        assert len(result["components"]) >= 2
        
        # Find requests component
        req = next((c for c in result["components"] if c["name"] == "requests"), None)
        assert req is not None
        assert req["version"] == "2.31.0"
        assert req["ecosystem"] == "python"
        assert req["type"] == "library"
        assert req["pqcClassification"] in ["PQC-native", "hybrid", "legacy", "unknown"]
    
    def test_lockfile_parser_python_pyproject_toml(self):
        """Test lockfile_parser for Python pyproject.toml."""
        content = """
[project]
name = "my-project"
version = "1.0.0"
dependencies = [
    "requests>=2.31.0",
    "cryptography==42.0.0",
]

[tool.poetry.dependencies]
python = "^3.11"
numpy = "^1.24.0"
"""
        result = lockfile_parser("python", content)
        
        assert isinstance(result, dict)
        assert result["ecosystem"] == "python"
        assert len(result["components"]) >= 2
    
    def test_lockfile_parser_java_maven(self):
        """Test lockfile_parser for Java Maven (edge case: scope exclusions)."""
        content = """<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
      <scope>compile</scope>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>2.23.1</version>
      <scope>provided</scope>
    </dependency>
  </dependencies>
</project>"""
        result = lockfile_parser("java", content)
        
        assert isinstance(result, dict)
        assert result["ecosystem"] == "java"
        assert len(result["components"]) >= 1
        
        # Check component structure
        comp = result["components"][0]
        assert comp["name"] == "org.bouncycastle:bcprov-jdk18on"
        assert comp["version"] == "1.78"
        assert comp["ecosystem"] == "java"
        assert comp["type"] == "library"
    
    def test_lockfile_parser_go_mod(self):
        """Test lockfile_parser for Go go.mod (edge case: replace directives)."""
        content = """module example.com/myproject

go 1.21

require (
    github.com/gorilla/mux v1.8.1
    golang.org/x/crypto v0.17.0
)

replace golang.org/x/crypto => golang.org/x/crypto v0.18.0
"""
        result = lockfile_parser("go", content)
        
        assert isinstance(result, dict)
        assert result["ecosystem"] == "go"
        assert len(result["components"]) >= 2
        
        comp = result["components"][0]
        assert comp["name"] == "github.com/gorilla/mux"
        assert comp["version"] == "v1.8.1"
        assert comp["ecosystem"] == "go"
        assert comp["type"] == "library"
    
    def test_lockfile_parser_js_package_lock(self):
        """Test lockfile_parser for JavaScript package-lock.json (edge case: nested dependencies)."""
        content = json.dumps({
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 2,
            "requires": True,
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                },
                "crypto-js": {
                    "version": "4.2.0",
                    "resolved": "https://registry.npmjs.org/crypto-js/-/crypto-js-4.2.0.tgz"
                }
            }
        })
        result = lockfile_parser("javascript", content)
        
        assert isinstance(result, dict)
        assert result["ecosystem"] == "javascript"
        assert len(result["components"]) >= 2
        
        comp = result["components"][0]
        assert comp["name"] == "lodash"
        assert comp["version"] == "4.17.21"
        assert comp["ecosystem"] == "javascript"
        assert comp["type"] == "library"
    
    def test_lockfile_parser_empty_input(self):
        """Test lockfile_parser with empty input (edge case #2/3)."""
        result = lockfile_parser("python", "")
        
        assert isinstance(result, dict)
        assert result["ecosystem"] == "python"
        assert result["components"] == []
    
    def test_lockfile_parser_missing_lockfile(self):
        """Test lockfile_parser handles missing lockfile gracefully (edge case #3)."""
        # For a missing lockfile, we'd call with empty content
        result = lockfile_parser("java", "")
        
        assert isinstance(result, dict)
        assert result["ecosystem"] == "java"
        assert result["components"] == []


class TestParserIntegration:
    """Integration tests combining scan and lockfile parsers."""
    
    def test_scan_and_lockfile_roundtrip(self):
        """Test that scan and lockfile parsers produce compatible structures."""
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
        
        # Both should be valid typed dicts
        assert "algorithms" in scan_result
        assert "components" in lockfile_result
        assert len(scan_result["algorithms"]) == 1
        assert len(lockfile_result["components"]) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])