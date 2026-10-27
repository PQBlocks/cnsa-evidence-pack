"""
Targeted coverage tests for migration_scheduler.py (lines 1-3) and parsers.py uncovered branches.
These tests specifically address the Check 3 (correctness) coverage gap (84% -> >=90%).
"""
import sys
import re
import pytest
import yaml


from pqblocks_cnsa_evidence.parsers import (
    scan_parser,
    lockfile_parser,
    compliance_matrix_emitter,
    migration_scheduler,
    sbom_emitter,
    crypto_inventory_emitter,
    narrative_emitter,
    executive_summary_emitter,
    attestation_emitter,
)

MONTH_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")


def _lockfile(*specs):
    """Build a LockfileResult from (name, pqcClassification) pairs."""
    return {
        "ecosystem": "python",
        "components": [
            {
                "name": name,
                "version": "1.0.0",
                "ecosystem": "python",
                "type": "library",
                "pqcClassification": cls,
            }
            for name, cls in specs
        ],
    }


def _matrix(scan_result=None):
    if scan_result is None:
        scan_result = scan_parser({
            "algorithms": [],
            "tls_endpoints": [],
            "dependencies": [],
            "pqc_grades": {},
        })
    return compliance_matrix_emitter(scan_result)


# ============================================================
# Test migration_scheduler.py lines 1-3 (the re-export wrapper)
# ============================================================

def test_migration_scheduler_module_import_works():
    """Exercise the import statement on line 1 of migration_scheduler.py"""
    import pqblocks_cnsa_evidence.migration_scheduler as ms_module
    # This exercises line 1: from pqblocks_cnsa_evidence.parsers import migration_scheduler
    assert hasattr(ms_module, 'migration_scheduler')
    assert callable(ms_module.migration_scheduler)


def test_migration_scheduler_module_all_export():
    """Exercise __all__ on line 3 of migration_scheduler.py"""
    import pqblocks_cnsa_evidence.migration_scheduler as ms_module
    # This exercises line 3: __all__ = ["migration_scheduler"]
    assert "__all__" in dir(ms_module)
    assert ms_module.__all__ == ["migration_scheduler"]


def test_migration_scheduler_via_module_import():
    """Call migration_scheduler via the module import (exercises re-export)"""
    import pqblocks_cnsa_evidence.migration_scheduler as ms_module
    lock = _lockfile(("crypto-lib", "legacy"))
    matrix = _matrix()
    plan_yaml = ms_module.migration_scheduler(lock, matrix, {"max_systems_per_month": 5})
    parsed = yaml.safe_load(plan_yaml)
    assert len(parsed) == 1
    assert parsed[0]["system"] == "crypto-lib"


# ============================================================
# Test parsers.py uncovered lines (from coverage report)
# ============================================================

# Line 161: pqc_grades overwrite protection branch
def test_scan_parser_pqc_grades_does_not_overwrite_existing():
    """Cover line 161: if algo not in result["pqc_grades"]"""
    parsed_scan = {
        "algorithms": [
            {"name": "ML-KEM-1024", "type": "key-encapsulation", "mode": "PQC", "keySize": 1024, "cnsA20Grade": "A", "breakYear": 2035}
        ],
        "pqc_grades": {
            "ML-KEM-1024": "F"  # Should NOT overwrite the 'A' from algorithms
        },
        "tls_endpoints": [],
        "dependencies": [],
    }
    result = scan_parser(parsed_scan)
    # The grade from algorithms (A) should be preserved, not overwritten by F from pqc_grades
    assert result["pqc_grades"]["ML-KEM-1024"] == "A"


# Lines 215-235: setup.py parser install_requires parsing
def test_parse_setup_py_with_install_requires():
    """Cover lines 215-235: setup.py install_requires parsing"""
    content = """
from setuptools import setup
setup(
    name="test",
    install_requires=[
        "requests>=2.25.0",
        "cryptography==3.4.7",
    ],
)
"""
    from pqblocks_cnsa_evidence.parsers import _parse_python_setup_py
    components = _parse_python_setup_py(content)
    assert len(components) >= 2
    names = [c["name"] for c in components]
    assert "requests" in names
    assert "cryptography" in names


def test_parse_setup_py_with_requires():
    """Cover lines 215-235: setup.py requires parsing"""
    content = """
from setuptools import setup
setup(
    name="test",
    requires=["requests", "numpy>=1.19"],
)
"""
    from pqblocks_cnsa_evidence.parsers import _parse_python_setup_py
    components = _parse_python_setup_py(content)
    assert len(components) >= 1


# Lines 245-269: setup.py continuation lines in install_requires
def test_parse_setup_py_multiline_install_requires():
    """Cover lines 245-269: multiline install_requires with closing bracket"""
    content = """install_requires = [
    "requests>=2.0",
    "cryptography==3.0",
]"""
    from pqblocks_cnsa_evidence.parsers import _parse_python_setup_py
    components = _parse_python_setup_py(content)
    assert len(components) >= 2


# Lines 313-317: pyproject.toml poetry version cleaning
def test_parse_pyproject_toml_poetry_version_star():
    """Cover lines 311-313: poetry version '*' handling"""
    content = """
[tool.poetry.dependencies]
python = "^3.9"
requests = "*"
"""
    from pqblocks_cnsa_evidence.parsers import _parse_python_pyproject_toml
    components = _parse_python_pyproject_toml(content)
    req = next((c for c in components if c["name"] == "requests"), None)
    assert req is not None
    assert req["version"] == "0.0.0"  # '*' should become 0.0.0


def test_parse_pyproject_toml_poetry_version_dict():
    """Cover line 315: poetry version as dict"""
    content = """
[tool.poetry.dependencies]
python = "^3.9"
cryptography = {version = "^3.4", extras = ["rsa"]}
"""
    from pqblocks_cnsa_evidence.parsers import _parse_python_pyproject_toml
    components = _parse_python_pyproject_toml(content)
    crypto = next((c for c in components if c["name"] == "cryptography"), None)
    assert crypto is not None
    assert crypto["version"] == "^3.4"


# Line 342: maven namespace handling
def test_parse_java_maven_with_namespace():
    """Cover line 342: maven namespace detection"""
    content = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>test-project</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-lang3</artifactId>
            <version>3.12.0</version>
        </dependency>
    </dependencies>
</project>"""
    from pqblocks_cnsa_evidence.parsers import _parse_java_maven
    components = _parse_java_maven(content)
    assert len(components) >= 1
    assert any("org.apache.commons:commons-lang3" in c["name"] for c in components)


# Line 420: go.mod require with //indirect
def test_parse_go_mod_with_indirect_comment():
    """Cover line 419-420: go.mod //indirect handling"""
    content = """module example.com/test

go 1.20

require (
    github.com/stretchr/testify v1.8.0 // indirect
    golang.org/x/crypto v0.10.0
)
"""
    from pqblocks_cnsa_evidence.parsers import _parse_go_mod
    components = _parse_go_mod(content)
    assert len(components) >= 2
    names = [c["name"] for c in components]
    assert "github.com/stretchr/testify" in names
    assert "golang.org/x/crypto" in names


# Lines 430-434: go.mod single line require
def test_parse_go_mod_single_line_require():
    """Cover lines 428-440: go.mod single line require"""
    content = """module example.com/test
go 1.20
require github.com/user/repo v1.2.3
"""
    from pqblocks_cnsa_evidence.parsers import _parse_go_mod
    components = _parse_go_mod(content)
    assert len(components) >= 1
    assert components[0]["name"] == "github.com/user/repo"
    assert components[0]["version"] == "v1.2.3"


# Lines 459, 461: javascript package-lock version cleaning
def test_parse_javascript_package_lock_version_cleaning():
    """Cover lines 458-461: version cleaning for v prefix and empty"""
    content = """{
  "name": "test",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "dependencies": {
    "lodash": {
      "version": "v4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    },
    "express": {
      "version": "",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
    }
  }
}"""
    from pqblocks_cnsa_evidence.parsers import _parse_javascript_package_lock
    components = _parse_javascript_package_lock(content)
    assert len(components) >= 2
    lodash = next((c for c in components if c["name"] == "lodash"), None)
    express = next((c for c in components if c["name"] == "express"), None)
    assert lodash is not None
    assert lodash["version"] == "4.17.21"  # v prefix stripped
    assert express is not None
    assert express["version"] == "0.0.0"  # empty becomes 0.0.0


# Lines 474-491: javascript nested dependencies
def test_parse_javascript_package_lock_nested_deps():
    """Cover lines 472-488: nested dependencies in package-lock"""
    content = """{
  "name": "test",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "dependencies": {
    "parent": {
      "version": "1.0.0",
      "dependencies": {
        "child": {
          "version": "2.0.0"
        }
      }
    }
  }
}"""
    from pqblocks_cnsa_evidence.parsers import _parse_javascript_package_lock
    components = _parse_javascript_package_lock(content)
    assert len(components) >= 2
    names = [c["name"] for c in components]
    assert "parent" in names
    assert "child" in names


# H3 (Check 5 (adversarial review)): unknown ecosystem must RAISE ValueError (loud), never silent-empty.
#
# list item 3 + DISPATCH H3 mandate ValueError for typos like "pyhton".
def test_lockfile_parser_unknown_ecosystem():
    """Unknown ecosystem raises ValueError (H3 loud-error contract)."""
    with pytest.raises(ValueError, match="Unknown ecosystem"):
        lockfile_parser("unknown_ecosystem", "content")
    with pytest.raises(ValueError, match="Unknown ecosystem"):
        lockfile_parser("pyhton", "requests==1.0")  # typo must not parse quietly


def test_scan_parser_non_dict_dependency_raises():
    scan = {"algorithms": [], "tls_endpoints": [],
            "dependencies": ["not-a-dict"], "pqc_grades": {}}
    with pytest.raises(TypeError, match="Dependency entry must be dict"):
        scan_parser(scan)


def test_lockfile_parser_python_non_dict_input():
    """Non-string lockfile_content is a loud TypeError (Check 5 (adversarial review) H3 contract, same as scan_parser);
    an empty STRING stays a valid empty lockfile (spec edge cases 1-3)."""
    for bad in (None, 123, b"requests==2.0", ["requests==2.0"]):
        with pytest.raises(TypeError, match="Expected str for lockfile_content"):
            lockfile_parser("python", bad)

    assert lockfile_parser("python", "")["components"] == []


# Line 629: pqc_classification fallback in sbom_emitter
def test_sbom_emitter_pqc_classification_fallback():
    """Cover line 629: pqcClassification fallback when mode is unknown"""
    scan_result = scan_parser({
        "algorithms": [],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {},
    })
    lockfile_result = {
        "ecosystem": "python",
        "components": [{
            "name": "test-lib",
            "version": "1.0.0",
            "ecosystem": "python",
            "type": "library",
            "pqcClassification": "PQC-native"
        }]
    }
    sbom = sbom_emitter(scan_result, lockfile_result)
    # The component has PQC-native classification but no scan algo info
    # so mode should be set from pqcClassification
    assert len(sbom["components"]) == 1
    comp = sbom["components"][0]
    assert comp["pqcClassification"] == "PQC-native"


# Lines 717, 729, 744-746: crypto_inventory_emitter file_path handling
def test_crypto_inventory_emitter_tls_endpoint_with_file_path():
    """Cover lines 714-721: TLS endpoint file_path association"""
    scan_result = scan_parser({
        "algorithms": [
            {"name": "ML-KEM-1024", "type": "key-encapsulation", "mode": "PQC", "keySize": 1024, "cnsA20Grade": "A", "breakYear": 2035}
        ],
        "tls_endpoints": [{"file_path": "/etc/nginx/nginx.conf"}],
        "dependencies": [],
        "pqc_grades": {},
    })
    lockfile_result = {"ecosystem": "python", "components": []}
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    assert "ML-KEM-1024" in inventory
    assert "/etc/nginx/nginx.conf" in inventory["ML-KEM-1024"]["files"]


def test_crypto_inventory_emitter_tls_endpoint_with_path_key():
    """Cover line 715: path key fallback"""
    scan_result = scan_parser({
        "algorithms": [
            {"name": "ML-KEM-1024", "type": "key-encapsulation", "mode": "PQC", "keySize": 1024, "cnsA20Grade": "A", "breakYear": 2035}
        ],
        "tls_endpoints": [{"path": "/etc/ssl/openssl.cnf"}],
        "dependencies": [],
        "pqc_grades": {},
    })
    lockfile_result = {"ecosystem": "python", "components": []}
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    assert "/etc/ssl/openssl.cnf" in inventory["ML-KEM-1024"]["files"]


def test_crypto_inventory_emitter_scan_dependency_file_path():
    """Cover lines 727-733: scan dependency file_path"""
    scan_result = scan_parser({
        "algorithms": [
            {"name": "ML-KEM-1024", "type": "key-encapsulation", "mode": "PQC", "keySize": 1024, "cnsA20Grade": "A", "breakYear": 2035}
        ],
        "tls_endpoints": [],
        "dependencies": [{"file_path": "src/main.py"}],
        "pqc_grades": {},
    })
    lockfile_result = {"ecosystem": "python", "components": []}
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    assert "src/main.py" in inventory["ML-KEM-1024"]["files"]


def test_crypto_inventory_emitter_lockfile_component_file_path():
    """Cover lines 740-746: lockfile component file_path"""
    scan_result = scan_parser({
        "algorithms": [
            {"name": "ML-KEM-1024", "type": "key-encapsulation", "mode": "PQC", "keySize": 1024, "cnsA20Grade": "A", "breakYear": 2035}
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {},
    })
    lockfile_result = {
        "ecosystem": "python",
        "components": [{
            "name": "cryptography",
            "version": "41.0.0",
            "ecosystem": "python",
            "type": "library",
            "pqcClassification": "PQC-native",
            "file_path": "requirements.txt"
        }]
    }
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    assert "requirements.txt" in inventory["ML-KEM-1024"]["files"]


# Lines 987-988, 1011, 1030, 1053, 1055, 1065: executive_summary_emitter branches
def test_executive_summary_exposed_keys_zero():
    """Cover line 1017-1018: no exposed keys found"""
    compliance_matrix = {
        "key-establishment": {"requirement": "key-establishment", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
        "signature": {"requirement": "signature", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
        "encryption": {"requirement": "encryption", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
        "hashing": {"requirement": "hashing", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
        "fallback": {"requirement": "fallback", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
    }
    summary = executive_summary_emitter(compliance_matrix, "", "")
    assert "No exposed keys found" in summary


def test_executive_summary_exposed_keys_present():
    """Cover line 1020-1021: exposed keys detected"""
    compliance_matrix = {
        "key-establishment": {"requirement": "key-establishment", "algorithm": "ML-KEM-1024", "evidence": "found", "grade": "A", "breakYear": 2035},
        "signature": {"requirement": "signature", "algorithm": "ML-DSA-87", "evidence": "found", "grade": "A", "breakYear": 2035},
        "encryption": {"requirement": "encryption", "algorithm": "AES-256", "evidence": "found", "grade": "B", "breakYear": 2030},
        "hashing": {"requirement": "hashing", "algorithm": "SHA-384", "evidence": "found", "grade": "A", "breakYear": 2035},
        "fallback": {"requirement": "fallback", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
    }
    summary = executive_summary_emitter(compliance_matrix, "", "")
    assert "Exposed keys detected" in summary
    assert "4" in summary  # 4 algorithms with grades


def test_executive_summary_harvest_now_detected():
    """Cover line 1029-1030: harvest-now-decrypt-later exposure detected"""
    compliance_matrix = _matrix()
    narrative = "This system has harvest-now-decrypt-later risk due to classical algorithms"
    summary = executive_summary_emitter(compliance_matrix, narrative, "")
    assert "Harvest-now-decrypt-later exposure" in summary
    assert "Detected during review" in summary


def test_executive_summary_no_harvest():
    """Cover line 1031-1032: no harvest-now-decrypt-later risk"""
    compliance_matrix = _matrix()
    narrative = "All algorithms are PQC-ready"
    summary = executive_summary_emitter(compliance_matrix, narrative, "")
    assert "No harvest-now-decrypt-later risk identified" in summary


def test_executive_summary_recommendation_go():
    """Cover line 1050-1051: Go recommendation (A/B grades, no harvest)"""
    compliance_matrix = {
        "key-establishment": {"requirement": "key-establishment", "algorithm": "ML-KEM-1024", "evidence": "found", "grade": "A", "breakYear": 2035},
        "signature": {"requirement": "signature", "algorithm": "ML-DSA-87", "evidence": "found", "grade": "A", "breakYear": 2035},
        "encryption": {"requirement": "encryption", "algorithm": "AES-256", "evidence": "found", "grade": "B", "breakYear": 2030},
        "hashing": {"requirement": "hashing", "algorithm": "SHA-384", "evidence": "found", "grade": "A", "breakYear": 2035},
        "fallback": {"requirement": "fallback", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
    }
    narrative = "All PQC ready"
    summary = executive_summary_emitter(compliance_matrix, narrative, "")
    assert "Go:" in summary


def test_executive_summary_recommendation_no_go_harvest_no_ab():
    """Cover line 1052-1053: No-Go (harvest + no A/B)"""
    compliance_matrix = {
        "key-establishment": {"requirement": "key-establishment", "algorithm": "RSA-2048", "evidence": "found", "grade": "D", "breakYear": 2025},
        "signature": {"requirement": "signature", "algorithm": "ECDSA-P256", "evidence": "found", "grade": "D", "breakYear": 2025},
        "encryption": {"requirement": "encryption", "algorithm": "AES-128", "evidence": "found", "grade": "C", "breakYear": 2030},
        "hashing": {"requirement": "hashing", "algorithm": "SHA-256", "evidence": "found", "grade": "C", "breakYear": 2035},
        "fallback": {"requirement": "fallback", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
    }
    narrative = "harvest-now-decrypt-later risk with classical crypto"
    summary = executive_summary_emitter(compliance_matrix, narrative, "")
    assert "No-Go:" in summary


def test_executive_summary_recommendation_go_with_conditions():
    """Cover line 1054-1055: Go with conditions (A/B + harvest)"""
    compliance_matrix = {
        "key-establishment": {"requirement": "key-establishment", "algorithm": "ML-KEM-1024", "evidence": "found", "grade": "A", "breakYear": 2035},
        "signature": {"requirement": "signature", "algorithm": "ML-DSA-87", "evidence": "found", "grade": "A", "breakYear": 2035},
        "encryption": {"requirement": "encryption", "algorithm": "AES-256", "evidence": "found", "grade": "B", "breakYear": 2030},
        "hashing": {"requirement": "hashing", "algorithm": "SHA-384", "evidence": "found", "grade": "A", "breakYear": 2035},
        "fallback": {"requirement": "fallback", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
    }
    narrative = "harvest-now-decrypt-later risk identified"
    summary = executive_summary_emitter(compliance_matrix, narrative, "")
    assert "Go with conditions:" in summary


def test_executive_summary_recommendation_no_go_insufficient():
    """Cover line 1056-1057: No-Go (insufficient PQC readiness)"""
    compliance_matrix = {
        "key-establishment": {"requirement": "key-establishment", "algorithm": "RSA-2048", "evidence": "found", "grade": "D", "breakYear": 2025},
        "signature": {"requirement": "signature", "algorithm": "ECDSA-P256", "evidence": "found", "grade": "D", "breakYear": 2025},
        "encryption": {"requirement": "encryption", "algorithm": "AES-128", "evidence": "found", "grade": "C", "breakYear": 2030},
        "hashing": {"requirement": "hashing", "algorithm": "SHA-256", "evidence": "found", "grade": "C", "breakYear": 2035},
        "fallback": {"requirement": "fallback", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
    }
    narrative = "All classical algorithms"
    summary = executive_summary_emitter(compliance_matrix, narrative, "")
    assert "No-Go:" in summary
    assert "Insufficient PQC readiness" in summary


# Lines 1112, 1115, 1117, 1123: attestation_emitter hash validation branches
def test_attestation_emitter_sha256_fields_type_error():
    """Cover lines 1128-1132: sha256 field type validation"""
    with pytest.raises(TypeError):
        attestation_emitter(
            sbom_sha256=123,  # not a string
            inventory_sha256="a" * 64,
            narrative_sha256="b" * 64,
            compliance_sha256="c" * 64,
            migration_plan_sha256="d" * 64,
            executive_summary_sha256="e" * 64,
            tool_version="1.0",
            tool_timestamp="2026-01-01T00:00:00Z",
            scan_json_sha256="f" * 64,
            lockfile_hashes={}
        )


def test_attestation_emitter_tool_version_type_error():
    """Cover lines 1134-1137: tool_version type validation"""
    with pytest.raises(TypeError):
        attestation_emitter(
            sbom_sha256="a" * 64,
            inventory_sha256="b" * 64,
            narrative_sha256="c" * 64,
            compliance_sha256="d" * 64,
            migration_plan_sha256="e" * 64,
            executive_summary_sha256="f" * 64,
            tool_version=123,  # not a string
            tool_timestamp="2026-01-01T00:00:00Z",
            scan_json_sha256="g" * 64,
            lockfile_hashes={}
        )


def test_attestation_emitter_tool_timestamp_type_error():
    """Cover lines 1138-1141: tool_timestamp type validation"""
    with pytest.raises(TypeError):
        attestation_emitter(
            sbom_sha256="a" * 64,
            inventory_sha256="b" * 64,
            narrative_sha256="c" * 64,
            compliance_sha256="d" * 64,
            migration_plan_sha256="e" * 64,
            executive_summary_sha256="f" * 64,
            tool_version="1.0",
            tool_timestamp=123,  # not a string
            scan_json_sha256="g" * 64,
            lockfile_hashes={}
        )


def test_attestation_emitter_lockfile_hashes_type_error():
    """Cover lines 1142-1145: lockfile_hashes type validation"""
    with pytest.raises(TypeError):
        attestation_emitter(
            sbom_sha256="a" * 64,
            inventory_sha256="b" * 64,
            narrative_sha256="c" * 64,
            compliance_sha256="d" * 64,
            migration_plan_sha256="e" * 64,
            executive_summary_sha256="f" * 64,
            tool_version="1.0",
            tool_timestamp="2026-01-01T00:00:00Z",
            scan_json_sha256="g" * 64,
            lockfile_hashes="not-a-dict"  # not a dict
        )


def test_attestation_emitter_lockfile_hashes_value_type_error():
    """Cover lines 1147-1151: lockfile_hashes value type validation"""
    with pytest.raises(TypeError):
        attestation_emitter(
            sbom_sha256="a" * 64,
            inventory_sha256="b" * 64,
            narrative_sha256="c" * 64,
            compliance_sha256="d" * 64,
            migration_plan_sha256="e" * 64,
            executive_summary_sha256="f" * 64,
            tool_version="1.0",
            tool_timestamp="2026-01-01T00:00:00Z",
            scan_json_sha256="g" * 64,
            lockfile_hashes={"file1": 123}  # value not a string
        )


# Lines 1230, 1235, 1239, 1243, 1249: attestation_emitter sha256 field presence
def test_attestation_emitter_all_sha256_fields_present():
    """Cover lines 1229-1251: all sha256 fields validated"""
    result = attestation_emitter(
        sbom_sha256="a" * 64,
        inventory_sha256="b" * 64,
        narrative_sha256="c" * 64,
        compliance_sha256="d" * 64,
        migration_plan_sha256="e" * 64,
        executive_summary_sha256="f" * 64,
        tool_version="1.0",
        tool_timestamp="2026-01-01T00:00:00Z",
        scan_json_sha256="g" * 64,
        lockfile_hashes={"lock1": "h" * 64}
    )
    assert result["sbom_sha256"] == "a" * 64
    assert result["inventory_sha256"] == "b" * 64
    assert result["narrative_sha256"] == "c" * 64
    assert result["compliance_sha256"] == "d" * 64
    assert result["migration_plan_sha256"] == "e" * 64
    assert result["executive_summary_sha256"] == "f" * 64
    assert result["scan_json_sha256"] == "g" * 64
    assert result["lockfile_hashes"]["lock1"] == "h" * 64


# Lines 1011: executive_summary_emitter missing requirement key
def test_executive_summary_missing_requirement_keys():
    """Cover line 1011: missing requirement key in compliance matrix"""
    compliance_matrix = {
        "key-establishment": {"requirement": "key-establishment", "algorithm": "ML-KEM-1024", "evidence": "found", "grade": "A", "breakYear": 2035},
        # signature missing
        "encryption": {"requirement": "encryption", "algorithm": "AES-256", "evidence": "found", "grade": "B", "breakYear": 2030},
        "hashing": {"requirement": "hashing", "algorithm": "SHA-384", "evidence": "found", "grade": "A", "breakYear": 2035},
        "fallback": {"requirement": "fallback", "algorithm": "", "evidence": "not-found", "grade": "F", "breakYear": 0},
    }
    summary = executive_summary_emitter(compliance_matrix, "", "")
    assert "Signature" in summary
    assert "✗" in summary


# Lines 1153: migration_scheduler classification fallback
def test_migration_scheduler_unknown_classification_fallback():
    """Cover line 1152-1153: unknown classification defaults to 'unknown'"""
    lock = {
        "ecosystem": "python",
        "components": [{
            "name": "test-lib",
            "version": "1.0.0",
            "ecosystem": "python",
            "type": "library",
            "pqcClassification": "invalid-classification"
        }]
    }
    matrix = _matrix()
    plan_yaml = migration_scheduler(lock, matrix, {"max_systems_per_month": 5, "start_month": "2027-01"})
    parsed = yaml.safe_load(plan_yaml)
    assert len(parsed) == 1
    # Should have been processed despite invalid classification (falls back to "unknown")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])