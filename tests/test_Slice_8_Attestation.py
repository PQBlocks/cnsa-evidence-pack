"""
Tests for Slice 8: Attestation - attestation_emitter() producing attestation.json.

Contract: Input all SHA256 hashes + tool version + timestamp + scan JSON SHA256 +
lockfile hashes. Output: attestation.json dict.
Tests: verify SHA256 hashes match actual file hashes; bit-identical across 3 runs;
all required fields present.
"""
import hashlib
import json
import sys
import pytest


from pqblocks_cnsa_evidence.parsers import (
    scan_parser,
    lockfile_parser,
    sbom_emitter,
    crypto_inventory_emitter,
    compliance_matrix_emitter,
    narrative_emitter,
    migration_scheduler,
    executive_summary_emitter,
)


@pytest.fixture
def sample_scan():
    return scan_parser({
        "algorithms": [
            {"name": "ML-KEM-768", "type": "key-encapsulation", "mode": "PQC",
             "keySize": 768, "cnsA20Grade": "A", "breakYear": 2099},
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {},
    })


@pytest.fixture
def sample_lockfile():
    return lockfile_parser("python", """
cryptography==1.0.0
""".strip())


def _sha256_of(obj):
    """Compute a deterministic SHA256 of any JSON-serialisable object."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode()
    ).hexdigest()


def _get_emitters_intermediate(sample_scan, sample_lockfile):
    """Generate all intermediate artifacts needed for attestation."""
    scan_result = sample_scan
    lockfile_result = sample_lockfile

    sbom = sbom_emitter(scan_result, lockfile_result)
    inventory = crypto_inventory_emitter(scan_result, lockfile_result)
    narrative = narrative_emitter(scan_result, lockfile_result)
    compliance = compliance_matrix_emitter(scan_result)
    migration_plan = migration_scheduler(
        lockfile_result,
        compliance,
        {"max_systems_per_month": 5, "start_month": "2027-01"},
    )
    exec_summary = executive_summary_emitter(compliance, narrative, migration_plan)

    return sbom, inventory, narrative, compliance, migration_plan, exec_summary


def test_attestation_emitter_is_dict(sample_scan, sample_lockfile):
    """Verify attestation_emitter returns a dict."""
    sbom, inventory, narrative, compliance, migration_plan, exec_summary = \
        _get_emitters_intermediate(sample_scan, sample_lockfile)

    from pqblocks_cnsa_evidence.parsers import attestation_emitter
    attestation = attestation_emitter(
        sbom_sha256=_sha256_of(sbom),
        inventory_sha256=_sha256_of(inventory),
        narrative_sha256=_sha256_of(narrative),
        compliance_sha256=_sha256_of(compliance),
        migration_plan_sha256=_sha256_of(migration_plan),
        executive_summary_sha256=_sha256_of(exec_summary),
        tool_version="0.1.0",
        tool_timestamp="2026-10-09T00:00:00Z",
        scan_json_sha256=_sha256_of({}),
        lockfile_hashes={"requirements.txt": _sha256_of("requirements.txt content")},
    )
    assert isinstance(attestation, dict)


def test_all_required_fields_present(sample_scan, sample_lockfile):
    """Verify all required fields are present in attestation."""
    sbom, inventory, narrative, compliance, migration_plan, exec_summary = \
        _get_emitters_intermediate(sample_scan, sample_lockfile)

    from pqblocks_cnsa_evidence.parsers import attestation_emitter
    attestation = attestation_emitter(
        sbom_sha256=_sha256_of(sbom),
        inventory_sha256=_sha256_of(inventory),
        narrative_sha256=_sha256_of(narrative),
        compliance_sha256=_sha256_of(compliance),
        migration_plan_sha256=_sha256_of(migration_plan),
        executive_summary_sha256=_sha256_of(exec_summary),
        tool_version="0.1.0",
        tool_timestamp="2026-10-09T00:00:00Z",
        scan_json_sha256=_sha256_of({}),
        lockfile_hashes={"requirements.txt": _sha256_of("requirements.txt content")},
    )

    required_fields = [
        "sbom_sha256",
        "inventory_sha256",
        "narrative_sha256",
        "compliance_sha256",
        "migration_plan_sha256",
        "executive_summary_sha256",
        "tool_version",
        "tool_timestamp",
        "scan_json_sha256",
        "lockfile_hashes",
    ]
    for field in required_fields:
        assert field in attestation, f"Missing required field: {field}"
        assert attestation[field], f"Field {field} is empty"


def test_sha256_hashes_match_actual_hashes(sample_scan, sample_lockfile):
    """Verify sha256 hashes in attestation match hashes computed from actual data."""
    sbom, inventory, narrative, compliance, migration_plan, exec_summary = \
        _get_emitters_intermediate(sample_scan, sample_lockfile)

    # Compute expected hashes
    expected_sbom = _sha256_of(sbom)
    expected_inventory = _sha256_of(inventory)
    expected_narrative = _sha256_of(narrative)
    expected_compliance = _sha256_of(compliance)
    expected_migration = _sha256_of(migration_plan)
    expected_exec = _sha256_of(exec_summary)
    expected_scan = _sha256_of({"test": "scan"})
    expected_lockfile = _sha256_of("requirements.txt content")

    from pqblocks_cnsa_evidence.parsers import attestation_emitter
    attestation = attestation_emitter(
        sbom_sha256=expected_sbom,
        inventory_sha256=expected_inventory,
        narrative_sha256=expected_narrative,
        compliance_sha256=expected_compliance,
        migration_plan_sha256=expected_migration,
        executive_summary_sha256=expected_exec,
        tool_version="0.1.0",
        tool_timestamp="2026-10-09T00:00:00Z",
        scan_json_sha256=expected_scan,
        lockfile_hashes={"requirements.txt": expected_lockfile},
    )

    assert attestation["sbom_sha256"] == expected_sbom
    assert attestation["inventory_sha256"] == expected_inventory
    assert attestation["narrative_sha256"] == expected_narrative
    assert attestation["compliance_sha256"] == expected_compliance
    assert attestation["migration_plan_sha256"] == expected_migration
    assert attestation["executive_summary_sha256"] == expected_exec
    assert attestation["tool_version"] == "0.1.0"
    assert attestation["tool_timestamp"] == "2026-10-09T00:00:00Z"
    assert attestation["scan_json_sha256"] == expected_scan
    assert attestation["lockfile_hashes"]["requirements.txt"] == expected_lockfile


def test_attestation_bit_identical_across_3_runs(sample_scan, sample_lockfile):
    """Verify attestation is bit-identical across 3 runs with identical inputs."""
    sbom, inventory, narrative, compliance, migration_plan, exec_summary = \
        _get_emitters_intermediate(sample_scan, sample_lockfile)

    hashes = dict(
        sbom_sha256=_sha256_of(sbom),
        inventory_sha256=_sha256_of(inventory),
        narrative_sha256=_sha256_of(narrative),
        compliance_sha256=_sha256_of(compliance),
        migration_plan_sha256=_sha256_of(migration_plan),
        executive_summary_sha256=_sha256_of(exec_summary),
        tool_version="0.1.0",
        tool_timestamp="2026-10-09T00:00:00Z",
        scan_json_sha256=_sha256_of({}),
        lockfile_hashes={"requirements.txt": _sha256_of("requirements.txt content")},
    )

    from pqblocks_cnsa_evidence.parsers import attestation_emitter
    attestations = []
    for _ in range(3):
        attestation = attestation_emitter(**hashes)
        attestations.append(attestation)

    # All 3 attestation dicts should be identical
    assert attestations[0] == attestations[1]
    assert attestations[1] == attestations[2]

    # JSON-serialize and compare byte-for-byte (excluding nothing, no timestamps in scope)
    json_strs = [json.dumps(a, sort_keys=True) for a in attestations]
    assert json_strs[0] == json_strs[1] == json_strs[2], \
        f"Attestation not bit-identical:\nRun 1: {json_strs[0][:200]}...\nRun 2: {json_strs[1][:200]}..."


def test_attestation_field_types(sample_scan, sample_lockfile):
    """Verify all fields have correct types."""
    sbom, inventory, narrative, compliance, migration_plan, exec_summary = \
        _get_emitters_intermediate(sample_scan, sample_lockfile)

    from pqblocks_cnsa_evidence.parsers import attestation_emitter
    attestation = attestation_emitter(
        sbom_sha256=_sha256_of(sbom),
        inventory_sha256=_sha256_of(inventory),
        narrative_sha256=_sha256_of(narrative),
        compliance_sha256=_sha256_of(compliance),
        migration_plan_sha256=_sha256_of(migration_plan),
        executive_summary_sha256=_sha256_of(exec_summary),
        tool_version="0.1.0",
        tool_timestamp="2026-10-09T00:00:00Z",
        scan_json_sha256=_sha256_of({}),
        lockfile_hashes={"requirements.txt": _sha256_of("requirements.txt content")},
    )

    # All sha256 fields should be 64-char hex strings
    sha256_fields = [
        "sbom_sha256", "inventory_sha256", "narrative_sha256",
        "compliance_sha256", "migration_plan_sha256", "executive_summary_sha256",
        "scan_json_sha256",
    ]
    for field in sha256_fields:
        val = attestation[field]
        assert isinstance(val, str), f"{field} should be str, got {type(val)}"
        assert len(val) == 64, f"{field} should be 64 chars (SHA256 hex), got {len(val)}"
        assert all(c in "0123456789abcdef" for c in val), f"{field} should be lowercase hex"

    assert isinstance(attestation["tool_version"], str)
    assert isinstance(attestation["tool_timestamp"], str)
    assert isinstance(attestation["lockfile_hashes"], dict)
    for v in attestation["lockfile_hashes"].values():
        assert isinstance(v, str)
        assert len(v) == 64


def test_attestation_empty_inputs(sample_scan, sample_lockfile):
    """Verify attestation works with empty/None inputs where appropriate."""
    from pqblocks_cnsa_evidence.parsers import attestation_emitter

    # Test with empty string hashes (edge case)
    attestation = attestation_emitter(
        sbom_sha256="",
        inventory_sha256="",
        narrative_sha256="",
        compliance_sha256="",
        migration_plan_sha256="",
        executive_summary_sha256="",
        tool_version="0.1.0",
        tool_timestamp="2026-10-09T00:00:00Z",
        scan_json_sha256="",
        lockfile_hashes={},
    )
    assert isinstance(attestation, dict)
    assert attestation["sbom_sha256"] == ""
    assert attestation["lockfile_hashes"] == {}


def test_attestation_lockfile_hashes_is_dict(sample_scan, sample_lockfile):
    """Verify lockfile_hashes is stored as a dict."""
    sbom, inventory, narrative, compliance, migration_plan, exec_summary = \
        _get_emitters_intermediate(sample_scan, sample_lockfile)

    lockfile_hashes = {
        "requirements.txt": _sha256_of("requirements.txt content"),
        "go.mod": _sha256_of("go.mod content"),
        "package-lock.json": _sha256_of("package-lock.json content"),
    }

    from pqblocks_cnsa_evidence.parsers import attestation_emitter
    attestation = attestation_emitter(
        sbom_sha256=_sha256_of(sbom),
        inventory_sha256=_sha256_of(inventory),
        narrative_sha256=_sha256_of(narrative),
        compliance_sha256=_sha256_of(compliance),
        migration_plan_sha256=_sha256_of(migration_plan),
        executive_summary_sha256=_sha256_of(exec_summary),
        tool_version="0.1.0",
        tool_timestamp="2026-10-09T00:00:00Z",
        scan_json_sha256=_sha256_of(sample_scan),
        lockfile_hashes=lockfile_hashes,
    )

    assert attestation["lockfile_hashes"] == lockfile_hashes
    assert len(attestation["lockfile_hashes"]) == 3


def test_attestation_determinism_with_different_data(sample_scan, sample_lockfile):
    """Verify that attestation with different input hashes produces different output."""
    sbom, inventory, narrative, compliance, migration_plan, exec_summary = \
        _get_emitters_intermediate(sample_scan, sample_lockfile)

    from pqblocks_cnsa_evidence.parsers import attestation_emitter
    attestation1 = attestation_emitter(
        sbom_sha256=_sha256_of(sbom),
        inventory_sha256=_sha256_of(inventory),
        narrative_sha256=_sha256_of(narrative),
        compliance_sha256=_sha256_of(compliance),
        migration_plan_sha256=_sha256_of(migration_plan),
        executive_summary_sha256=_sha256_of(exec_summary),
        tool_version="0.1.0",
        tool_timestamp="2026-10-09T00:00:00Z",
        scan_json_sha256=_sha256_of({"data": "1"}),
        lockfile_hashes={"requirements.txt": _sha256_of("requirements.txt content")},
    )
    attestation2 = attestation_emitter(
        sbom_sha256=_sha256_of(sbom),
        inventory_sha256=_sha256_of(inventory),
        narrative_sha256=_sha256_of(narrative),
        compliance_sha256=_sha256_of(compliance),
        migration_plan_sha256=_sha256_of(migration_plan),
        executive_summary_sha256=_sha256_of(exec_summary),
        tool_version="0.1.0",
        tool_timestamp="2026-10-09T00:00:00Z",
        scan_json_sha256=_sha256_of({"data": "2"}),
        lockfile_hashes={"requirements.txt": _sha256_of("requirements.txt content")},
    )
    assert attestation1["scan_json_sha256"] != attestation2["scan_json_sha256"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
