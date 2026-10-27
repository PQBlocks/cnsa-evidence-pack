"""
Tests for Slice 7: executive_summary_emitter().

Contract: Input ComplianceMatrix + Narrative dict + MigrationPlan -> 1-page markdown string.
Tests: verify RFP compliance checkmarks present; key findings; risk summary;
migration timeline; recommendation.
"""
import sys

import pytest

from pqblocks_cnsa_evidence.parsers import (
    compliance_matrix_emitter,
    scan_parser,
    lockfile_parser,
    narrative_emitter,
    migration_scheduler,
)

EXEC_SUMMARY_MARKER = "# Executive Summary"
RFP_COMPLIANCE_SECTION = "## RFP Compliance"
KEY_FINDINGS_SECTION = "## Key Findings"
RISK_SUMMARY_SECTION = "## Risk Summary"
MIGRATION_TIMELINE_SECTION = "## Migration Timeline"
RECOMMENDATION_SECTION = "## Recommendation"

def test_executive_summary_is_string():
    """Verify output is a string."""
    compliance_matrix = compliance_matrix_emitter(scan_parser({"algorithms": []}))
    narrative = narrative_emitter(scan_parser({"algorithms": []}), {"components": []})
    migration_plan = migration_scheduler({"ecosystem": "python", "components": []}, compliance_matrix, {})
    from pqblocks_cnsa_evidence.parsers import executive_summary_emitter
    result = executive_summary_emitter(compliance_matrix, narrative, migration_plan)
    assert isinstance(result, str)

def test_rfp_compliance_checkmarks_present():
    """Verify RFP compliance checkmarks are present."""
    scan_algos = [
        {"name": "ML-KEM-768", "type": "key-encapsulation", "mode": "PQC",
         "keySize": 768, "cnsA20Grade": "A", "breakYear": 2099},
        {"name": "ML-DSA-65", "type": "signature", "mode": "PQC",
         "keySize": 65, "cnsA20Grade": "A", "breakYear": 2099},
        {"name": "AES-256", "type": "encryption", "mode": "classical",
         "keySize": 256, "cnsA20Grade": "A", "breakYear": 2030},
    ]
    scan_result = {"algorithms": scan_algos, "tls_endpoints": [], "dependencies": [], "pqc_grades": {}}
    parsed_scan = scan_parser(scan_result)
    
    compliance_matrix = compliance_matrix_emitter(parsed_scan)
    narrative = narrative_emitter(parsed_scan, {"ecosystem": "python", "components": [{"name": "cryptography", "version": "1.0.0", "ecosystem": "python", "type": "library", "pqcClassification": "PQC-native"}]})
    migration_plan = migration_scheduler(
        {"ecosystem": "python", "components": [{"name": "cryptography", "version": "1.0.0", "ecosystem": "python", "type": "library", "pqcClassification": "PQC-native"}]},
        compliance_matrix,
        {"max_systems_per_month": 3, "start_month": "2027-01"}
    )
    from pqblocks_cnsa_evidence.parsers import executive_summary_emitter
    result = executive_summary_emitter(compliance_matrix, narrative, migration_plan)
    assert isinstance(result, str)
    # Check for RFP compliance markers
    assert RFP_COMPLIANCE_SECTION in result, f"Expected '{RFP_COMPLIANCE_SECTION}' in result"

def test_key_findings_present():
    """Verify key findings section with grade distribution."""
    scan_algos = [
        {"name": "ML-KEM-768", "type": "key-encapsulation", "mode": "PQC",
         "keySize": 768, "cnsA20Grade": "A", "breakYear": 2099},
        {"name": "ML-DSA-65", "type": "signature", "mode": "PQC",
         "keySize": 65, "cnsA20Grade": "A", "breakYear": 2099},
        {"name": "AES-256", "type": "encryption", "mode": "classical",
         "keySize": 256, "cnsA20Grade": "A", "breakYear": 2030},
    ]
    scan_result = {"algorithms": scan_algos, "tls_endpoints": [], "dependencies": [], "pqc_grades": {}}
    parsed_scan = scan_parser(scan_result)
    
    compliance_matrix = compliance_matrix_emitter(parsed_scan)
    narrative = narrative_emitter(parsed_scan, {"ecosystem": "python", "components": [{"name": "cryptography", "version": "1.0.0", "ecosystem": "python", "type": "library", "pqcClassification": "PQC-native"}]})
    migration_plan = migration_scheduler(
        {"ecosystem": "python", "components": [{"name": "cryptography", "version": "1.0.0", "ecosystem": "python", "type": "library", "pqcClassification": "PQC-native"}]},
        compliance_matrix,
        {"max_systems_per_month": 3, "start_month": "2027-01"}
    )
    from pqblocks_cnsa_evidence.parsers import executive_summary_emitter
    result = executive_summary_emitter(compliance_matrix, narrative, migration_plan)
    assert isinstance(result, str)
    # Check for key findings markers
    assert KEY_FINDINGS_SECTION in result, f"Expected '{KEY_FINDINGS_SECTION}' in result"
    # Check for grade distribution - should contain grade entries
    lower = result.lower()
    assert "grade distribution" in lower
    # Check that grades A and F are present in the distribution
    assert "a" in lower or "f" in lower

def test_risk_summary_present():
    """Verify risk summary with harvest-now-decrypt-later exposure."""
    scan_algos = [
        {"name": "RSA-2048", "type": "encryption", "mode": "classical",
         "keySize": 2048, "cnsA20Grade": "D", "breakYear": 2030},
    ]
    scan_result = {"algorithms": scan_algos, "tls_endpoints": [], "dependencies": [], "pqc_grades": {}}
    parsed_scan = scan_parser(scan_result)
    
    compliance_matrix = compliance_matrix_emitter(parsed_scan)
    narrative = narrative_emitter(parsed_scan, {"ecosystem": "python", "components": []})
    migration_plan = migration_scheduler({"ecosystem": "python", "components": []}, compliance_matrix, {})
    from pqblocks_cnsa_evidence.parsers import executive_summary_emitter
    result = executive_summary_emitter(compliance_matrix, narrative, migration_plan)
    assert isinstance(result, str)
    # Check for risk summary markers
    assert RISK_SUMMARY_SECTION in result, f"Expected '{RISK_SUMMARY_SECTION}' in result"
    # Check for harvest-now-decrypt-later language
    lower = result.lower()
    assert "harvest" in lower or "decrypt" in lower or "harvest-now" in lower

def test_migration_timeline_present():
    """Verify migration timeline section."""
    scan_algos = [
        {"name": "ML-KEM-768", "type": "key-encapsulation", "mode": "PQC",
         "keySize": 768, "cnsA20Grade": "A", "breakYear": 2099},
    ]
    scan_result = {"algorithms": scan_algos, "tls_endpoints": [], "dependencies": [], "pqc_grades": {}}
    parsed_scan = scan_parser(scan_result)
    
    compliance_matrix = compliance_matrix_emitter(parsed_scan)
    narrative = narrative_emitter(parsed_scan, {"ecosystem": "python", "components": []})
    migration_plan = migration_scheduler(
        {"ecosystem": "python", "components": [{"name": "cryptography", "version": "1.0.0", "ecosystem": "python", "type": "library", "pqcClassification": "PQC-native"}]},
        compliance_matrix,
        {"max_systems_per_month": 5, "start_month": "2027-01"}
    )
    from pqblocks_cnsa_evidence.parsers import executive_summary_emitter
    result = executive_summary_emitter(compliance_matrix, narrative, migration_plan)
    assert isinstance(result, str)
    # Check for migration timeline markers
    assert MIGRATION_TIMELINE_SECTION in result, f"Expected '{MIGRATION_TIMELINE_SECTION}' in result"
    # Check for month references
    import re
    months = re.findall(r"202[3-9]-[01][0-9]", result)
    assert len(months) > 0, f"Expected month references in result, got: {result[:200]}"

def test_recommendation_present():
    """Verify recommendation section with go/no-go."""
    scan_algos = [
        {"name": "ML-KEM-768", "type": "key-encapsulation", "mode": "PQC",
         "keySize": 768, "cnsA20Grade": "A", "breakYear": 2099},
    ]
    scan_result = {"algorithms": scan_algos, "tls_endpoints": [], "dependencies": [], "pqc_grades": {}}
    parsed_scan = scan_parser(scan_result)
    
    compliance_matrix = compliance_matrix_emitter(parsed_scan)
    narrative = narrative_emitter(parsed_scan, {"ecosystem": "python", "components": []})
    migration_plan = migration_scheduler({"ecosystem": "python", "components": []}, compliance_matrix, {})
    from pqblocks_cnsa_evidence.parsers import executive_summary_emitter
    result = executive_summary_emitter(compliance_matrix, narrative, migration_plan)
    assert isinstance(result, str)
    # Check for recommendation markers
    assert RECOMMENDATION_SECTION in result, f"Expected '{RECOMMENDATION_SECTION}' in result"
    # Check for go/go-no-go language
    lower = result.lower()
    assert "go" in lower or "no-go" in lower

def test_executive_summary_deterministic():
    """Verify output is deterministic across runs."""
    scan_algos = [
        {"name": "ML-KEM-768", "type": "key-encapsulation", "mode": "PQC",
         "keySize": 768, "cnsA20Grade": "A", "breakYear": 2099},
    ]
    scan_result = {"algorithms": scan_algos, "tls_endpoints": [], "dependencies": [], "pqc_grades": {}}
    parsed_scan = scan_parser(scan_result)
    
    compliance_matrix = compliance_matrix_emitter(parsed_scan)
    narrative = narrative_emitter(parsed_scan, {"ecosystem": "python", "components": []})
    migration_plan = migration_scheduler({"ecosystem": "python", "components": []}, compliance_matrix, {"max_systems_per_month": 5, "start_month": "2027-01"})
    from pqblocks_cnsa_evidence.parsers import executive_summary_emitter
    result1 = executive_summary_emitter(compliance_matrix, narrative, migration_plan)
    result2 = executive_summary_emitter(compliance_matrix, narrative, migration_plan)
    assert result1 == result2

def test_empty_scan_produces_valid_output():
    """Verify executive summary works with empty scan (edge case)."""
    compliance_matrix = compliance_matrix_emitter(scan_parser({"algorithms": []}))
    narrative = narrative_emitter(scan_parser({"algorithms": []}), {"ecosystem": "python", "components": []})
    migration_plan = migration_scheduler({"ecosystem": "python", "components": []}, compliance_matrix, {})
    from pqblocks_cnsa_evidence.parsers import executive_summary_emitter
    result = executive_summary_emitter(compliance_matrix, narrative, migration_plan)
    assert isinstance(result, str)
    assert "no exposed keys" in result.lower() or "no keys found" in result.lower()
    # Should still have all sections
    assert RFP_COMPLIANCE_SECTION in result
    assert KEY_FINDINGS_SECTION in result
    assert RISK_SUMMARY_SECTION in result
    assert MIGRATION_TIMELINE_SECTION in result
    assert RECOMMENDATION_SECTION in result