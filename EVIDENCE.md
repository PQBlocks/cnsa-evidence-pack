# Regulatory Evidence & Standards Mapping

This document details the government standards, specifications, and regulatory frameworks implemented in `pqblocks-cnsa-evidence`.

---

## Regulatory Frameworks and Standards

| Specification | Source | Purpose in Evidence Pack | Implementation Mapping |
| :--- | :--- | :--- | :--- |
| **CNSA 2.0** | US National Security Agency (NSA) | Algorithmic mandates for National Security Systems | Classification into Grade A (CNSA 2.0 compliant) through Grade F |
| **NIST IR 8413** | NIST | PQC migration roadmap and break-year estimates | Break-year horizon scoring used in migration scheduling |
| **CycloneDX 1.6** | OWASP / CycloneDX | Software & Cryptographic Bill of Materials (CBOM) | `sbom_emitter` producing CycloneDX 1.6 CBOM |
| **FIPS 203** | NIST | Module-Lattice-Based Key-Encapsulation (ML-KEM) | ML-KEM-1024 (Grade A), ML-KEM-768/512 (Grade B) |
| **FIPS 204** | NIST | Module-Lattice-Based Digital Signature (ML-DSA) | ML-DSA-87 (Grade A), ML-DSA-65/44 (Grade B) |
| **FIPS 205** | NIST | Stateless Hash-Based Digital Signature (SLH-DSA) | SLH-DSA-SHAKE-256 (Grade A) |
| **SP 800-208** | NIST | Stateful Hash-Based Signatures (LMS, XMSS) | Firmware / Boot attestation evaluation |
| **SP 800-38D / FIPS 197** | NIST | Symmetric Encryption (AES-256) | Grade A symmetric validation |

---

## Algorithm Grading Matrix (CNSA 2.0)

| Algorithm Family | Parameter Set | Mode | CNSA 2.0 Grade | Deprecation Horizon |
| :--- | :--- | :--- | :--- | :--- |
| **ML-KEM** | ML-KEM-1024 | PQC | **A** | Recommended (2033+) |
| **ML-KEM** | ML-KEM-768 | PQC | **B** | Transitional (2030–2033) |
| **ML-DSA** | ML-DSA-87 | PQC | **A** | Recommended (2033+) |
| **ML-DSA** | ML-DSA-65 | PQC | **B** | Transitional (2030–2033) |
| **Stateful Hash** | LMS / XMSS (SP 800-208) | PQC | **A** | Recommended for firmware |
| **Symmetric** | AES-256 | Classical | **A** | Compliant (2035+) |
| **Hashing** | SHA-384, SHA-512 | Classical | **A** | Compliant (2035+) |
| **Legacy Classical** | RSA-4096 / P-384 | Classical | **C** | Sunset 2030 |
| **Deprecating** | RSA-2048 / P-256 | Classical | **D** | Sunset 2026–2030 |
| **Broken** | RSA-1024, MD5, SHA-1 | Classical | **F** | Immediate replacement required |

---

## Evidence Mapping by Test Suite

| Requirement | Test Module | Verification Method |
| :--- | :--- | :--- |
| **CycloneDX 1.6 Schema Validity** | `tests/test_Slice_2_SBOM_emitter.py` | Schema field inspection, format tags, dependencies |
| **Cryptographic Asset Inventory** | `tests/test_Slice_3_Crypto_inventory.py` | Type, mode, keySize, and grade catalog validation |
| **CNSA 2.0 Grading Matrix** | `tests/test_Slice_4_Compliance_matrix.py` | Algorithmic grading against CNSA 2.0 deadlines |
| **Five-Section Key Narrative** | `tests/test_Slice_5_Narrative_emitter.py` | Presence of mandatory federal procurement sections |
| **Migration Roadmap Scheduling** | `tests/test_Slice_6_Migration_scheduler.py` | Phased milestone calculations and priority assignment |
| **Executive Decision Summary** | `tests/test_Slice_7_Executive_summary.py` | Summary formulation, score rollups, risk assessments |
| **Bit-Identical Attestation Seal** | `tests/test_Slice_8_Attestation.py` | SHA-256 manifest reproducibility across multiple runs |
