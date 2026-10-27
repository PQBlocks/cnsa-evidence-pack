# pqblocks-cnsa-evidence

[![PyPI version](https://img.shields.io/pypi/v/pqblocks-cnsa-evidence.svg)](https://pypi.org/project/pqblocks-cnsa-evidence/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Versions](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](https://pypi.org/project/pqblocks-cnsa-evidence/)

CNSA 2.0 Procurement Evidence Pack Generator for federal contractors and enterprise systems transitioning to post-quantum cryptography.

`pqblocks-cnsa-evidence` parses cryptographic bill of materials (CBOM) scan results and multi-ecosystem build lockfiles to synthesize a formal, audit-ready evidence pack meeting US National Security Agency (NSA) Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) compliance requirements.

---

## Key Features

- **Multi-Ecosystem Lockfile Ingestion**: Native parsing for Python (`requirements.txt`, `setup.py`, `pyproject.toml`), Go (`go.mod`), JavaScript (`package-lock.json`), and Java (`pom.xml`).
- **CycloneDX 1.6 CBOM Synthesis**: Generates schema-valid CycloneDX 1.6 software and cryptographic bills of materials enriched with post-quantum properties.
- **CNSA 2.0 Compliance Matrix**: Automatically classifies algorithms against CNSA 2.0 timelines (A through F grading) based on NIST IR 8413 projections.
- **Automated Migration Scheduling**: Computes phased migration roadmaps, component-level replacement milestones, and milestone timelines.
- **Cryptographic Attestation**: Issues SHA-256 integrity attestations binding all generated reports (SBOM, crypto inventory, compliance matrix, migration plan, narrative, and source lockfiles).

---

## Installation

```bash
pip install pqblocks-cnsa-evidence
```

### Dependencies

`pqblocks-cnsa-evidence` is a pure-Python document generation and compliance engine requiring `cryptography`, `pyyaml`, and `toml`.

---

## Quickstart

```python
import hashlib
import json
from pqblocks_cnsa_evidence import (
    scan_parser,
    lockfile_parser,
    sbom_emitter,
    crypto_inventory_emitter,
    compliance_matrix_emitter,
    narrative_emitter,
    migration_scheduler,
    executive_summary_emitter,
    attestation_emitter,
)

# 1. Ingest scan findings and lockfile
scan_data = {
    "algorithms": [
        {"name": "ML-KEM-1024", "type": "key-encapsulation", "mode": "PQC", "keySize": 1024, "cnsA20Grade": "A", "breakYear": 2040},
        {"name": "RSA-2048", "type": "signature", "mode": "classical", "keySize": 2048, "cnsA20Grade": "D", "breakYear": 2030},
        {"name": "AES-256", "type": "encryption", "mode": "classical", "keySize": 256, "cnsA20Grade": "A", "breakYear": 2050},
    ],
    "tls_endpoints": [{"host": "api.fed.gov", "cipher": "TLS_AES_256_GCM_SHA384"}],
    "dependencies": [{"name": "cryptography", "version": "42.0.5"}],
    "pqc_grades": {"ML-KEM-1024": "A", "RSA-2048": "D", "AES-256": "A"}
}
lockfile_content = "cryptography==42.0.5\nrequests>=2.31.0\n"

scan_res = scan_parser(scan_data)
lock_res = lockfile_parser("python", lockfile_content)

# 2. Synthesize evidence pack components
sbom = sbom_emitter(scan_res, lock_res)
inventory = crypto_inventory_emitter(scan_res, lock_res)
matrix = compliance_matrix_emitter(scan_res)
narrative = narrative_emitter(scan_res, lock_res)
schedule = migration_scheduler(lock_res, matrix)
exec_summary = executive_summary_emitter(matrix, narrative, schedule)

def sha256(val):
    b = val.encode("utf-8") if isinstance(val, str) else json.dumps(val, sort_keys=True).encode("utf-8")
    return hashlib.sha256(b).hexdigest()

# 3. Create cryptographic attestation
attestation = attestation_emitter(
    sbom_sha256=sha256(sbom),
    inventory_sha256=sha256(inventory),
    narrative_sha256=sha256(narrative),
    compliance_sha256=sha256(matrix),
    migration_plan_sha256=sha256(schedule),
    executive_summary_sha256=sha256(exec_summary),
    tool_version="0.1.0",
    tool_timestamp="2026-10-26T00:00:00Z",
    scan_json_sha256=sha256(scan_data),
    lockfile_hashes={"requirements.txt": sha256(lockfile_content)},
)

print(f"Evidence Pack Generated: {sbom['bomFormat']} {sbom['specVersion']}")
print(f"Compliance Status: {matrix.get('status', 'complete')}")
```

---

## Evidence Pack Architecture

```
evidence-pack/
├── sbom.json                  # CycloneDX 1.6 CBOM with post-quantum properties
├── crypto-inventory.json      # Structured algorithm and key-size catalog
├── compliance-matrix.json     # CNSA 2.0 requirement evaluation and grading
├── migration-plan.yaml        # Phased timeline and dependency upgrade schedule
├── narrative.md               # Key-management narrative (5 mandatory sections)
├── executive-summary.md       # Decision-maker brief with risk analysis
└── attestation.json           # SHA-256 manifest cryptographically sealing the pack
```

---

## Non-Claims & Compliance Notice

> [!IMPORTANT]
> **Advisory Nature**: `pqblocks-cnsa-evidence` is an automated documentation and compliance analysis toolkit.
> - Generating an evidence pack does **not** constitute formal NSA or US Government accreditation.
> - The package is **not** certified under FIPS 140-3, and does not conduct CMVP validation of external binaries.
> - Contractors are responsible for ensuring underlying cryptographic algorithms are implemented in accredited modules where required by federal agency procurement directives.

---

## License

This project is licensed under the Apache 2.0 License. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
