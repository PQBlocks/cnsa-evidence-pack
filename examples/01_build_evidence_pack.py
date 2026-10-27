#!/usr/bin/env python3
"""Example 1: Complete CNSA 2.0 Procurement Evidence Pack Generation."""

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


def _sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def main():
    # 1. Sample CBOM scan input from a codebase scan
    scan_data = {
        "algorithms": [
            {
                "name": "ML-KEM-1024",
                "type": "key-encapsulation",
                "mode": "PQC",
                "keySize": 1024,
                "cnsA20Grade": "A",
                "breakYear": 2040,
            },
            {
                "name": "RSA-2048",
                "type": "signature",
                "mode": "classical",
                "keySize": 2048,
                "cnsA20Grade": "D",
                "breakYear": 2030,
            },
            {
                "name": "AES-256",
                "type": "encryption",
                "mode": "classical",
                "keySize": 256,
                "cnsA20Grade": "A",
                "breakYear": 2050,
            },
        ],
        "tls_endpoints": [
            {"host": "api.fed-gateway.gov", "cipher": "TLS_AES_256_GCM_SHA384"}
        ],
        "dependencies": [
            {"name": "cryptography", "version": "42.0.5"}
        ],
        "pqc_grades": {
            "ML-KEM-1024": "A",
            "RSA-2048": "D",
            "AES-256": "A",
        },
    }

    # 2. Sample lockfile (e.g. requirements.txt)
    lockfile_text = "cryptography==42.0.5\nrequests>=2.31.0\n"

    # 3. Parse scan and lockfile
    scan_res = scan_parser(scan_data)
    lock_res = lockfile_parser("python", lockfile_text)

    # 4. Generate core evidence pack components
    sbom = sbom_emitter(scan_res, lock_res)
    inventory = crypto_inventory_emitter(scan_res, lock_res)
    matrix = compliance_matrix_emitter(scan_res)
    narrative = narrative_emitter(scan_res, lock_res)
    schedule = migration_scheduler(lock_res, matrix)
    exec_summary = executive_summary_emitter(matrix, narrative, schedule)

    # 5. Emit cryptographic attestation binding all pack artifacts
    sbom_s = json.dumps(sbom, sort_keys=True)
    inv_s = json.dumps(inventory, sort_keys=True)
    comp_s = json.dumps(matrix, sort_keys=True)
    sched_s = str(schedule)

    attestation = attestation_emitter(
        sbom_sha256=_sha256(sbom_s),
        inventory_sha256=_sha256(inv_s),
        narrative_sha256=_sha256(narrative),
        compliance_sha256=_sha256(comp_s),
        migration_plan_sha256=_sha256(sched_s),
        executive_summary_sha256=_sha256(exec_summary),
        tool_version="0.1.0",
        tool_timestamp="2026-10-26T00:00:00Z",
        scan_json_sha256=_sha256(json.dumps(scan_data, sort_keys=True)),
        lockfile_hashes={"requirements.txt": _sha256(lockfile_text)},
    )

    print("✅ CNSA 2.0 Evidence Pack Generated:")
    print(f"  - CycloneDX Spec: {sbom.get('specVersion', '1.6')}")
    print(f"  - Cryptographic Assets: {len(inventory.get('assets', []))}")
    print(f"  - Narrative Length: {len(narrative)} chars")
    print(f"  - Attestation Hash: {attestation.get('attestation_sha256', 'verified')}")


if __name__ == "__main__":
    main()
