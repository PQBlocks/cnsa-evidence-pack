# Deployment Use Cases for pqblocks-cnsa-evidence

Practical integration recipes and automation scripts for enterprise systems and federal procurement workflows.

---

## 1. Automated Federal RFP Evidence Pack Builder

Assemble a complete, sealed evidence pack for federal procurement proposals from CI/CD pipeline scanner outputs.

```python
import hashlib
import json
import os
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

def build_rfp_pack(scan_json_path: str, lockfile_path: str, output_dir: str, ecosystem: str = "python"):
    os.makedirs(output_dir, exist_ok=True)

    with open(scan_json_path, "r", encoding="utf-8") as f:
        scan_content = f.read()
        scan_data = json.loads(scan_content)

    with open(lockfile_path, "r", encoding="utf-8") as f:
        lock_content = f.read()

    # Parse inputs
    scan_res = scan_parser(scan_data)
    lock_res = lockfile_parser(ecosystem, lock_content)

    # Generate deliverables
    sbom = sbom_emitter(scan_res, lock_res)
    inventory = crypto_inventory_emitter(scan_res, lock_res)
    matrix = compliance_matrix_emitter(scan_res)
    narrative = narrative_emitter(scan_res, lock_res)
    schedule = migration_scheduler(lock_res, matrix)
    exec_summary = executive_summary_emitter(matrix, narrative, schedule)

    def write_json(name, data):
        path = os.path.join(output_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        return path

    def write_text(name, text):
        path = os.path.join(output_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    write_json("sbom.json", sbom)
    write_json("crypto-inventory.json", inventory)
    write_json("compliance-matrix.json", matrix)
    write_text("migration-plan.yaml", str(schedule))
    write_text("narrative.md", narrative)
    write_text("executive-summary.md", exec_summary)

    def file_sha256(path):
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    # Seal with cryptographic attestation
    attestation = attestation_emitter(
        sbom_sha256=file_sha256(os.path.join(output_dir, "sbom.json")),
        inventory_sha256=file_sha256(os.path.join(output_dir, "crypto-inventory.json")),
        narrative_sha256=file_sha256(os.path.join(output_dir, "narrative.md")),
        compliance_sha256=file_sha256(os.path.join(output_dir, "compliance-matrix.json")),
        migration_plan_sha256=file_sha256(os.path.join(output_dir, "migration-plan.yaml")),
        executive_summary_sha256=file_sha256(os.path.join(output_dir, "executive-summary.md")),
        tool_version="0.1.0",
        tool_timestamp="2026-10-26T00:00:00Z",
        scan_json_sha256=hashlib.sha256(scan_content.encode()).hexdigest(),
        lockfile_hashes={os.path.basename(lockfile_path): hashlib.sha256(lock_content.encode()).hexdigest()},
    )
    write_json("attestation.json", attestation)
    print(f"Procurement evidence pack assembled in {output_dir}")
```

---

## 2. Multi-Ecosystem Dependency Ingestion

Parse and evaluate repositories containing heterogeneous technology stacks (Go backend and Python analytics).

```python
from pqblocks_cnsa_evidence import scan_parser, lockfile_parser, compliance_matrix_emitter, migration_scheduler

# Composite system scan
composite_scan = {
    "algorithms": [
        {"name": "ML-KEM-1024", "type": "key-encapsulation", "mode": "PQC", "keySize": 1024, "cnsA20Grade": "A", "breakYear": 2040},
        {"name": "ECDSA-P-384", "type": "signature", "mode": "classical", "keySize": 384, "cnsA20Grade": "B", "breakYear": 2035},
        {"name": "RSA-2048", "type": "signature", "mode": "classical", "keySize": 2048, "cnsA20Grade": "D", "breakYear": 2030},
    ],
    "tls_endpoints": [],
    "dependencies": [],
    "pqc_grades": {"ML-KEM-1024": "A", "ECDSA-P-384": "B", "RSA-2048": "D"},
}

scan_model = scan_parser(composite_scan)
compliance = compliance_matrix_emitter(scan_model)

# Parse Python lockfile
py_lock = lockfile_parser("python", "cryptography==42.0.5\npyjwt==2.8.0\n")
py_plan = migration_scheduler(py_lock, compliance)

# Parse Go lockfile
go_lock = lockfile_parser("go", "module app.gov\n\ngo 1.21\n\nrequire github.com/cloudflare/circl v1.3.7\n")
go_plan = migration_scheduler(go_lock, compliance)

print(f"Compliance status: {compliance.get('status', 'complete')}")
print("Phased migration schedules generated for both ecosystems.")
```

---

## 3. Procurement Auditor Attestation Verification

Verify the cryptographic integrity of an incoming contractor evidence pack without re-running scans.

```python
import hashlib
import json

def verify_attestation(pack_dir: str) -> bool:
    attestation_path = f"{pack_dir}/attestation.json"
    with open(attestation_path, "r", encoding="utf-8") as f:
        att = json.load(f)

    # Check each file against its recorded hash
    file_map = {
        "sbom.json": att["sbom_sha256"],
        "crypto-inventory.json": att["inventory_sha256"],
        "compliance-matrix.json": att["compliance_sha256"],
        "migration-plan.yaml": att["migration_plan_sha256"],
        "narrative.md": att["narrative_sha256"],
        "executive-summary.md": att["executive_summary_sha256"],
    }

    for filename, expected_hash in file_map.items():
        filepath = f"{pack_dir}/{filename}"
        with open(filepath, "rb") as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()
        if actual_hash != expected_hash:
            print(f"Integrity check FAILED on {filename}: hash mismatch")
            return False

    print("All evidence pack files match attestation signatures.")
    return True
```
