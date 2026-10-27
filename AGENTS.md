# Agent Guidelines: pqblocks-cnsa-evidence

Structured context for AI agents generating or modifying code that uses `pqblocks-cnsa-evidence`.

---

## Package Role & Mission

`pqblocks-cnsa-evidence` synthesizes audit-ready procurement evidence packs for systems subject to the US National Security Agency (NSA) CNSA 2.0 post-quantum transition mandate. It transforms CBOM scans and build lockfiles into CycloneDX 1.6 CBOMs, compliance matrices, narratives, migration roadmaps, and cryptographic attestations.

---

## Primary Public API

All core functions are exported from `pqblocks_cnsa_evidence`:

```python
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
```

### Signatures & Types

1. **`scan_parser(parsed_scan: dict) -> dict`**:
   - Parses raw scanner CBOM JSON into normalized `ScanResult`.
2. **`lockfile_parser(ecosystem: str, lockfile_content: str) -> dict`**:
   - Supported ecosystems: `"python"`, `"go"`, `"javascript"`, `"java"`.
   - Returns normalized `LockfileResult` with component classifications.
3. **`sbom_emitter(scan_result: dict, lockfile_result: dict) -> dict`**:
   - Returns CycloneDX 1.6 compliant SBOM dictionary.
4. **`crypto_inventory_emitter(scan_result: dict, lockfile_result: dict) -> dict`**:
   - Compiles structured catalog of algorithms, key sizes, and break-year estimates.
5. **`compliance_matrix_emitter(scan_result: dict) -> dict`**:
   - Assigns CNSA 2.0 compliance grades (A through F) and evaluates milestone timelines.
6. **`narrative_emitter(scan_result: dict, lockfile_result: dict) -> str`**:
   - Produces markdown narrative containing the 5 mandatory federal procurement sections.
7. **`migration_scheduler(lockfile_result: dict, compliance_matrix: dict, ...) -> str`**:
   - Produces a YAML-formatted phased migration plan.
8. **`executive_summary_emitter(compliance_matrix: dict, narrative: Any, migration_plan: Any) -> str`**:
   - Produces markdown executive summary with risk analysis.
9. **`attestation_emitter(sbom_sha256, inventory_sha256, narrative_sha256, compliance_sha256, migration_plan_sha256, executive_summary_sha256, tool_version, tool_timestamp, scan_json_sha256, lockfile_hashes) -> dict`**:
   - Produces attestation manifest dictionary binding all artifacts with SHA-256 digests.

---

## Common AI Assistant Mistakes

| Mistake | Why it fails | Correct approach |
| :--- | :--- | :--- |
| Passing uppercase ecosystem name (e.g. `"Python"`) | Ecosystem matching is lowercase | Use `"python"`, `"go"`, `"javascript"`, or `"java"` |
| Expecting dict from `migration_scheduler` | Returns formatted YAML text | Treat output as string, or use `yaml.safe_load(plan)` |
| Passing file objects to `attestation_emitter` | Requires SHA-256 hex string digests | Compute `hashlib.sha256(content).hexdigest()` beforehand |
| Assuming `attestation_emitter` takes arbitrary kwargs | Exact 10 positional arguments are validated | Provide all 10 required arguments in order |

---

## Minimal Canonical Example

```python
from pqblocks_cnsa_evidence import scan_parser, lockfile_parser, compliance_matrix_emitter

scan = scan_parser({
    "algorithms": [{"name": "ML-KEM-1024", "type": "key-encapsulation", "mode": "PQC", "keySize": 1024, "cnsA20Grade": "A", "breakYear": 2040}],
    "tls_endpoints": [],
    "dependencies": [],
    "pqc_grades": {"ML-KEM-1024": "A"}
})
lock = lockfile_parser("python", "cryptography==42.0.0\n")
matrix = compliance_matrix_emitter(scan)
print("CNSA 2.0 Status:", matrix.get("status", "assessed"))
```
