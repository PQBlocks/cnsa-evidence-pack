# Security Notes & Operating Assumptions for pqblocks-cnsa-evidence

This document outlines the security posture, operational assumptions, and advisory boundaries of `pqblocks-cnsa-evidence`.

---

## 1. Scope & Operational Role

`pqblocks-cnsa-evidence` is an audit compilation and document generation engine. It processes static scan results and package management lockfiles to synthesize compliance documentation and migration roadmaps.

### Threat Model & Boundaries
- **Advisory Documentation**: Outputs produced by this tool (SBOM, compliance matrix, migration schedules, executive summaries) represent automated analytical assessments. They do not substitute for formal system accreditation or security authorization (ATO).
- **Scanner Dependency**: The completeness of generated evidence packs depends on the fidelity of upstream scanning tools (such as `pqblocks-scan`). If an algorithm or cryptographic endpoint is omitted by the scanner, it will not appear in the generated inventory.
- **Untrusted Lockfile Ingestion**: Lockfile parsers process arbitrary text files. The parsers are hardened against malformed XML/JSON structures and issue structured warnings (`UserWarning`) rather than executing untrusted build commands.

---

## 2. Cryptographic Integrity & Attestation

- **SHA-256 Manifest Sealing**: The `attestation_emitter` seals the complete evidence pack bundle by computing individual SHA-256 digests across all six output artifacts and binding them to tool version and execution timestamps.
- **Bit-Identical Reproducibility**: Given identical input scans and lockfile inputs, the tool produces deterministic output, allowing independent third-party verification during procurement reviews.

---

## 3. Dependency Posture

- **Runtime Dependencies**:
  - `cryptography`: Used for cryptographic hashing and verification routines.
  - `pyyaml`: Safe YAML generation using `yaml.safe_dump` (untrusted deserialization via `yaml.load` is strictly avoided).
  - `toml`: Structured TOML configuration parsing.

---

## 4. Formal Non-Claims

> [!IMPORTANT]
> - `pqblocks-cnsa-evidence` is **not** certified under FIPS 140-3 and has **not** undergone CMVP validation.
> - Generating a CNSA 2.0 evidence pack does not confer official verification or formal endorsement by the National Security Agency or any United States federal agency.
> - Contractors remain responsible for verifying that production deployments comply with all agency-specific procurement requirements.
