# Changelog

All notable changes to `pqblocks-cnsa-evidence` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-26

### Added
- **Multi-Ecosystem Lockfile Ingestion**: Parsers for Python (`requirements.txt`, `setup.py`, `pyproject.toml`), Go (`go.mod`), JavaScript (`package-lock.json`), and Java (`pom.xml`).
- **CycloneDX 1.6 CBOM Synthesis**: Generates schema-compliant CycloneDX 1.6 software and cryptographic bills of materials with post-quantum properties.
- **Cryptographic Inventory Cataloging**: Structured classification of detected cryptographic assets, key sizes, and NIST IR 8413 break-year projections.
- **CNSA 2.0 Compliance Engine**: Automatic grading (A through F) evaluating algorithms against National Security Agency CNSA 2.0 timeline requirements.
- **Migration Roadmap Scheduling**: Algorithmic planner producing YAML-formatted phased migration schedules, milestones, and deprecation horizons.
- **Five-Section Key Narrative**: Automated generation of procurement-mandated key management narratives covering exposed keys, milestones, strategy, governance, and exceptions.
- **Executive Brief Formulation**: Decision-maker summary generation with risk analysis and transition scorecards.
- **Cryptographic Attestation Manifest**: SHA-256 integrity seal binding all generated reports and source lockfiles into a verifiable `attestation.json`.
- **Documentation**: Comprehensive guides covering benchmarks, test methodology, regulatory evidence mapping, deployment use cases, and agent integration rules.
