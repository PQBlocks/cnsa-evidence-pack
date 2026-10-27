#!/usr/bin/env python3
"""Example 2: Multi-Ecosystem Lockfile Parsing and Compliance Analysis."""

from pqblocks_cnsa_evidence import scan_parser, lockfile_parser, compliance_matrix_emitter, migration_scheduler


def main():
    # Multi-ecosystem lockfiles
    py_reqs = "cryptography==42.0.5\npyjwt==2.8.0\n"
    go_mod = "module example.gov/app\n\ngo 1.21\n\nrequire github.com/cloudflare/circl v1.3.7\n"

    # Scan finding
    scan_data = {
        "algorithms": [
            {
                "name": "ML-KEM-768",
                "type": "key-encapsulation",
                "mode": "PQC",
                "keySize": 768,
                "cnsA20Grade": "B",
                "breakYear": 2045,
            },
            {
                "name": "ECDSA-P-384",
                "type": "signature",
                "mode": "classical",
                "keySize": 384,
                "cnsA20Grade": "B",
                "breakYear": 2035,
            },
        ],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {"ML-KEM-768": "B", "ECDSA-P-384": "B"},
    }

    scan_res = scan_parser(scan_data)
    py_lock = lockfile_parser("python", py_reqs)
    go_lock = lockfile_parser("go", go_mod)

    matrix = compliance_matrix_emitter(scan_res)
    plan_py = migration_scheduler(py_lock, matrix)
    plan_go = migration_scheduler(go_lock, matrix)

    print("Compliance Assessment:")
    print(f"  - Overall CNSA Status: {matrix.get('status', 'assessed')}")
    print(f"  - Python Components: {len(py_lock.get('components', []))}")
    print(f"  - Go Components: {len(go_lock.get('components', []))}")
    print("Migration Planning: Ready.")


if __name__ == "__main__":
    main()
