"""
Tests for Slice 5: narrative_emitter().

Contract: Input ScanResult + LockfileResult -> markdown string with 5 sections:
exposed keys, retirement milestones, migration strategy, governance, exception handling.
Edge case: empty inputs produce a structured "no keys found" narrative.
"""
import sys

import pytest

from pqblocks_cnsa_evidence.parsers import (
    narrative_emitter,
    scan_parser,
    lockfile_parser,
)


SCAN_WITH_ALGOS = {
    "algorithms": [
        {"name": "RSA-2048", "type": "encryption", "mode": "classical",
         "keySize": 2048, "cnsA20Grade": "D", "breakYear": 2030},
        {"name": "ECDSA-P-256", "type": "signature", "mode": "classical",
         "keySize": 256, "cnsA20Grade": "C", "breakYear": 2031},
        {"name": "ML-KEM-768", "type": "key-encapsulation", "mode": "PQC",
         "keySize": 768, "cnsA20Grade": "A", "breakYear": 2099},
    ],
    "tls_endpoints": [
        {"host": "api.example.gov", "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
    ],
    "dependencies": [{"name": "cryptography", "version": "42.0.5"}],
    "pqc_grades": {"RSA-2048": "D", "ECDSA-P-256": "C", "ML-KEM-768": "A"},
}

REQ_TXT = """cryptography==42.0.5
requests>=2.31
"""


def _scan():
    return scan_parser(SCAN_WITH_ALGOS)


def _lockfile():
    return lockfile_parser("python", REQ_TXT)


def test_narrative_has_all_five_sections():
    md = narrative_emitter(_scan(), _lockfile())
    assert isinstance(md, str)
    assert "Exposed Keys" in md
    assert "Retirement Milestones" in md
    assert "Migration Strategy" in md
    assert "Governance" in md
    assert "Exception Handling" in md


def test_narrative_lists_exposed_key_algorithms():
    md = narrative_emitter(_scan(), _lockfile())
    assert "RSA-2048" in md
    assert "ECDSA-P-256" in md
    assert "ML-KEM-768" in md


def test_narrative_includes_break_year_milestones():
    md = narrative_emitter(_scan(), _lockfile())
    assert "2030" in md
    assert "2031" in md


def test_narrative_mentions_cnsa20_deadline():
    md = narrative_emitter(_scan(), _lockfile())
    assert "2031" in md or "CNSA 2.0" in md


def test_narrative_migration_strategy_phases():
    md = narrative_emitter(_scan(), _lockfile())
    lowered = md.lower()
    assert "classical" in lowered
    assert "hybrid" in lowered
    assert "pqc" in lowered


def test_narrative_empty_inputs_no_keys_found():
    empty_scan = scan_parser({})
    empty_lock = lockfile_parser("python", "")
    md = narrative_emitter(empty_scan, empty_lock)
    assert isinstance(md, str)
    assert "no keys found" in md.lower()
    # structured: still has the 5 sections
    assert "Exposed Keys" in md
    assert "Retirement Milestones" in md
    assert "Migration Strategy" in md
    assert "Governance" in md
    assert "Exception Handling" in md


def test_narrative_garbage_inputs_do_not_crash():
    md = narrative_emitter({}, {})
    assert isinstance(md, str)
    md2 = narrative_emitter({"algorithms": None}, {"components": None})
    assert isinstance(md2, str)


def test_narrative_deterministic():
    a = narrative_emitter(_scan(), _lockfile())
    b = narrative_emitter(_scan(), _lockfile())
    assert a == b
