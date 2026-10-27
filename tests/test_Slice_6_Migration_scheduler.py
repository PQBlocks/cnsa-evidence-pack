"""
Tests for Slice 6: Migration scheduler - migration_scheduler() producing a YAML migration plan.
Contract: Input LockfileResult + ComplianceMatrix + resource constraints dict.
Output: YAML migration plan. Tests: zero double-booked systems; zero undated systems;
dependency ordering respected; resource constraints honored.
"""
import re
import sys

import pytest
import yaml


from pqblocks_cnsa_evidence.parsers import lockfile_parser, scan_parser  # noqa: E402

MONTH_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")


def _lockfile(*specs):
    """Build a LockfileResult from (name, pqcClassification) pairs."""
    return {
        "ecosystem": "python",
        "components": [
            {
                "name": name,
                "version": "1.0.0",
                "ecosystem": "python",
                "type": "library",
                "pqcClassification": cls,
            }
            for name, cls in specs
        ],
    }


def _matrix():
    scan_result = scan_parser({
        "algorithms": [],
        "tls_endpoints": [],
        "dependencies": [],
        "pqc_grades": {},
    })
    from pqblocks_cnsa_evidence.parsers import compliance_matrix_emitter
    return compliance_matrix_emitter(scan_result)


def test_empty_lockfile_produces_empty_plan():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    plan_yaml = migration_scheduler(_lockfile(), _matrix(), {})
    parsed = yaml.safe_load(plan_yaml)
    assert parsed == [] or parsed is None or parsed == ""


def test_single_system_gets_dated_month():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    plan_yaml = migration_scheduler(
        _lockfile(("cryptography", "legacy")), _matrix(),
        {"max_systems_per_month": 5, "start_month": "2027-01"},
    )
    parsed = yaml.safe_load(plan_yaml)
    assert len(parsed) == 1
    entry = parsed[0]
    assert entry["system"] == "cryptography"
    assert MONTH_RE.match(entry["month"]), entry["month"]
    assert entry["reason"]


def test_resource_constraints_honored_capacity_split():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    lock = _lockfile(
        ("aaa-lib", "legacy"), ("bbb-lib", "legacy"), ("ccc-lib", "legacy"),
    )
    parsed = yaml.safe_load(migration_scheduler(
        lock, _matrix(), {"max_systems_per_month": 2, "start_month": "2027-01"}))
    assert len(parsed) == 3
    months = [e["month"] for e in parsed]
    assert months.count("2027-01") == 2
    assert months.count("2027-02") == 1


def test_zero_double_booked_systems():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    lock = _lockfile(
        ("lib-a", "legacy"), ("lib-b", "hybrid"),
        ("lib-c", "PQC-native"), ("lib-d", "unknown"),
    )
    parsed = yaml.safe_load(migration_scheduler(
        lock, _matrix(), {"max_systems_per_month": 10}))
    systems = [e["system"] for e in parsed]
    assert len(systems) == len(set(systems)) == 4


def test_zero_undated_systems():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    lock = _lockfile(("lib-a", "legacy"), ("lib-b", "legacy"))
    parsed = yaml.safe_load(migration_scheduler(lock, _matrix(), {}))
    assert len(parsed) == 2
    for entry in parsed:
        assert "month" in entry and MONTH_RE.match(entry["month"]), entry


def test_dependency_ordering_legacy_before_pqc_native():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    lock = _lockfile(
        ("zzz-pqc", "PQC-native"), ("aaa-legacy", "legacy"),
    )
    parsed = yaml.safe_load(migration_scheduler(
        lock, _matrix(),
        {"max_systems_per_month": 1, "start_month": "2027-01"}))
    by_system = {e["system"]: e["month"] for e in parsed}
    assert by_system["aaa-legacy"] < by_system["zzz-pqc"]


def test_all_months_within_cnsa_deadline():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    lock = _lockfile(*[(f"lib-{i}", "legacy") for i in range(6)])
    parsed = yaml.safe_load(migration_scheduler(
        lock, _matrix(), {"max_systems_per_month": 2, "start_month": "2027-01"}))
    for entry in parsed:
        assert entry["month"] <= "2031-12", entry


def test_deterministic_across_three_runs():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    lock = _lockfile(
        ("lib-b", "hybrid"), ("lib-a", "legacy"), ("lib-c", "PQC-native"))
    args = (lock, _matrix(), {"max_systems_per_month": 2})
    r1 = migration_scheduler(*args)
    r2 = migration_scheduler(*args)
    r3 = migration_scheduler(*args)
    assert r1 == r2 == r3


def test_output_is_valid_yaml_list_of_entries():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    plan_yaml = migration_scheduler(
        _lockfile(("lib-a", "legacy"),), _matrix(), {})
    assert isinstance(plan_yaml, str)
    parsed = yaml.safe_load(plan_yaml)
    assert isinstance(parsed, list)
    for entry in parsed:
        assert set(("system", "month", "reason")) <= set(entry)


def test_zero_capacity_raises():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    with pytest.raises(ValueError):
        migration_scheduler(
            _lockfile(("lib-a", "legacy"),), _matrix(),
            {"max_systems_per_month": 0})


def test_bad_start_month_raises():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    with pytest.raises(ValueError):
        migration_scheduler(
            _lockfile(("lib-a", "legacy"),), _matrix(),
            {"start_month": "next spring"})


def test_garbage_lockfile_raises_loudly():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    with pytest.raises(TypeError):
        migration_scheduler(None, _matrix(), {})
    with pytest.raises(TypeError):
        migration_scheduler("not-a-dict", _matrix(), {})


def test_component_missing_name_raises():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    bad = {"ecosystem": "python", "components": [{"version": "1.0"}]}
    with pytest.raises(ValueError):
        migration_scheduler(bad, _matrix(), {})


def test_schedule_beyond_deadline_raises():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    lock = _lockfile(("lib-a", "legacy"), ("lib-b", "legacy"))
    with pytest.raises(ValueError):
        migration_scheduler(
            lock, _matrix(),
            {"max_systems_per_month": 1, "start_month": "2031-12"})


def test_team_capacity_alias_honored():
    from pqblocks_cnsa_evidence.parsers import migration_scheduler
    lock = _lockfile(
        ("aaa-lib", "legacy"), ("bbb-lib", "legacy"), ("ccc-lib", "legacy"),
    )
    parsed = yaml.safe_load(migration_scheduler(
        lock, _matrix(), {"team_capacity_per_month": 1, "start_month": "2027-01"}))
    months = [e["month"] for e in parsed]
    assert months == ["2027-01", "2027-02", "2027-03"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
