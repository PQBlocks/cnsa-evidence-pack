"""G5-H3 residual: parser misuse surface must fail loudly, never silent-return.

Covers the recorded attempt6 FAIL classes still reproducible on current disk:
  H3-A: lockfile_parser('python', <garbage>) silently returns zero components.
  H3-B: unparseable requirement versions silently default to 0.0.0 (spec edge 5
         allows logged-unknown, but nothing is logged).
  H3-C: compliance_matrix_emitter propagates non-finite breakYear / non-grade
         values verbatim, and raises bare AttributeError on non-dict input
         instead of the TypeError contract the other parsers honor.
"""
import math

import pytest

import sys

from pqblocks_cnsa_evidence.parsers import lockfile_parser, compliance_matrix_emitter


class TestH3APythonGarbageLoud:
    def test_garbage_content_raises(self):
        with pytest.raises(ValueError, match="no parseable components"):
            lockfile_parser("python", "this is not a lockfile !!!")

    def test_xml_content_in_python_branch_raises(self):
        with pytest.raises(ValueError, match="no parseable components"):
            lockfile_parser("python", "<project><x>1</x></project>")

    def test_empty_string_still_graceful(self):
        # Spec edge #2/#3: genuinely empty input stays graceful, never raises.
        result = lockfile_parser("python", "")
        assert result == {"ecosystem": "python", "components": []}


class TestH3BVersionFallbackLogged:
    def test_bad_version_warns_but_keeps_component(self):
        with pytest.warns(UserWarning, match="version"):
            result = lockfile_parser("python", "requests==notaversion???")
        assert len(result["components"]) == 1
        assert result["components"][0]["version"] == "0.0.0"

    def test_skipped_garbage_line_warns(self):
        with pytest.warns(UserWarning, match="skip"):
            result = lockfile_parser("python", "requests==2.31.0\n!!!garbage line!!!\n")
        names = [c["name"] for c in result["components"]]
        assert "requests" in names


class TestH3CComplianceMatrixValidation:
    def test_inf_break_year_coerced_to_zero_partial(self):
        matrix = compliance_matrix_emitter({"algorithms": [{
            "name": "ML-KEM-768", "type": "key-encapsulation", "mode": "PQC",
            "keySize": 768, "cnsA20Grade": "A", "breakYear": float("inf"),
        }]})
        entry = matrix["key-establishment"]
        assert entry["breakYear"] == 0
        assert entry["breakYear"] != float("inf")
        assert isinstance(entry["breakYear"], int)
        assert entry["evidence"] == "partial"

    def test_nan_grade_coerced_to_f(self):
        matrix = compliance_matrix_emitter({"algorithms": [{
            "name": "X", "type": "signature", "mode": "classical",
            "keySize": 256, "cnsA20Grade": float("nan"), "breakYear": 2030,
        }]})
        assert matrix["signature"]["grade"] == "F"

    def test_non_dict_scan_raises_type_error(self):
        with pytest.raises(TypeError, match="Expected dict"):
            compliance_matrix_emitter("not a dict")

    def test_none_scan_raises_type_error(self):
        with pytest.raises(TypeError, match="Expected dict"):
            compliance_matrix_emitter(None)

    def test_non_dict_algorithm_entry_raises(self):
        with pytest.raises(TypeError, match="algorithm entry"):
            compliance_matrix_emitter({"algorithms": [42]})


class TestEmittersNameTheirBadInput:
    def test_non_dict_inputs_are_a_typeerror_not_attributeerror(self):
        from pqblocks_cnsa_evidence.parsers import sbom_emitter, crypto_inventory_emitter
        for fn in (sbom_emitter, crypto_inventory_emitter):
            for a, b in ((None, {}), ({}, None), ("x", {}), ([], [])):
                with pytest.raises(TypeError, match="Expected dict"):
                    fn(a, b)
