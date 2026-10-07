"""Check that the exchange tool accepts genuine agreement and flags mismatch."""

import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "compare_cross_vectors.py"
VECTORS = [
    {"schedule": "assignment", "key_bits": "1010000010", "plaintext_bits": "10011010", "ciphertext_bits": "11101111"},
    {"schedule": "cumulative", "key_bits": "1010000010", "plaintext_bits": "10011010", "ciphertext_bits": "01101011"},
]


class ExchangeScriptTests(unittest.TestCase):
    def run_fixture(self, rows, csv_format=False, implementation="core", previous_report=None, raw_json=None):
        with tempfile.TemporaryDirectory(prefix="sdes-exchange-") as temporary:
            folder = Path(temporary)
            vector_file = folder / ("vectors.csv" if csv_format else "vectors.json")
            output = folder / "comparison.json"
            if csv_format:
                with vector_file.open("w", encoding="utf-8", newline="") as stream:
                    writer = csv.DictWriter(stream, fieldnames=list(VECTORS[0]))
                    writer.writeheader()
                    writer.writerows(rows)
            else:
                vector_file.write_text(raw_json if raw_json is not None else json.dumps({"vectors": rows}), encoding="utf-8")
            if previous_report is not None:
                output.write_text(json.dumps(previous_report), encoding="utf-8")
            command = [sys.executable, str(SCRIPT), str(vector_file), "--output", str(output),
                       "--implementation", implementation, "--source-label", "internal unittest fixture"]
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
            report = json.loads(output.read_text(encoding="utf-8")) if output.exists() else None
            return result.returncode, report

    def test_json_vectors_match_integer_implementation(self):
        code, report = self.run_fixture(VECTORS)
        self.assertEqual(code, 0)
        self.assertTrue(report["successful"])
        self.assertEqual(report["vectors_checked"], 2)

    def test_csv_vectors_match_string_implementation(self):
        code, report = self.run_fixture(VECTORS, csv_format=True, implementation="reference")
        self.assertEqual(code, 0)
        self.assertTrue(report["successful"])

    def test_wrong_ciphertext_is_reported(self):
        rows = [dict(VECTORS[0], ciphertext_bits="00000000")]
        code, report = self.run_fixture(rows)
        self.assertEqual(code, 1)
        self.assertFalse(report["successful"])
        self.assertEqual(report["mismatches"][0]["row"], 1)

    def test_malformed_bits_are_rejected(self):
        code, report = self.run_fixture([dict(VECTORS[0], key_bits="101")])
        self.assertEqual(code, 2)
        self.assertFalse(report["successful"])
        self.assertEqual(report["status"], "invalid_input")
        self.assertEqual(report["input_errors"][0]["row"], 1)
        self.assertEqual(report["vectors_checked"], 0)

    def test_invalid_input_replaces_previous_successful_report(self):
        code, report = self.run_fixture([dict(VECTORS[0], key_bits="101")],
                                        previous_report={"successful": True, "vectors_checked": 999})
        self.assertEqual(code, 2)
        self.assertFalse(report["successful"])
        self.assertEqual(report["vectors_checked"], 0)
        self.assertTrue(report["source_sha256"])

    def test_invalid_json_structure_is_reported(self):
        for payload in ("{}", "[]", "null", "[1]", "{broken"):
            with self.subTest(payload=payload):
                code, report = self.run_fixture([], raw_json=payload)
                self.assertEqual(code, 2)
                self.assertFalse(report["successful"])
                self.assertTrue(report["input_errors"])

    def test_output_cannot_overwrite_supplied_vectors(self):
        with tempfile.TemporaryDirectory(prefix="sdes-exchange-") as temporary:
            vector_file = Path(temporary) / "vectors.json"
            original = json.dumps({"vectors": VECTORS}).encode("utf-8")
            vector_file.write_bytes(original)
            command = [sys.executable, str(SCRIPT), str(vector_file), "--output", str(vector_file)]
            result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(vector_file.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
