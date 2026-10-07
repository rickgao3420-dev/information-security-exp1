"""Compare another group's JSON/CSV exchange vectors with a local S-DES implementation.

This script only records real supplied vectors. Its presence does not mean an
external group test has occurred. JSON uses {"vectors": [...]} (or a bare list);
CSV uses schedule,key_bits,plaintext_bits,ciphertext_bits columns.
"""

import argparse
import csv
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reference_sdes
import sdes


def parse_vector(row, number):
    if not isinstance(row, dict):
        raise ValueError(f"Row {number} must be a JSON object or CSV record")
    schedule = row.get("schedule", "assignment")
    if schedule not in sdes.SCHEDULES:
        raise ValueError(f"Row {number}: schedule must be assignment or cumulative")
    key = row.get("key_bits", row.get("key"))
    plain = row.get("plaintext_bits", row.get("plaintext"))
    cipher = row.get("ciphertext_bits", row.get("ciphertext"))
    return schedule, sdes.parse_bits(key, 10), sdes.parse_bits(plain, 8), sdes.parse_bits(cipher, 8)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vectors", type=Path, help="Actual supplied .json/.csv exchange file")
    parser.add_argument("--implementation", choices=("core", "reference"), default="core")
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "external_vector_comparison.json")
    parser.add_argument("--source-label", default="supplied vector file", help="Actual provenance, e.g. group number")
    args = parser.parse_args()
    vector_path = args.vectors.resolve()
    output_path = args.output.resolve()
    if output_path == vector_path:
        parser.error("--output must differ from the supplied vector file")
    input_errors = []
    source_hash = None
    rows = []
    try:
        source_bytes = vector_path.read_bytes()
        source_hash = hashlib.sha256(source_bytes).hexdigest()
        source_text = source_bytes.decode("utf-8-sig")
        if vector_path.suffix.lower() == ".csv":
            rows = list(csv.DictReader(io.StringIO(source_text, newline="")))
        else:
            contents = json.loads(source_text)
            rows = contents.get("vectors") if isinstance(contents, dict) else contents
        if not isinstance(rows, list) or not rows:
            raise ValueError("At least one supplied vector is required in a list or a vectors array")
    except (OSError, UnicodeError, ValueError, csv.Error) as error:
        input_errors.append({"row": None, "error": str(error)})
        rows = []
    implementation = sdes if args.implementation == "core" else reference_sdes
    differences = []
    checked = 0
    for number, row in enumerate(rows, 1):
        try:
            schedule, key, plain, expected = parse_vector(row, number)
        except ValueError as error:
            input_errors.append({"row": number, "error": str(error)})
            continue
        actual = implementation.encrypt_block(plain, key, schedule)
        decrypted = implementation.decrypt_block(expected, key, schedule)
        checked += 1
        if actual != expected or decrypted != plain:
            differences.append({"row": number, "schedule": schedule, "key_bits": f"{key:010b}",
                                "plaintext_bits": f"{plain:08b}", "supplied_ciphertext_bits": f"{expected:08b}",
                                "local_ciphertext_bits": f"{actual:08b}", "local_decrypted_plaintext_bits": f"{decrypted:08b}"})
    status = "invalid_input" if input_errors else "mismatch" if differences else "passed"
    result = {"schema": "sdes-vector-comparison-v1", "status": status,
              "created_at": datetime.now().astimezone().isoformat(timespec="milliseconds"),
              "source_label": args.source_label, "source_path": str(vector_path),
              "source_sha256": source_hash,
              "implementation": args.implementation, "vectors_supplied": len(rows),
              "vectors_checked": checked, "mismatches": differences, "input_errors": input_errors,
              "successful": status == "passed",
              "scope": "Comparison of the supplied file only; external-group provenance depends on the source label and actual file origin."}
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Checked {checked} vectors; mismatches={len(differences)}; input_errors={len(input_errors)}; report={output_path}")
    return 2 if input_errors else 1 if differences else 0


if __name__ == "__main__":
    raise SystemExit(main())
