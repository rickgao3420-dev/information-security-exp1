"""Compare another group's JSON/CSV exchange vectors with a local S-DES implementation.

This script only records real supplied vectors. Its presence does not mean an
external group test has occurred. JSON uses {"vectors": [...]} (or a bare list);
CSV uses schedule,key_bits,plaintext_bits,ciphertext_bits columns.
"""

import argparse
import csv
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import reference_sdes
import sdes


def parse_vector(row, number):
    schedule = row.get("schedule", "assignment")
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
    if vector_path.suffix.lower() == ".csv":
        with vector_path.open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
    else:
        contents = json.loads(vector_path.read_text(encoding="utf-8-sig"))
        rows = contents["vectors"] if isinstance(contents, dict) else contents
    if not isinstance(rows, list) or not rows:
        raise ValueError("At least one supplied vector is required")
    implementation = sdes if args.implementation == "core" else reference_sdes
    differences = []
    for number, row in enumerate(rows, 1):
        schedule, key, plain, expected = parse_vector(row, number)
        actual = implementation.encrypt_block(plain, key, schedule)
        decrypted = implementation.decrypt_block(expected, key, schedule)
        if actual != expected or decrypted != plain:
            differences.append({"row": number, "schedule": schedule, "key_bits": f"{key:010b}",
                                "plaintext_bits": f"{plain:08b}", "supplied_ciphertext_bits": f"{expected:08b}",
                                "local_ciphertext_bits": f"{actual:08b}", "local_decrypted_plaintext_bits": f"{decrypted:08b}"})
    result = {"created_at": datetime.now().astimezone().isoformat(timespec="milliseconds"),
              "source_label": args.source_label, "source_path": str(vector_path),
              "source_sha256": hashlib.sha256(vector_path.read_bytes()).hexdigest(),
              "implementation": args.implementation, "vectors_checked": len(rows), "mismatches": differences,
              "successful": not differences,
              "scope": "Comparison of the supplied file only; external-group provenance depends on the source label and actual file origin."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Checked {len(rows)} vectors; mismatches={len(differences)}; report={args.output.resolve()}")
    return 0 if not differences else 1


if __name__ == "__main__":
    raise SystemExit(main())
