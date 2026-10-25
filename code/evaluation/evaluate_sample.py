#!/usr/bin/env python3
"""Evaluate the auditor against the public sample cases."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))

from main import audit_case, identity_map, read_csv


def read_expected(path: Path) -> dict[str, tuple[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        raise ValueError(f"Sample answer file is empty: {path}")

    expected: dict[str, tuple[str, str]] = {}
    for row in rows[1:]:
        if len(row) == 3:
            case_id, status, steps = row
        elif len(row) == 2 and rows[0] == ["case_id", "deletion_status", "steps_json"]:
            raise ValueError(f"Malformed sample answer row: {row}")
        else:
            raise ValueError(f"Unexpected sample answer row: {row}")
        expected[case_id] = (status, steps)
    return expected


def main() -> int:
    requests = read_csv(ROOT / "dataset" / "sample_deletion_requests.csv")
    expected = read_expected(ROOT / "dataset" / "sample_output.csv")
    email_to_user, dated_aliases = identity_map()
    manifest = read_csv(ROOT / "dataset" / "evidence_files.csv")

    status_matches = 0
    for request in requests:
        case_id = request["case_id"]
        if case_id not in expected:
            raise ValueError(f"Sample answer missing case: {case_id}")
        actual, _ = audit_case(request, email_to_user, dated_aliases, manifest)
        expected_status, _ = expected[case_id]
        status_matches += actual == expected_status
        if actual != expected_status:
            print(f"{case_id}: predicted {actual}, expected {expected_status}")

    total = len(requests)
    print(f"Public sample status agreement: {status_matches}/{total} ({status_matches / total:.1%})")
    if status_matches != total:
        return 1
    print("PASS: all public sample statuses match.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
