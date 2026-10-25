import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"

INPUT_FILE = DATASET / "deletion_requests.csv"
OUTPUT_FILE = ROOT / "output.csv"

EXPECTED_COLUMNS = [
    "case_id",
    "deletion_status",
    "steps_json",
]

ALLOWED_STATUSES = {
    "COMPLETE",
    "INCOMPLETE",
    "NOT_APPLICABLE",
}

ALLOWED_PHASES = {
    "FINDING",
    "REMEDIATION",
    "VERIFICATION",
}


def read_csv(path):
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        reader = csv.DictReader(file)

        if reader.fieldnames is None:
            raise ValueError(f"Missing CSV header: {path}")

        return reader.fieldnames, list(reader)


def validate():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(INPUT_FILE)

    if not OUTPUT_FILE.exists():
        raise FileNotFoundError(
            "output.csv not found. Run the agent first."
        )

    _, requests = read_csv(INPUT_FILE)
    columns, predictions = read_csv(OUTPUT_FILE)

    assert columns == EXPECTED_COLUMNS, (
        f"Incorrect columns: {columns}"
    )

    assert len(predictions) == len(requests), (
        f"Expected {len(requests)} rows, "
        f"found {len(predictions)}"
    )

    expected_ids = {
        row["case_id"]
        for row in requests
    }

    actual_ids = [
        row["case_id"]
        for row in predictions
    ]

    assert len(actual_ids) == len(set(actual_ids)), (
        "Duplicate case_id values found."
    )

    assert set(actual_ids) == expected_ids, (
        "Missing or unexpected case IDs."
    )

    assert actual_ids == sorted(actual_ids), (
        "Output rows must be sorted by case_id."
    )

    for row in predictions:
        case_id = row["case_id"]
        status = row["deletion_status"]

        assert status in ALLOWED_STATUSES, (
            f"{case_id}: invalid status {status}"
        )

        steps = json.loads(row["steps_json"])

        assert isinstance(steps, list), (
            f"{case_id}: steps_json must be a JSON array"
        )

        if status == "NOT_APPLICABLE":
            assert steps == [], (
                f"{case_id}: NOT_APPLICABLE requires []"
            )
            continue

        for index, step in enumerate(steps, start=1):
            required_fields = {
                "step_no",
                "phase",
                "system_id",
                "resource_id",
                "operation",
                "state",
                "evidence_id",
            }

            assert set(step.keys()) == required_fields, (
                f"{case_id}: incorrect fields in step {index}"
            )

            assert step["step_no"] == index, (
                f"{case_id}: incorrect step numbering"
            )

            assert step["phase"] in ALLOWED_PHASES, (
                f"{case_id}: invalid phase"
            )

        phases = [
            step["phase"]
            for step in steps
        ]

        phase_order = {
            "FINDING": 0,
            "REMEDIATION": 1,
            "VERIFICATION": 2,
        }

        assert phases == sorted(
            phases,
            key=lambda phase: phase_order[phase],
        ), f"{case_id}: phases are out of order"

    print("Validation passed.")
    print("Input requests:", len(requests))
    print("Output predictions:", len(predictions))
    print("Output columns:", columns)


if __name__ == "__main__":
    validate()