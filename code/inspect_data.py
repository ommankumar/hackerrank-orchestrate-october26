# #!/usr/bin/env python3
# """Inspect the HackerRank Orchestrate dataset and print a concise summary.

# This helper is intentionally lightweight: it reads the participant-facing CSVs in
# `dataset/`, reports row counts, column names, and a few sample rows, and surfaces
# schema anomalies that are useful when building the final deletion-audit solver.
# """

# from __future__ import annotations

# import argparse
# import csv
# import json
# from collections import Counter
# from pathlib import Path
# from typing import Any, Dict, Iterable, List


# DEFAULT_CSV_FILES = [
#     "deletion_requests.csv",
#     "sample_deletion_requests.csv",
#     "sample_output.csv",
#     "user_identities.csv",
#     "user_audit_log.csv",
#     "system_activity.csv",
#     "deletion_rules.csv",
#     "evidence_files.csv",
# ]


# def as_repo_root() -> Path:
#     """Return the repository root for the current project."""
#     return Path(__file__).resolve().parents[1]


# def read_csv(path: Path) -> List[Dict[str, str]]:
#     """Read a CSV file into a list of dict rows using the first row as headers."""
#     with path.open("r", newline="", encoding="utf-8") as handle:
#         reader = csv.DictReader(handle)
#         if reader.fieldnames is None:
#             return []
#         return [dict(row) for row in reader]


# def inspect_csv(path: Path, max_rows: int = 5) -> Dict[str, Any]:
#     """Collect summary data for a single CSV file."""
#     rows = read_csv(path)
#     file_name = path.name

#     with path.open("r", newline="", encoding="utf-8") as handle:
#         reader = csv.reader(handle)
#         try:
#             header = next(reader)
#         except StopIteration:
#             header = []
#         preview_rows = []
#         for _ in range(max_rows):
#             try:
#                 preview_rows.append(next(reader))
#             except StopIteration:
#                 break

#     summary: Dict[str, Any] = {
#         "file": file_name,
#         "path": str(path),
#         "row_count": len(rows),
#         "column_count": len(header),
#         "columns": header,
#         "preview_rows": preview_rows,
#         "duplicate_rows": 0,
#     }

#     if rows:
#         seen = set()
#         for row in rows:
#             key = tuple((column, row.get(column, "")) for column in header)
#             if key in seen:
#                 summary["duplicate_rows"] += 1
#             else:
#                 seen.add(key)

#     return summary


# def summarize_dataset(dataset_dir: Path, files: Iterable[str] | None = None, max_rows: int = 5) -> Dict[str, Any]:
#     """Summarize the dataset directory and selected CSV files."""
#     dataset_dir = dataset_dir.resolve()
#     selected_files = list(files) if files else DEFAULT_CSV_FILES

#     summaries: List[Dict[str, Any]] = []
#     for filename in selected_files:
#         candidate = dataset_dir / filename
#         if not candidate.exists():
#             continue
#         summaries.append(inspect_csv(candidate, max_rows=max_rows))

#     evidence_summary: Dict[str, Any] = {}
#     evidence_manifest = dataset_dir / "evidence_files.csv"
#     if evidence_manifest.exists():
#         rows = read_csv(evidence_manifest)
#         origins = Counter(row.get("origin", "") for row in rows if row.get("origin"))
#         evidence_summary = {
#             "total_files": len(rows),
#             "origin_counts": dict(sorted(origins.items())),
#         }

#     return {
#         "dataset_dir": str(dataset_dir),
#         "file_count": len(summaries),
#         "files": summaries,
#         "evidence_summary": evidence_summary,
#     }


# def print_summary(summary: Dict[str, Any], max_rows: int = 5) -> None:
#     """Pretty-print the dataset summary to stdout."""
#     print(f"Dataset directory: {summary['dataset_dir']}")
#     print(f"CSV files inspected: {summary['file_count']}")
#     print()

#     for info in summary["files"]:
#         print(f"== {info['file']} ==")
#         print(f"  rows: {info['row_count']}")
#         print(f"  columns: {len(info['columns'])}")
#         print(f"  column names: {', '.join(info['columns'])}")
#         if info["duplicate_rows"]:
#             print(f"  duplicate rows: {info['duplicate_rows']}")
#         if info["preview_rows"]:
#             print("  sample rows:")
#             for row in info["preview_rows"]:
#                 print(f"    {row}")
#         print()

#     evidence = summary.get("evidence_summary")
#     if evidence:
#         print("== evidence summary ==")
#         print(f"  total evidence entries: {evidence.get('total_files', 0)}")
#         if evidence.get("origin_counts"):
#             for origin, count in evidence["origin_counts"].items():
#                 print(f"    {origin}: {count}")
#         print()


# def build_parser() -> argparse.ArgumentParser:
#     parser = argparse.ArgumentParser(
#         description="Inspect the HackerRank Orchestrate dataset and print schema/row summaries."
#     )
#     parser.add_argument(
#         "--dataset-dir",
#         type=Path,
#         default=as_repo_root() / "dataset",
#         help="Path to the dataset directory. Defaults to <repo>/dataset.",
#     )
#     parser.add_argument(
#         "--file",
#         dest="files",
#         nargs="*",
#         help="Optional subset of CSV filenames to inspect (for example: deletion_requests.csv user_identities.csv).",
#     )
#     parser.add_argument(
#         "--max-rows",
#         type=int,
#         default=5,
#         help="Number of sample rows to print per CSV file.",
#     )
#     return parser


# def main() -> int:
#     args = build_parser().parse_args()
#     dataset_dir = args.dataset_dir.resolve()

#     if not dataset_dir.exists():
#         raise FileNotFoundError(f"Dataset directory not found: {dataset_dir}")

#     summary = summarize_dataset(dataset_dir, files=args.files, max_rows=args.max_rows)
#     print_summary(summary, max_rows=args.max_rows)
#     return 0


# if __name__ == "__main__":
#     raise SystemExit(main())

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"


def inspect_csv(filename):
    path = DATASET / filename

    print(f"\n{'=' * 60}")
    print(f"FILE: {filename}")
    print("=" * 60)

    if not path.exists():
        print("File not found:", path)
        return

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        reader = csv.DictReader(file)

        print("Columns:")
        print(reader.fieldnames)

        rows = list(reader)

        print("Total rows:", len(rows))

        for row in rows[:3]:
            print(json.dumps(row, indent=2))


def main():
    files = [
        "deletion_requests.csv",
        "sample_deletion_requests.csv",
        "user_identities.csv",
        "user_audit_log.csv",
        "system_activity.csv",
        "deletion_rules.csv",
        "evidence_files.csv",
        "sample_output.csv",
    ]

    for filename in files:
        inspect_csv(filename)


if __name__ == "__main__":
    main()