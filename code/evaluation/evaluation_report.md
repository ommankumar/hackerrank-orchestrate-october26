# Evaluation report

## Final run

- Command: `python3 code/main.py`
- Input: `dataset/deletion_requests.csv` (518 requests).
- Structural validation: `python3 code/validate_output.py` passed.
- Output rows: 518, sorted by `case_id`, with the required three columns and parseable JSON arrays.
- Predicted statuses: 459 `INCOMPLETE`, 42 `COMPLETE`, 17 `NOT_APPLICABLE`.
- The solver reads current/historical identifiers and eligible JSON and SQLite evidence. It does not use workflow-reported status as proof.

## Public sample evaluation

The 32 sample requests were evaluated by calling the same audit function used by the full run. Status agreement was **23/32 (71.9%)**. Exact step-sequence agreement was **0/32**. Among the 63 position-aligned step pairs, 6 steps matched exactly and 51/63 fields matched; missing and extra steps are not counted in that field-level denominator.

The checked-in `dataset/sample_output.csv` currently has a modified header that omits `case_id`; the evaluation helper reads its three-column rows positionally and does not change the sample file. The sample cases are separate from the 518 full evaluation requests, so their predictions are evaluated directly rather than being looked up in the full output.

## Three additional evaluation cases

1. **Ghost profile after deletion:** a matching profile is present in the latest eligible account snapshot. Expected: `INCOMPLETE`, report the profile, plan `DELETE_RECORD`, and verify absence.
2. **Permitted tombstone:** a tombstone exists with only the stable internal user reference. Expected: keep the tombstone and verify it is present and redacted; do not delete the stable reference.
3. **Active restore route:** a matching backup has restore access enabled at audit time. Expected: `INCOMPLETE`, report `REPORT_RESTORE_RISK`, plan `BLOCK_RESTORE`, and verify the restore is blocked.

These are authored policy checks; they are not included in the sample accuracy figure.

## Failures found and remaining limitations

- Sample status agreement and exact-step agreement remain below the target; do not treat the generated output as a verified gold-quality submission.
- The evidence scanner currently covers structured JSON snapshots and SQLite-compatible SQL captures. It does not extract PDF/image content or fully parse logs and text artifacts.
- The current fallback is `INCOMPLETE` with an empty step list when no matching structured evidence is found. This preserves a conservative status but does not satisfy the evidence-backed findings/remediation requirements.
- Resource/linkage coverage is incomplete, and the solver does not establish exhaustive per-system absence before returning `COMPLETE`.
- The full evaluation set has no supplied canonical answer file, so full-dataset case, field, and sequence accuracy cannot be calculated.

## Improvements made

1. Replaced the misplaced validator copy in `code/main.py` with a deterministic dataset reader and output generator.
2. Added current and historical email identity mapping with audit-time alias filtering.
3. Added manifest-time filtering and structured JSON/SQL evidence inspection.
4. Added policy-aware treatments for deletion, redaction, anonymization, retention, tombstones, data flows, and restore risks.
5. Corrected global step numbering across finding, remediation, and verification phases.
6. Added multilingual deletion-intent terms and fixed the sample evaluator to exercise the same audit function on sample inputs.

## Regression command

Run `python3 code/evaluation/evaluate_sample.py` for the public sample comparison. It currently exits nonzero because 9 of 32 public statuses still differ.
