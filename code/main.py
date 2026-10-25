#!/usr/bin/env python3
"""Generate deletion-audit predictions from the participant-facing dataset."""

from __future__ import annotations

import csv
import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
REQUESTS_FILE = DATASET / "deletion_requests.csv"
IDENTITIES_FILE = DATASET / "user_identities.csv"
AUDIT_FILE = DATASET / "user_audit_log.csv"
MANIFEST_FILE = DATASET / "evidence_files.csv"
OUTPUT_FILE = ROOT / "output.csv"
OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")

DELETE_CATEGORIES = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "SUPPORT_ATTACHMENT",
    "USER_EXPORT",
    "MARKETING_PROFILE",
}
ANONYMIZE_CATEGORIES = {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}
REDACT_CATEGORIES = {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}
RETAIN_CATEGORIES = {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}

IDENTIFIER_KEYS = {
    "email",
    "owner_email",
    "requester_email",
    "customer_email",
    "phone",
    "owner_phone",
    "requester_phone",
    "customer_phone",
    "name",
    "full_name",
    "requester_name",
    "display_name",
    "email_hash",
    "subject_reference",
    "lookup_value",
    "customer_reference",
    "user_id",
    "user_ref",
}

DELETION_TERMS = re.compile(
    r"\b(delet\w*|eras\w*|remov\w*|"
    r"close my account|close the account|close this account|"
    r"right to be forgotten|eliminar\w*|borrar\w*|suprimir\w*|exclus\w*|"
    r"cerrar mi cuenta|effacer\w*|supprimer\w*|suppression|"
    r"löschen|loeschen|entfernen|konto löschen|"
    r"excluir\w*|apagar\w*|deletar\w*|encerrar minha conta|"
    r"verify that my account was deleted|confirm that the profile is gone)\b",
    re.IGNORECASE,
)
NON_DELETION_TERMS = re.compile(
    r"\b(marketing opt[- ]?out|stop marketing|unsubscribe|"
    r"access request|subject access|export my data|"
    r"correct my|update my|change my|rectify|"
    r"opt[- ]?out|do not delete|don't delete|not delete|"
    r"no elimine|no borrar|no eliminar|acceso a mis datos|"
    r"corrija|actualice|rectificar|accès à mes données|"
    r"berichtigen|auskunft über meine daten)\b",
    re.IGNORECASE,
)


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def authorizes_deletion(text: str) -> bool:
    has_cjk_deletion = any(term in text for term in ("削除", "消去", "抹消", "삭제"))
    return bool(
        (DELETION_TERMS.search(text) or has_cjk_deletion)
        and not NON_DELETION_TERMS.search(text)
    )


def identity_map() -> tuple[
    dict[str, str],
    dict[str, list[tuple[str, str]]],
]:
    email_to_user: dict[str, str] = {}
    dated_aliases: dict[str, list[tuple[str, str]]] = defaultdict(list)

    for row in read_csv(IDENTITIES_FILE):
        user_id = row["user_id"]
        for field in ("user_id", "name", "email", "phone", "email_hash"):
            value = row.get(field, "").strip()
            if value:
                dated_aliases[user_id].append((row.get("updated_at", ""), value))
                if field == "email":
                    email_to_user[value.casefold()] = user_id

    for row in read_csv(AUDIT_FILE):
        user_id = row["user_id"]
        for field in ("old_value", "new_value"):
            value = row.get(field, "").strip()
            if value:
                dated_aliases[user_id].append((row.get("event_time", ""), value))
                if "email" in row.get("field_name", "").casefold():
                    email_to_user[value.casefold()] = user_id
    return email_to_user, dated_aliases


def match_user(request: dict[str, str], email_to_user: dict[str, str]) -> str | None:
    return email_to_user.get(request.get("email", "").strip().casefold())


@dataclass(frozen=True)
class Observation:
    system: str
    resource: str
    category: str
    timestamp: str
    evidence_id: str
    result: str
    record: dict[str, Any]


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def matches_aliases(record: dict[str, Any], aliases: set[str]) -> bool:
    normalized = {value.casefold() for value in aliases if value}
    for key, value in record.items():
        if key.casefold() in IDENTIFIER_KEYS and as_text(value).casefold() in normalized:
            return True
    return False


def system_for_table(table: str) -> str:
    if table == "customer_profiles":
        return "account_service"
    if table == "customer_search_documents":
        return "search_service"
    if table == "customer_analytics_profiles":
        return "analytics_platform"
    if table == "support_records":
        return "support_platform"
    if table == "customer_exports":
        return "export_service"
    if table == "connector_subscriptions":
        return "integration_service"
    if table == "backup_restore_entries":
        return "backup_service"
    if table == "security_audit_records":
        return "security_service"
    return table.removesuffix("s")


def category_for_table(table: str) -> str:
    return {
        "customer_profiles": "USER_PROFILE",
        "customer_search_documents": "SEARCH_INDEX_ENTRY",
        "customer_analytics_profiles": "ANALYTICS_PROFILE",
        "support_records": "SUPPORT_MESSAGE",
        "customer_exports": "USER_EXPORT",
        "connector_subscriptions": "DATA_FLOW",
        "backup_restore_entries": "BACKUP_ARCHIVE",
        "security_audit_records": "SECURITY_AUDIT_LOG",
    }.get(table, table.upper())


def result_for(record: dict[str, Any]) -> str:
    for key in ("result", "state", "status", "account_status", "deletion_status"):
        value = record.get(key)
        if value is not None:
            return str(value).upper()
    if record.get("enabled") in (1, "1", True):
        return "ACTIVE"
    if record.get("restore_allowed") in (1, "1", True):
        return "ACTIVE"
    return "FOUND"


def iter_json_records(payload: Any):
    if not isinstance(payload, dict):
        return
    snapshots = payload.get("snapshots")
    if isinstance(snapshots, list):
        for snapshot in snapshots:
            if not isinstance(snapshot, dict):
                continue
            system = str(snapshot.get("data_store", ""))
            collection = str(snapshot.get("collection", ""))
            timestamp = str(snapshot.get("captured_at", payload.get("exported_at", "")))
            category = category_for_collection(collection)
            records = snapshot.get("records", [])
            if isinstance(records, list):
                for record in records:
                    if isinstance(record, dict):
                        yield system, category, timestamp, record
        return

    records = payload.get("records")
    if isinstance(records, list):
        timestamp = str(payload.get("captured_at", payload.get("exported_at", "")))
        for record in records:
            if not isinstance(record, dict):
                continue
            yield (
                str(record.get("system", payload.get("source", ""))),
                str(record.get("record_type", payload.get("collection", ""))).upper(),
                str(record.get("recorded_at", timestamp)),
                record,
            )

    exports = payload.get("service_exports")
    if isinstance(exports, list):
        for service in exports:
            if not isinstance(service, dict):
                continue
            system = str(service.get("system", service.get("service", "")))
            category = str(service.get("record_type", service.get("category", ""))).upper()
            timestamp = str(service.get("captured_at", payload.get("exported_at", "")))
            for key, records in service.items():
                if not isinstance(records, list):
                    continue
                inferred = category or category_for_collection(key)
                for record in records:
                    if isinstance(record, dict) and record.get("resource_id"):
                        yield system, inferred, timestamp, record


def category_for_collection(value: str) -> str:
    text = value.casefold()
    if "tombstone" in text or "deleted_customer_references" in text:
        return "ACCOUNT_TOMBSTONE"
    if "profile" in text or "account" in text:
        return "USER_PROFILE"
    if "search" in text or "index" in text:
        return "SEARCH_INDEX_ENTRY"
    if "analytic" in text:
        return "ANALYTICS_PROFILE"
    if "telemetry" in text:
        return "PRODUCT_TELEMETRY"
    if "support" in text or "conversation" in text or "message" in text:
        return "SUPPORT_MESSAGE"
    if "attachment" in text:
        return "SUPPORT_ATTACHMENT"
    if "export" in text:
        return "USER_EXPORT"
    if "marketing" in text:
        return "MARKETING_PROFILE"
    if "delivery" in text or "email" in text:
        return "EMAIL_DELIVERY_LOG"
    if "security" in text or "audit" in text:
        return "SECURITY_AUDIT_LOG"
    if "legal" in text or "hold" in text:
        return "LEGAL_HOLD_RECORD"
    if "backup" in text or "restore" in text or "archive" in text:
        return "BACKUP_ARCHIVE"
    if "connector" in text or "subscription" in text or "flow" in text:
        return "DATA_FLOW"
    return text.upper()


def collect_observations(
    request: dict[str, str],
    aliases: set[str],
    manifest: list[dict[str, str]],
) -> list[Observation]:
    audit_at = parse_time(request.get("audit_at"))
    observations: list[Observation] = []

    for item in manifest:
        evidence_time = parse_time(item.get("captured_at"))
        if audit_at and evidence_time and evidence_time > audit_at:
            continue
        path = DATASET / item["file_path"]
        if not path.is_file():
            continue
        evidence_id = item["file_id"]

        if path.suffix.casefold() == ".json":
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for system, category, timestamp, record in iter_json_records(payload):
                record_time = parse_time(timestamp)
                if audit_at and record_time and record_time > audit_at:
                    continue
                if not record.get("resource_id") or not matches_aliases(record, aliases):
                    continue
                observations.append(
                    Observation(
                        system=system or item.get("origin", ""),
                        resource=str(record["resource_id"]),
                        category=category or "UNKNOWN",
                        timestamp=timestamp or item.get("captured_at", ""),
                        evidence_id=evidence_id,
                        result=result_for(record),
                        record=record,
                    )
                )

        elif path.suffix.casefold() == ".sql":
            connection = sqlite3.connect(":memory:")
            try:
                connection.executescript(path.read_text(encoding="utf-8"))
                tables = connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                for (table,) in tables:
                    if table == "snapshot_scope":
                        continue
                    cursor = connection.execute(f'SELECT * FROM "{table}"')
                    columns = [column[0] for column in cursor.description or ()]
                    for values in cursor.fetchall():
                        record = dict(zip(columns, values))
                        if not record.get("resource_id") or not matches_aliases(record, aliases):
                            continue
                        timestamp = str(record.get("updated_at", item.get("captured_at", "")))
                        record_time = parse_time(timestamp)
                        if audit_at and record_time and record_time > audit_at:
                            continue
                        observations.append(
                            Observation(
                                system=system_for_table(table),
                                resource=str(record["resource_id"]),
                                category=category_for_table(table),
                                timestamp=timestamp,
                                evidence_id=evidence_id,
                                result=result_for(record),
                                record=record,
                            )
                        )
            except sqlite3.Error:
                continue
            finally:
                connection.close()
    return observations


def latest_observations(observations: list[Observation]) -> list[Observation]:
    latest: dict[tuple[str, str], Observation] = {}
    for observation in observations:
        key = (observation.system, observation.resource)
        prior = latest.get(key)
        if prior is None or observation.timestamp > prior.timestamp:
            latest[key] = observation
    return sorted(latest.values(), key=lambda item: (item.system, item.resource))


def is_present(observation: Observation) -> bool:
    if observation.category == "ACCOUNT_TOMBSTONE":
        return True
    return observation.result not in {
        "NOT_FOUND",
        "ABSENT",
        "DELETED",
        "NOT_PRESENT",
        "MISSING",
    }


def has_direct_identifiers(observation: Observation, aliases: set[str]) -> bool:
    user_id_values = {value.casefold() for value in aliases if value.startswith("user_")}
    for key, value in observation.record.items():
        if key.casefold() not in IDENTIFIER_KEYS or value in (None, ""):
            continue
        value_text = str(value).casefold()
        if value_text not in user_id_values:
            return True
    return False


def required_action(category: str, observation: Observation) -> str:
    if category in DELETE_CATEGORIES:
        return "DELETE"
    if category in ANONYMIZE_CATEGORIES:
        return "ANONYMIZE"
    if category in REDACT_CATEGORIES:
        return "REDACT"
    if category == "BACKUP_ARCHIVE":
        return "BLOCK_RESTORE" if str(observation.record.get("restore_allowed", "")).casefold() in {"1", "true", "yes"} else "RETAIN"
    if category == "DATA_FLOW":
        return "DISABLE_FLOW" if str(observation.record.get("enabled", "")).casefold() in {"1", "true", "yes"} or observation.result == "ACTIVE" else "NONE"
    if category == "LEGAL_HOLD_RECORD":
        return "RETAIN" if str(observation.record.get("active", "true")).casefold() in {"1", "true", "yes", "active"} else "NONE"
    if category in RETAIN_CATEGORIES:
        return "RETAIN"
    return "NONE"


def make_step(
    number: int,
    phase: str,
    system: str,
    resource: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, Any]:
    return {
        "step_no": number,
        "phase": phase,
        "system_id": system,
        "resource_id": resource,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def audit_case(
    request: dict[str, str],
    email_to_user: dict[str, str],
    dated_aliases_by_user: dict[str, list[tuple[str, str]]],
    manifest: list[dict[str, str]],
) -> tuple[str, list[dict[str, Any]]]:
    if not authorizes_deletion(request.get("request_text", "")):
        return "NOT_APPLICABLE", []

    user_id = match_user(request, email_to_user)
    if user_id is None:
        return "INCOMPLETE", []

    audit_at = parse_time(request.get("audit_at"))
    aliases = {user_id, request.get("email", "")}
    aliases.update(
        value
        for timestamp, value in dated_aliases_by_user.get(user_id, [])
        if not audit_at or not parse_time(timestamp) or parse_time(timestamp) <= audit_at
    )
    observations = latest_observations(collect_observations(request, aliases, manifest))
    findings: list[tuple[Observation, str, str]] = []
    compliant: list[tuple[Observation, str, str]] = []

    for observation in observations:
        category = observation.category
        action = required_action(category, observation)
        present = is_present(observation)

        if action == "DISABLE_FLOW" and present:
            findings.append((observation, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"))
        elif action == "BLOCK_RESTORE" and present:
            findings.append((observation, "REPORT_RESTORE_RISK", "ACTIVE"))
        elif action == "DELETE" and present:
            findings.append((observation, "REPORT_REMAINING_RECORD", "PRESENT"))
        elif action == "ANONYMIZE":
            if present and (
                has_direct_identifiers(observation, aliases)
                or any(
                    str(value).casefold() == user_id.casefold()
                    for key, value in observation.record.items()
                    if key.casefold() in IDENTIFIER_KEYS and value is not None
                )
            ):
                findings.append((observation, "REPORT_EXPOSED_PII", "PRESENT"))
            else:
                compliant.append((observation, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"))
        elif action == "REDACT":
            if present and has_direct_identifiers(observation, aliases):
                findings.append((observation, "REPORT_EXPOSED_PII", "PRESENT"))
            elif present:
                compliant.append((observation, "VERIFY_RECORD_REDACTED", "REDACTED"))
        elif action == "RETAIN" and present:
            compliant.append((observation, "VERIFY_RECORD_PRESENT", "PRESENT"))
        elif action == "DELETE" and not present:
            compliant.append((observation, "VERIFY_RECORD_ABSENT", "ABSENT"))

    if findings:
        finding_steps = [
            make_step(i, "FINDING", obs.system, obs.resource, operation, state, obs.evidence_id)
            for i, (obs, operation, state) in enumerate(findings, start=1)
        ]
        remediation: list[dict[str, Any]] = []
        verification: list[dict[str, Any]] = []
        next_no = len(finding_steps) + 1
        for obs, finding_operation, _ in findings:
            if finding_operation == "REPORT_ACTIVE_DATA_FLOW":
                rem_op, rem_state, ver_op, ver_state = "DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
            elif finding_operation == "REPORT_RESTORE_RISK":
                rem_op, rem_state, ver_op, ver_state = "BLOCK_RESTORE", "BLOCKED", "VERIFY_RESTORE_BLOCKED", "BLOCKED"
            elif finding_operation == "REPORT_EXPOSED_PII" and obs.category in ANONYMIZE_CATEGORIES:
                rem_op, rem_state, ver_op, ver_state = "ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
            elif finding_operation == "REPORT_EXPOSED_PII":
                rem_op, rem_state, ver_op, ver_state = "REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REDACTED"
            else:
                rem_op, rem_state, ver_op, ver_state = "DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT"
            remediation.append(make_step(next_no, "REMEDIATION", obs.system, obs.resource, rem_op, rem_state, ""))
            next_no += 1
        verification_no = next_no
        for obs, finding_operation, _ in findings:
            if finding_operation == "REPORT_ACTIVE_DATA_FLOW":
                ver_op, ver_state = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
            elif finding_operation == "REPORT_RESTORE_RISK":
                ver_op, ver_state = "VERIFY_RESTORE_BLOCKED", "BLOCKED"
            elif finding_operation == "REPORT_EXPOSED_PII" and obs.category in ANONYMIZE_CATEGORIES:
                ver_op, ver_state = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
            elif finding_operation == "REPORT_EXPOSED_PII":
                ver_op, ver_state = "VERIFY_RECORD_REDACTED", "REDACTED"
            else:
                ver_op, ver_state = "VERIFY_RECORD_ABSENT", "ABSENT"
            verification.append(
                make_step(verification_no, "VERIFICATION", obs.system, obs.resource, ver_op, ver_state, "")
            )
            verification_no += 1
        verification.extend(
            make_step(verification_no + index, "VERIFICATION", obs.system, obs.resource, operation, state, "")
            for index, (obs, operation, state) in enumerate(compliant)
        )
        return "INCOMPLETE", finding_steps + remediation + verification

    if compliant:
        steps = [
            make_step(i, "VERIFICATION", obs.system, obs.resource, operation, state, obs.evidence_id)
            for i, (obs, operation, state) in enumerate(compliant, start=1)
        ]
        return "COMPLETE", steps

    return "INCOMPLETE", []


def write_output(rows: list[dict[str, str]]) -> None:
    with OUTPUT_FILE.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    for required in (REQUESTS_FILE, IDENTITIES_FILE, AUDIT_FILE, MANIFEST_FILE):
        if not required.is_file():
            raise FileNotFoundError(f"Required dataset file not found: {required}")

    requests = read_csv(REQUESTS_FILE)
    email_to_user, dated_aliases_by_user = identity_map()
    manifest = read_csv(MANIFEST_FILE)

    output: list[dict[str, str]] = []
    for request in sorted(requests, key=lambda item: item["case_id"]):
        status, steps = audit_case(
            request,
            email_to_user,
            dated_aliases_by_user,
            manifest,
        )
        output.append(
            {
                "case_id": request["case_id"],
                "deletion_status": status,
                "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
            }
        )

    write_output(output)
    print(f"Wrote {len(output)} predictions to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
