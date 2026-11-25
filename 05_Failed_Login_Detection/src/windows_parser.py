import csv
from pathlib import Path


def get_value(row, *field_names, default="Unknown"):
    """Get the first available non-empty value from a CSV row."""

    normalized = {
        str(key).strip().lower(): value
        for key, value in row.items()
        if key is not None
    }

    for field in field_names:
        value = normalized.get(field.lower())

        if value is not None and str(value).strip():
            return str(value).strip()

    return default


def parse_windows_event(row):
    """Parse a Windows Security failed-logon event."""

    event_id = get_value(
        row, "Id", "EventId", "EventID", default=""
    )

    if event_id != "4625":
        return None

    return {
        "platform": "Windows",
        "event_id": "4625",
        "timestamp": get_value(
            row, "TimeCreated", "Timestamp"
        ),
        "username": get_value(
            row, "TargetUserName", "AccountName"
        ),
        "domain": get_value(
            row, "TargetDomainName", "AccountDomain"
        ),
        "source_ip": get_value(
            row, "IpAddress", "SourceNetworkAddress"
        ),
        "workstation": get_value(
            row, "WorkstationName", "Workstation"
        ),
        "logon_type": get_value(
            row, "LogonType"
        ),
        "status": get_value(
            row, "Status"
        ),
        "sub_status": get_value(
            row, "SubStatus", "SubStatusCode"
        ),
        "failure_reason": get_value(
            row, "FailureReason"
        ),
        "authentication_package": get_value(
            row, "AuthenticationPackageName"
        ),
        "logon_process": get_value(
            row, "LogonProcessName"
        ),
        "subject_username": get_value(
            row, "SubjectUserName"
        ),
        "raw": dict(row)
    }


def load_windows_failures(file_path):
    """Load Windows CSV logs and return parsed failed logons."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Windows event log not found: {path}"
        )

    events = []
    skipped_rows = 0

    with path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("CSV file has no header row.")

        for row in reader:
            if not row or not any(row.values()):
                continue

            event = parse_windows_event(row)

            if event is None:
                skipped_rows += 1
                continue

            events.append(event)

    return events, skipped_rows