import csv
from pathlib import Path


WINDOWS_EVENT_TYPES = {
    "4672": "SPECIAL_PRIVILEGES_ASSIGNED",
    "4720": "USER_ACCOUNT_CREATED",
    "4728": "GLOBAL_GROUP_MEMBER_ADDED",
    "4732": "LOCAL_GROUP_MEMBER_ADDED",
    "4756": "UNIVERSAL_GROUP_MEMBER_ADDED",
    "4738": "USER_ACCOUNT_CHANGED",
}


def get_value(row, *field_names, default="Unknown"):
    """Return the first available non-empty CSV field."""

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


def parse_windows_privilege_event(row):
    """Parse a supported Windows privilege-related event."""

    event_id = get_value(
        row, "Id", "EventId", "EventID", default=""
    )

    if event_id not in WINDOWS_EVENT_TYPES:
        return None

    event_type = WINDOWS_EVENT_TYPES[event_id]

    actor = get_value(
        row, "SubjectUserName", "ActorUsername"
    )

    target = get_value(
        row, "TargetUserName", "TargetAccount"
    )

    member = get_value(
        row, "MemberName", "Member"
    )

    username = target

    if event_id == "4672":
        username = actor

    elif event_id in ("4728", "4732", "4756"):
        username = member

    return {
        "platform": "Windows",
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": get_value(
            row, "TimeCreated", "Timestamp"
        ),
        "actor": actor,
        "username": username,
        "target_username": target,
        "member": member,
        "group_name": target if event_id in (
            "4728", "4732", "4756"
        ) else "Unknown",
        "source_ip": get_value(
            row, "IpAddress", "SourceNetworkAddress"
        ),
        "logon_id": get_value(
            row, "SubjectLogonId", "TargetLogonId"
        ),
        "privileges": get_value(
            row, "PrivilegeList", "Privileges"
        ),
        "raw": dict(row)
    }


def load_windows_privilege_events(file_path):
    """Load and parse supported Windows privilege events."""

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
            raise ValueError(
                "CSV file has no header row."
            )

        for row in reader:
            if not row or not any(row.values()):
                continue

            event = parse_windows_privilege_event(row)

            if event is None:
                skipped_rows += 1
                continue

            events.append(event)

    return events, skipped_rows