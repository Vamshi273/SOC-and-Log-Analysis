from datetime import datetime, timezone
from pathlib import Path


EXPECTED_FIELDS = 8

SUPPORTED_EVENT_IDS = {400, 403, 4103, 4104, 4688}


def parse_timestamp(value):
    """Parse an ISO 8601 timestamp and normalize it to UTC."""
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return timestamp.astimezone(timezone.utc).isoformat()


def parse_record(line, line_number=1):
    """Parse one pipe-delimited PowerShell event record."""
    parts = line.strip().split("|")

    if len(parts) != EXPECTED_FIELDS:
        raise ValueError(
            f"Line {line_number}: expected {EXPECTED_FIELDS} fields, "
            f"received {len(parts)}"
        )

    timestamp, event_id, computer, user, process_id, process, host_app, script = parts

    try:
        event_id = int(event_id)
        process_id = int(process_id)
    except ValueError as exc:
        raise ValueError(
            f"Line {line_number}: Event ID and Process ID must be integers"
        ) from exc

    if event_id not in SUPPORTED_EVENT_IDS:
        raise ValueError(
            f"Line {line_number}: unsupported Event ID {event_id}"
        )

    if process_id < 0:
        raise ValueError(
            f"Line {line_number}: Process ID cannot be negative"
        )

    if not computer.strip() or not user.strip() or not process.strip():
        raise ValueError(
            f"Line {line_number}: Computer, User and Process are required"
        )

    return {
        "timestamp": parse_timestamp(timestamp),
        "event_id": event_id,
        "computer": computer.strip(),
        "user": user.strip(),
        "process_id": process_id,
        "process": process.strip(),
        "host_application": host_app.strip(),
        "script_block": script.strip(),
    }


def parse_log_file(file_path):
    """Parse a PowerShell event log and return valid events and errors."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    events = []
    errors = []

    with path.open("r", encoding="utf-8-sig") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            if not line.strip():
                continue

            try:
                events.append(parse_record(line, line_number))
            except ValueError as exc:
                errors.append({
                    "line_number": line_number,
                    "error": str(exc),
                    "raw_record": line.rstrip("\r\n"),
                })

    return events, errors
