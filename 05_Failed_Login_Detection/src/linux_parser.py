import re
from datetime import datetime
from pathlib import Path


SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^:]+):\s*"
    r"(?P<message>.*)$"
)

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<ip>\S+)"
)

INVALID_USER_PATTERN = re.compile(
    r"Invalid user (?P<username>\S+) from (?P<ip>\S+)"
)

PAM_PATTERN = re.compile(
    r"pam_.*?:\s*"
    r"(?P<message>authentication failure.*)",
    re.IGNORECASE
)

def parse_linux_failure(line, year=None):
    """Parse a Linux authentication failure log entry."""

    year = year or datetime.now().year
    raw = line.strip().lstrip("\ufeff")

    match = SYSLOG_PATTERN.match(raw)

    if not match:
        return None

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(
            f"{year} {data['month']} {data['day']} {data['time']}",
            "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None

    message = data["message"]

    event = {
        "platform": "Linux",
        "timestamp": timestamp.isoformat(),
        "hostname": data["host"],
        "process": data["process"],
        "event_type": "AUTHENTICATION_FAILURE",
        "failure_type": "UNKNOWN",
        "username": "Unknown",
        "source_ip": "Unknown",
        "details": message,
        "raw": raw
    }

    failed = FAILED_PASSWORD_PATTERN.search(message)

    if failed:
        event.update({
            "event_type": "SSH_LOGIN_FAILURE",
            "failure_type": "INCORRECT_PASSWORD",
            "username": failed.group("username"),
            "source_ip": failed.group("ip")
        })

        return event

    invalid = INVALID_USER_PATTERN.search(message)

    if invalid:
        event.update({
            "event_type": "SSH_INVALID_USER",
            "failure_type": "UNKNOWN_USERNAME",
            "username": invalid.group("username"),
            "source_ip": invalid.group("ip")
        })

        return event

    pam = PAM_PATTERN.search(message)

    if pam:
        event.update({
            "event_type": "PAM_AUTHENTICATION_FAILURE",
            "failure_type": "PAM_FAILURE",
            "details": pam.group("message")
        })

        username_match = re.search(
            r"\buser=(?P<username>\S+)",
            message
        )

        ip_match = re.search(
            r"\brhost=(?P<ip>\S+)",
            message
        )

        if username_match:
            event["username"] = username_match.group("username")

        if ip_match:
            event["source_ip"] = ip_match.group("ip")

        return event

    return None


def load_linux_failures(file_path, year=None):
    """Load Linux authentication logs and parse failure events."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Linux authentication log not found: {path}"
        )

    events = []
    skipped_lines = 0

    with path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace"
    ) as file:

        for line in file:
            if not line.strip():
                continue

            event = parse_linux_failure(line, year=year)

            if event is None:
                skipped_lines += 1
                continue

            events.append(event)

    return events, skipped_lines