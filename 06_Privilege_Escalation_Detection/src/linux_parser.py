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

SUDO_COMMAND_PATTERN = re.compile(
    r"^(?P<actor>\S+)\s*:\s*.*?"
    r"\bUSER=(?P<target>\S+)\s*;\s*"
    r".*?\bCOMMAND=(?P<command>.+)$"
)

SUDO_SESSION_PATTERN = re.compile(
    r"session opened for user (?P<target>\S+) "
    r"by (?P<actor>\S+)\(uid="
)

SU_SESSION_PATTERN = re.compile(
    r"session opened for user root "
    r"by (?P<actor>\S+)\(uid="
)

ACCOUNT_COMMANDS = {
    "usermod",
    "useradd",
    "groupadd",
    "groupmod",
    "gpasswd"
}


def parse_linux_privilege_event(line, year=None):
    """Parse a Linux privilege-related syslog entry."""

    year = year or datetime.now().year
    raw = line.strip().lstrip("\ufeff")

    match = SYSLOG_PATTERN.match(raw)

    if not match:
        return None

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(
            f"{year} {data['month']} "
            f"{data['day']} {data['time']}",
            "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None

    message = data["message"]
    process = data["process"].strip()
    process_name = re.sub(r"\[\d+\]$", "", process)

    event = {
        "platform": "Linux",
        "timestamp": timestamp.isoformat(),
        "hostname": data["host"],
        "process": process,
        "event_type": "UNKNOWN",
        "actor": "Unknown",
        "username": "Unknown",
        "target_username": "Unknown",
        "command": "Unknown",
        "source_ip": "Unknown",
        "details": message,
        "raw": raw
    }

    # Sudo command execution
    sudo_command = SUDO_COMMAND_PATTERN.search(message)

    if sudo_command and "sudo" in process_name.lower():
        actor = sudo_command.group("actor")
        target = sudo_command.group("target")
        command = sudo_command.group("command").strip()

        event.update({
            "event_type": "SUDO_COMMAND_EXECUTED",
            "actor": actor,
            "username": actor,
            "target_username": target,
            "command": command
        })

        return event

    # Root session opened through su
    su_session = SU_SESSION_PATTERN.search(message)

    if su_session and process_name.lower() == "su":
        actor = su_session.group("actor")

        event.update({
            "event_type": "SU_ROOT_SESSION_OPENED",
            "actor": actor,
            "username": actor,
            "target_username": "root"
        })

        return event

    # Sudo session opened
    sudo_session = SUDO_SESSION_PATTERN.search(message)

    if sudo_session and process_name.lower() == "sudo":
        actor = sudo_session.group("actor")
        target = sudo_session.group("target")

        event.update({
            "event_type": (
                "SUDO_ROOT_SESSION_OPENED"
                if target == "root"
                else "SUDO_SESSION_OPENED"
            ),
            "actor": actor,
            "username": actor,
            "target_username": target
        })

        return event

    # Privileged account or group modification
    if process_name.lower() in ACCOUNT_COMMANDS:
        event.update({
            "event_type": "PRIVILEGED_ACCOUNT_MODIFICATION",
            "command": process_name.lower(),
            "details": message
        })

        return event

    return None


def load_linux_privilege_events(file_path, year=None):
    """Load Linux logs and return privilege-related events."""

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

            event = parse_linux_privilege_event(
                line,
                year=year
            )

            if event is None:
                skipped_lines += 1
                continue

            events.append(event)

    return events, skipped_lines