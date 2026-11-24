import re
from datetime import datetime
from pathlib import Path


MONTHS = (
    "Jan", "Feb", "Mar", "Apr",
    "May", "Jun", "Jul", "Aug",
    "Sep", "Oct", "Nov", "Dec"
)

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^:]+):\s*"
    r"(?P<message>.*)$"
)

SSH_PATTERN = re.compile(
    r"^(?P<action>Accepted|Failed)\s+"
    r"(?P<method>\S+)\s+"
    r"for\s+(?P<account>.*?)\s+"
    r"from\s+(?P<ip>\S+)\s+"
    r"port\s+(?P<port>\d+)"
)

INVALID_USER_PATTERN = re.compile(
    r"^Invalid user\s+(?P<account>\S+)\s+"
    r"from\s+(?P<ip>\S+)"
)

SUDO_PATTERN = re.compile(
    r"^(?P<account>\S+)\s*:\s+"
    r"TTY=(?P<tty>[^;]+)\s*;\s*"
    r"PWD=(?P<pwd>[^;]+)\s*;\s*"
    r"USER=(?P<target>\S+)\s*;\s*"
    r"COMMAND=(?P<command>.*)$"
)

PAM_SESSION_PATTERN = re.compile(
    r"session\s+(?P<action>opened|closed)\s+"
    r"for\s+user\s+(?P<account>[^\s(]+)"
)


def parse_auth_line(line, year=None):
    """Parse one Linux syslog authentication entry."""

    year = year or datetime.now().year

    match = SYSLOG_PATTERN.match(line.strip().lstrip("\ufeff"))

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

    process = data["process"]
    message = data["message"]

    event = {
        "timestamp": timestamp.isoformat(),
        "hostname": data["host"],
        "process": process,
        "event_type": "OTHER",
        "status": "INFO",
        "username": "Unknown",
        "source_ip": "Unknown",
        "method": "Unknown",
        "details": message,
        "raw": line.strip()
    }

    ssh_match = SSH_PATTERN.search(message)

    if ssh_match:
        ssh = ssh_match.groupdict()

        account = ssh["account"]

        invalid_user = account.startswith("invalid user ")

        if invalid_user:
            account = account.replace("invalid user ", "", 1)

        event.update({
            "event_type": (
                "SSH_LOGIN_SUCCESS"
                if ssh["action"] == "Accepted"
                else "SSH_LOGIN_FAILURE"
            ),
            "status": (
                "SUCCESS"
                if ssh["action"] == "Accepted"
                else "FAILURE"
            ),
            "username": account,
            "source_ip": ssh["ip"],
            "method": ssh["method"]
        })

        if invalid_user:
            event["event_type"] = "SSH_INVALID_USER"
            event["status"] = "SUSPICIOUS"

        if account == "root" and ssh["action"] == "Accepted":
            event["event_type"] = "SSH_ROOT_LOGIN"
            event["status"] = "REVIEW"

        return event

    invalid_match = INVALID_USER_PATTERN.search(message)

    if invalid_match:
        event.update({
            "event_type": "SSH_INVALID_USER",
            "status": "SUSPICIOUS",
            "username": invalid_match.group("account"),
            "source_ip": invalid_match.group("ip")
        })

        return event

    sudo_match = SUDO_PATTERN.search(message)

    if sudo_match:
        sudo = sudo_match.groupdict()

        event.update({
            "event_type": "SUDO_COMMAND",
            "status": "PRIVILEGED_ACTIVITY",
            "username": sudo["account"],
            "details": (
                f"Target={sudo['target']}; "
                f"Command={sudo['command']}; "
                f"PWD={sudo['pwd']}"
            )
        })

        return event

    pam_match = PAM_SESSION_PATTERN.search(message)

    if pam_match:
        event.update({
            "event_type": "PAM_SESSION",
            "status": "INFO",
            "username": pam_match.group("account"),
            "details": message
        })

        return event

    if "authentication failure" in message.lower():
        event.update({
            "event_type": "AUTHENTICATION_FAILURE",
            "status": "FAILURE"
        })

    return event


def load_auth_logs(file_path, year=None):
    """Load and parse Linux authentication logs."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Authentication log not found: {path}"
        )

    events = []
    invalid_lines = 0

    with path.open("r", encoding="utf-8-sig", errors="replace") as file:
        for line in file:

            if not line.strip():
                continue

            event = parse_auth_line(line, year=year)

            if event is None:
                invalid_lines += 1
                continue

            events.append(event)

    return events, invalid_lines

