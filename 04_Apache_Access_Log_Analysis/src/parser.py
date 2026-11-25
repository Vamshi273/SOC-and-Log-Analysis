import re
from datetime import datetime
from urllib.parse import unquote
from typing import Optional


APACHE_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) '
    r'(?P<identity>\S+) '
    r'(?P<user>\S+) '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"$'
)


def parse_timestamp(value: str) -> datetime:
    return datetime.strptime(
        value,
        "%d/%b/%Y:%H:%M:%S %z"
    )


def parse_log_line(line: str) -> Optional[dict]:
    """
    Parse one Apache Combined Log Format entry.

    Returns a dictionary when parsing succeeds.
    Returns None when the entry is malformed.
    """

    line = line.strip()

    if not line:
        return None

    match = APACHE_LOG_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    try:
        timestamp = parse_timestamp(data["timestamp"])
        status = int(data["status"])

        size = (
            None if data["size"] == "-"
            else int(data["size"])
        )

    except (ValueError, TypeError):
        return None

    raw_url = data["url"]

    return {
        "ip": data["ip"],
        "timestamp": timestamp.isoformat(),
        "method": data["method"],
        "url": raw_url,
        "decoded_url": unquote(raw_url),
        "protocol": data["protocol"],
        "status": status,
        "size": size,
        "referrer": data["referrer"],
        "user_agent": data["user_agent"],
    }


def parse_log_file(file_path: str) -> dict:
    """
    Parse an Apache access log file.

    Returns successfully parsed entries and parsing statistics.
    """

    entries = []
    malformed_lines = 0

    with open(file_path, "r", encoding="utf-8-sig") as file:

        for line in file:

            parsed = parse_log_line(line)

            if parsed is None:
                malformed_lines += 1
                continue

            entries.append(parsed)

    return {
        "entries": entries,
        "total_lines": len(entries) + malformed_lines,
        "parsed_lines": len(entries),
        "malformed_lines": malformed_lines,
    }
