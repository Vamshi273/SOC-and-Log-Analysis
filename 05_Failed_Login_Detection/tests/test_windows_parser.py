import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from windows_parser import parse_windows_event, load_windows_failures


def test_parse_failed_login_event():
    row = {
        "Id": "4625",
        "TimeCreated": "2026-11-25T10:00:00Z",
        "TargetUserName": "admin",
        "TargetDomainName": "WORKGROUP",
        "IpAddress": "192.168.1.50",
        "Workstation": "DESKTOP-01",
        "LogonType": "3",
        "Status": "0xC000006D",
        "SubStatus": "0xC000006A"
    }

    event = parse_windows_event(row)

    assert event["event_id"] == "4625"
    assert event["username"] == "admin"
    assert event["source_ip"] == "192.168.1.50"
    assert event["logon_type"] == "3"
    assert event["status"] == "0xC000006D"
    assert event["sub_status"] == "0xC000006A"


def test_ignore_unrelated_event():
    row = {
        "Id": "4624",
        "TargetUserName": "admin"
    }

    assert parse_windows_event(row) is None


def test_missing_optional_fields():
    row = {
        "Id": "4625",
        "TargetUserName": "guest"
    }

    event = parse_windows_event(row)

    assert event is not None
    assert event["username"] == "guest"
    assert event["source_ip"] == "Unknown"
    assert event["status"] == "Unknown"
    assert event["sub_status"] == "Unknown"


def test_load_windows_csv(tmp_path):
    csv_file = tmp_path / "windows.csv"

    csv_file.write_text(
        "Id,TimeCreated,TargetUserName,IpAddress\n"
        "4625,2026-11-25T10:00:00Z,admin,192.168.1.50\n"
        "4624,2026-11-25T10:01:00Z,admin,192.168.1.50\n"
        "4625,2026-11-25T10:02:00Z,guest,192.168.1.60\n",
        encoding="utf-8"
    )

    events, skipped = load_windows_failures(csv_file)

    assert len(events) == 2
    assert skipped == 1
    assert events[0]["username"] == "admin"
    assert events[1]["username"] == "guest"


def test_missing_csv_file():
    with pytest.raises(FileNotFoundError):
        load_windows_failures("missing_windows_logs.csv")