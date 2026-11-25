import pytest
from importlib import import_module

parser_module = import_module(
    "07_PowerShell_Threat_Detection.src.parser"
)

parse_record = parser_module.parse_record
parse_log_file = parser_module.parse_log_file


VALID_RECORD = (
    "2026-11-20T09:10:15Z|4104|WS-ADMIN01|administrator|2480|"
    "powershell.exe|-NoProfile -File C:\\Scripts\\Inventory.ps1|"
    "Get-Process; Get-Service"
)


def test_parse_valid_record():
    event = parse_record(VALID_RECORD)

    assert event["event_id"] == 4104
    assert event["process_id"] == 2480
    assert event["computer"] == "WS-ADMIN01"
    assert event["user"] == "administrator"
    assert event["process"] == "powershell.exe"


def test_parse_timestamp_normalized_to_utc():
    event = parse_record(VALID_RECORD)

    assert event["timestamp"].endswith("+00:00")


def test_reject_invalid_field_count():
    with pytest.raises(ValueError, match="expected 8 fields"):
        parse_record("2026-11-20|4104|WS-ADMIN01")


def test_reject_non_integer_event_id():
    record = VALID_RECORD.replace("|4104|", "|INVALID|")

    with pytest.raises(ValueError, match="must be integers"):
        parse_record(record)


def test_reject_unsupported_event_id():
    record = VALID_RECORD.replace("|4104|", "|9999|")

    with pytest.raises(ValueError, match="unsupported Event ID"):
        parse_record(record)


def test_reject_negative_process_id():
    record = VALID_RECORD.replace("|2480|", "|-1|")

    with pytest.raises(ValueError, match="cannot be negative"):
        parse_record(record)


def test_reject_invalid_timestamp():
    record = VALID_RECORD.replace(
        "2026-11-20T09:10:15Z",
        "invalid-timestamp",
    )

    with pytest.raises(ValueError):
        parse_record(record)


def test_parse_log_file_and_track_invalid_records(tmp_path):
    log_file = tmp_path / "sample.log"

    log_file.write_text(
        VALID_RECORD + "\n" +
        "invalid|record\n",
        encoding="utf-8",
    )

    events, errors = parse_log_file(log_file)

    assert len(events) == 1
    assert len(errors) == 1
    assert errors[0]["line_number"] == 2


def test_missing_log_file():
    with pytest.raises(FileNotFoundError):
        parse_log_file("missing_powershell.log")
