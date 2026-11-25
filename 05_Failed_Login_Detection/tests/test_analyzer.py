import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from analyzer import analyze_failures


def sample_events():
    return [
        {
            "platform": "Windows",
            "timestamp": "2026-11-25T10:00:00",
            "username": "admin",
            "source_ip": "192.168.1.10",
            "status": "0xC000006D",
            "sub_status": "0xC000006A"
        },
        {
            "platform": "Linux",
            "timestamp": "2026-11-25T10:01:00",
            "username": "root",
            "source_ip": "192.168.1.20",
            "failure_type": "UNKNOWN_USERNAME"
        },
        {
            "platform": "Linux",
            "timestamp": "2026-11-25T10:02:00",
            "username": "admin",
            "source_ip": "192.168.1.10",
            "failure_type": "PAM_FAILURE"
        }
    ]


def test_total_failure_count():
    result = analyze_failures(sample_events())

    assert result["summary"]["total_failures"] == 3


def test_platform_counts():
    result = analyze_failures(sample_events())

    assert result["summary"]["platform_counts"] == {
        "Windows": 1,
        "Linux": 2
    }


def test_failure_category_counts():
    result = analyze_failures(sample_events())

    assert result["summary"]["category_counts"] == {
        "INCORRECT_PASSWORD": 1,
        "UNKNOWN_USERNAME": 1,
        "PAM_AUTHENTICATION_FAILURE": 1
    }


def test_unique_username_count():
    result = analyze_failures(sample_events())

    assert result["summary"]["unique_usernames"] == 2


def test_unique_source_ip_count():
    result = analyze_failures(sample_events())

    assert result["summary"]["unique_source_ips"] == 2


def test_top_usernames():
    result = analyze_failures(sample_events())

    assert result["top_usernames"][0] == {
        "username": "admin",
        "count": 2
    }


def test_top_source_ips():
    result = analyze_failures(sample_events())

    assert result["top_source_ips"][0] == {
        "source_ip": "192.168.1.10",
        "count": 2
    }


def test_timeline_is_sorted():
    result = analyze_failures(sample_events())

    timestamps = [
        item["timestamp"]
        for item in result["timeline"]
    ]

    assert timestamps == sorted(timestamps)


def test_classified_events_include_reason():
    result = analyze_failures(sample_events())

    event = result["events"][0]

    assert event["failure_category"] == "INCORRECT_PASSWORD"
    assert event["failure_description"]
    assert event["evidence_code"] == "0XC000006A"


def test_empty_events():
    result = analyze_failures([])

    assert result["summary"]["total_failures"] == 0
    assert result["summary"]["platform_counts"] == {}
    assert result["summary"]["category_counts"] == {}
    assert result["top_usernames"] == []
    assert result["top_source_ips"] == []
    assert result["timeline"] == []
    assert result["events"] == []


def test_missing_username_and_ip():
    events = [
        {
            "platform": "Windows",
            "timestamp": "2026-11-25T10:00:00",
            "status": "0xDEADBEEF"
        }
    ]

    result = analyze_failures(events)

    assert result["top_usernames"][0]["username"] == "Unknown"
    assert result["top_source_ips"][0]["source_ip"] == "Unknown"


def test_invalid_entries_are_skipped():
    events = [
        None,
        "invalid event",
        {
            "platform": "Linux",
            "username": "admin",
            "source_ip": "192.168.1.10",
            "failure_type": "INCORRECT_PASSWORD"
        }
    ]

    result = analyze_failures(events)

    assert result["summary"]["total_failures"] == 1