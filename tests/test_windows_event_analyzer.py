import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "01_Windows_Event_Log_Analysis" / "src"

sys.path.insert(0, str(SRC_PATH))

from main import analyze_logs


def create_event(event_id, timestamp, username="megha",
                 ip="192.168.1.100"):
    return {
        "Id": str(event_id),
        "TimeCreated": timestamp.isoformat(),
        "TargetUserName": username,
        "IpAddress": ip,
        "Message": "Synthetic test event"
    }


def create_failed_logins(count, interval_seconds=60):
    start = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)

    return [
        create_event(
            "4625",
            start + timedelta(seconds=i * interval_seconds)
        )
        for i in range(count)
    ]


def test_brute_force_within_ten_minutes():
    events = create_failed_logins(5, 60)

    results = analyze_logs(events)

    alerts = [
        alert for alert in results["alerts"]
        if alert["type"] == "Possible Brute Force"
    ]

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["attempts"] == 5


def test_failures_spread_over_ten_minutes():
    events = create_failed_logins(5, 180)

    results = analyze_logs(events)

    alerts = [
        alert for alert in results["alerts"]
        if alert["type"] == "Possible Brute Force"
    ]

    assert len(alerts) == 0


def test_successful_login_after_repeated_failures():
    events = create_failed_logins(5, 60)

    success_time = datetime(
        2026, 11, 23, 10, 6, tzinfo=timezone.utc
    )

    events.append(create_event("4624", success_time))

    results = analyze_logs(events)

    alerts = [
        alert for alert in results["alerts"]
        if alert["type"] ==
        "Successful Login After Repeated Failures"
    ]

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"


def test_explicit_credentials_are_reported():
    timestamp = datetime(
        2026, 11, 23, 10, 0, tzinfo=timezone.utc
    )

    events = [create_event("4648", timestamp)]

    results = analyze_logs(events)

    alerts = [
        alert for alert in results["alerts"]
        if alert["type"] == "Explicit Credential Usage Observed"
    ]

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "LOW"


def test_special_privileges_are_informational():
    timestamp = datetime(
        2026, 11, 23, 10, 0, tzinfo=timezone.utc
    )

    events = [create_event("4672", timestamp)]

    results = analyze_logs(events)

    alerts = [
        alert for alert in results["alerts"]
        if alert["type"] == "Special Privileges Assigned"
    ]

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "INFO"


def test_empty_dataset():
    results = analyze_logs([])

    assert results["total_events"] == 0
    assert results["failed_logins"] == 0
    assert results["successful_logins"] == 0
    assert results["alerts"] == []


def test_missing_and_invalid_timestamps():
    events = [
        {
            "Id": "4625",
            "TimeCreated": "",
            "TargetUserName": "megha",
            "IpAddress": "192.168.1.100"
        },
        {
            "Id": "4625",
            "TimeCreated": "invalid-date",
            "TargetUserName": "megha",
            "IpAddress": "192.168.1.100"
        },
        *create_failed_logins(5, 60)
    ]

    results = analyze_logs(events)

    alerts = [
        a for a in results["alerts"]
        if a["type"] == "Possible Brute Force"
    ]

    assert len(alerts) == 1
    assert alerts[0]["attempts"] == 5


def test_multiple_separate_brute_force_bursts():
    first = create_failed_logins(5, 60)

    start = datetime(2026, 11, 23, 10, 30, tzinfo=timezone.utc)

    second = [
        create_event("4625", start + timedelta(seconds=i * 60))
        for i in range(5)
    ]

    results = analyze_logs(first + second)

    alerts = [
        a for a in results["alerts"]
        if a["type"] == "Possible Brute Force"
    ]

    assert len(alerts) == 2


def test_brute_force_from_different_ips():
    first = create_failed_logins(5, 60)

    second = [
        create_event(
            "4625",
            datetime(2026, 11, 23, 11, 0, tzinfo=timezone.utc)
            + timedelta(seconds=i * 60),
            username="admin",
            ip="192.168.1.200"
        )
        for i in range(5)
    ]

    results = analyze_logs(first + second)

    alerts = [
        a for a in results["alerts"]
        if a["type"] == "Possible Brute Force"
    ]

    assert len(alerts) == 2


def test_naive_and_timezone_aware_timestamps():
    events = create_failed_logins(4, 60)

    events.append({
        "Id": "4625",
        "TimeCreated": "2026-11-23T10:04:00",
        "TargetUserName": "megha",
        "IpAddress": "192.168.1.100"
    })

    results = analyze_logs(events)

    alerts = [
        a for a in results["alerts"]
        if a["type"] == "Possible Brute Force"
    ]

    assert len(alerts) == 1
    assert alerts[0]["attempts"] == 5
