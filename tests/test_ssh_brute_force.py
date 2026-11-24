import importlib.util
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DETECTOR_PATH = (
    PROJECT_ROOT
    / "03_SSH_Brute_Force_Detection"
    / "src"
    / "detector.py"
)

# Load Module 03 detector independently to avoid collision
# with Module 02's detector.py.
spec = importlib.util.spec_from_file_location(
    "ssh_brute_force_detector",
    DETECTOR_PATH
)

detector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(detector_module)

detect_ssh_attacks = detector_module.detect_ssh_attacks


def make_event(
    minute,
    second,
    event_type="SSH_LOGIN_FAILURE",
    username="shiva",
    source_ip="203.0.113.50"
):
    return {
        "timestamp": f"2026-11-24T09:{minute:02d}:{second:02d}",
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "hostname": "test-server"
    }


def test_detect_repeated_ssh_failures():
    events = [
        make_event(0, 5),
        make_event(1, 5),
        make_event(2, 5),
        make_event(3, 5),
        make_event(4, 5),
    ]

    result = detect_ssh_attacks(events)

    assert result["failed_attempts"] == 5
    assert result["total_alerts"] >= 1
    assert any(
        alert["rule"] == "SSH_BRUTE_FORCE"
        for alert in result["alerts"]
    )


def test_detect_multi_account_brute_force():
    usernames = ["admin", "root", "guest", "test", "oracle"]

    events = [
        make_event(
            minute=index,
            second=10,
            username=username
        )
        for index, username in enumerate(usernames)
    ]

    result = detect_ssh_attacks(events)

    assert any(
        alert["rule"] == "SSH_MULTI_ACCOUNT_BRUTE_FORCE"
        for alert in result["alerts"]
    )


def test_detect_distributed_brute_force():
    source_ips = [
        "192.0.2.10",
        "192.0.2.11",
        "192.0.2.12",
        "192.0.2.10",
        "192.0.2.11",
    ]

    events = [
        make_event(
            minute=index,
            second=20,
            username="deploy",
            source_ip=source_ip
        )
        for index, source_ip in enumerate(source_ips)
    ]

    result = detect_ssh_attacks(events)

    assert any(
        alert["rule"] == "SSH_DISTRIBUTED_BRUTE_FORCE"
        for alert in result["alerts"]
    )


def test_detect_success_after_brute_force():
    events = [
        make_event(minute=0, second=5),
        make_event(minute=1, second=5),
        make_event(minute=2, second=5),
        make_event(minute=3, second=5),
        make_event(minute=4, second=5),
        make_event(
            minute=4,
            second=30,
            event_type="SSH_LOGIN_SUCCESS"
        ),
    ]

    result = detect_ssh_attacks(events)

    assert any(
        alert["rule"] == "SSH_SUCCESS_AFTER_BRUTE_FORCE"
        and alert["severity"] == "CRITICAL"
        for alert in result["alerts"]
    )


def test_no_alert_below_threshold():
    events = [
        make_event(0, 5),
        make_event(1, 5),
        make_event(2, 5),
    ]

    result = detect_ssh_attacks(events)

    assert result["total_alerts"] == 0


def test_custom_detection_threshold():
    events = [
        make_event(0, 5),
        make_event(1, 5),
        make_event(2, 5),
    ]

    result = detect_ssh_attacks(events, threshold=3)

    assert result["total_alerts"] >= 1


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError):
        detect_ssh_attacks([], threshold=0)
