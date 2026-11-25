from pathlib import Path

from src.parser import parse_log_file
from src.detector import detect_attacks


PROJECT = Path(__file__).resolve().parents[1]
LOG_FILE = PROJECT / "04_Apache_Access_Log_Analysis" / "sample_logs" / "access.log"


def get_alerts():
    data = parse_log_file(str(LOG_FILE))
    return detect_attacks(data["entries"])


def test_sql_injection_detection():
    alerts = get_alerts()
    assert any(a["attack"] == "SQL Injection Attempt" for a in alerts)


def test_xss_detection():
    alerts = get_alerts()
    assert any(a["attack"] == "Cross-Site Scripting (XSS)" for a in alerts)


def test_directory_traversal_detection():
    alerts = get_alerts()
    assert any(a["attack"] == "Directory Traversal" for a in alerts)


def test_automated_scanner_detection():
    alerts = get_alerts()

    scanner_alerts = [
        a for a in alerts
        if a["attack"] == "Automated Web Scanner"
    ]

    assert len(scanner_alerts) == 1
    assert scanner_alerts[0]["event_count"] == 3
    assert scanner_alerts[0]["ip"] == "203.0.113.70"


def test_brute_force_detection():
    alerts = get_alerts()
    assert any(a["attack"] == "Possible Login Brute Force" for a in alerts)


def test_directory_scanning_detection():
    alerts = get_alerts()
    assert any(a["attack"] == "Possible Directory Scanning" for a in alerts)


def test_high_severity_alerts_exist():
    alerts = get_alerts()
    assert any(a["severity"] == "HIGH" for a in alerts)


def test_detection_returns_list():
    assert isinstance(get_alerts(), list)
