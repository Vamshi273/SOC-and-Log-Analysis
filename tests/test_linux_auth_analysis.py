import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC = PROJECT_ROOT / "02_Linux_Authentication_Log_Analysis" / "src"

sys.path.insert(0, str(SRC))

from parser import parse_auth_line, load_auth_logs
from detector import analyze_auth_events
from reporter import export_reports


SAMPLE_LOG = (
    "Nov 23 09:00:01 ubuntu-server "
    "sshd[1001]: Accepted password for shiva "
    "from 192.168.1.10 port 51234 ssh2"
)


def test_parse_successful_ssh_login():
    event = parse_auth_line(SAMPLE_LOG, year=2026)

    assert event is not None
    assert event["event_type"] == "SSH_LOGIN_SUCCESS"
    assert event["username"] == "shiva"
    assert event["source_ip"] == "192.168.1.10"


def test_parse_invalid_syslog_line():
    assert parse_auth_line("This is not a valid syslog entry") is None


def test_parse_root_ssh_login():
    line = (
        "Nov 23 09:04:00 ubuntu-server "
        "sshd[1007]: Accepted password for root "
        "from 198.51.100.80 port 41239 ssh2"
    )

    event = parse_auth_line(line, year=2026)

    assert event["event_type"] == "SSH_ROOT_LOGIN"
    assert event["username"] == "root"


def test_parse_pam_username():
    line = (
        "Nov 23 09:08:00 ubuntu-server "
        "sshd[1011]: pam_unix(sshd:session): "
        "session opened for user shiva(uid=1000) by (uid=0)"
    )

    event = parse_auth_line(line, year=2026)

    assert event["event_type"] == "PAM_SESSION"
    assert event["username"] == "shiva"


def test_sample_log_has_no_invalid_lines():
    sample = PROJECT_ROOT / "02_Linux_Authentication_Log_Analysis" / "sample_logs" / "auth.log"

    events, invalid = load_auth_logs(sample, year=2026)

    assert len(events) == 12
    assert invalid == 0


def test_detector_generates_root_login_alert():
    event = parse_auth_line(
        "Nov 23 09:04:00 ubuntu-server "
        "sshd[1007]: Accepted password for root "
        "from 198.51.100.80 port 41239 ssh2",
        year=2026
    )

    result = analyze_auth_events([event])

    assert result["total_events"] == 1
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["severity"] == "HIGH"


def test_report_exports(tmp_path):
    event = parse_auth_line(SAMPLE_LOG, year=2026)
    analysis = analyze_auth_events([event])

    files = export_reports([event], analysis, tmp_path)

    assert len(files) == 3
    assert all(file.exists() for file in files)

    assert (tmp_path / "linux_auth_report.json").stat().st_size > 0
    assert (tmp_path / "authentication_events.csv").stat().st_size > 0
    assert (tmp_path / "security_alerts.csv").stat().st_size > 0
