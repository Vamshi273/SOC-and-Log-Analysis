import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from linux_parser import parse_linux_failure, load_linux_failures


def test_failed_ssh_password():
    line = (
        "Nov 25 10:00:00 ubuntu sshd[1001]: "
        "Failed password for admin from 192.168.1.50 "
        "port 41000 ssh2"
    )

    event = parse_linux_failure(line, year=2026)

    assert event["event_type"] == "SSH_LOGIN_FAILURE"
    assert event["failure_type"] == "INCORRECT_PASSWORD"
    assert event["username"] == "admin"
    assert event["source_ip"] == "192.168.1.50"


def test_invalid_ssh_username():
    line = (
        "Nov 25 10:01:00 ubuntu sshd[1002]: "
        "Invalid user hacker from 192.168.1.60"
    )

    event = parse_linux_failure(line, year=2026)

    assert event["event_type"] == "SSH_INVALID_USER"
    assert event["failure_type"] == "UNKNOWN_USERNAME"
    assert event["username"] == "hacker"


def test_pam_authentication_failure():
    line = (
        "Nov 25 10:02:00 ubuntu sudo: "
        "pam_unix(sudo:auth): authentication failure; "
        "user=admin rhost=192.168.1.70"
    )

    event = parse_linux_failure(line, year=2026)

    assert event["event_type"] == "PAM_AUTHENTICATION_FAILURE"
    assert event["failure_type"] == "PAM_FAILURE"
    assert event["username"] == "admin"
    assert event["source_ip"] == "192.168.1.70"


def test_ignore_unrelated_log():
    line = (
        "Nov 25 10:03:00 ubuntu sshd[1003]: "
        "Accepted publickey for admin from 192.168.1.50 "
        "port 41001 ssh2"
    )

    assert parse_linux_failure(line, year=2026) is None


def test_invalid_timestamp():
    line = (
        "Feb 31 10:00:00 ubuntu sshd[1004]: "
        "Failed password for admin from 192.168.1.50 "
        "port 41000 ssh2"
    )

    assert parse_linux_failure(line, year=2026) is None


def test_load_linux_failure_logs(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Nov 25 10:00:00 ubuntu sshd[1001]: "
        "Failed password for admin from 192.168.1.50 "
        "port 41000 ssh2\n"
        "Nov 25 10:01:00 ubuntu sshd[1002]: "
        "Accepted publickey for admin from 192.168.1.50 "
        "port 41001 ssh2\n",
        encoding="utf-8"
    )

    events, skipped = load_linux_failures(
        log_file,
        year=2026
    )

    assert len(events) == 1
    assert skipped == 1
    assert events[0]["username"] == "admin"


def test_missing_log_file():
    with pytest.raises(FileNotFoundError):
        load_linux_failures("missing_auth.log")