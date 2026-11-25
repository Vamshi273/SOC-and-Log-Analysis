import pytest
from pathlib import Path
from importlib import import_module

linux_parser = import_module(
    "06_Privilege_Escalation_Detection.src.linux_parser"
)

parse_linux_privilege_event = linux_parser.parse_linux_privilege_event
load_linux_privilege_events = linux_parser.load_linux_privilege_events


def test_parse_sudo_command():
    line = (
        "Nov 25 09:00:01 ubuntu-server sudo: alice : "
        "TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"
    )

    event = parse_linux_privilege_event(line, year=2026)

    assert event is not None
    assert event["event_type"] == "SUDO_COMMAND_EXECUTED"
    assert event["actor"] == "alice"
    assert event["target_username"] == "root"
    assert event["command"] == "/usr/bin/id"


def test_parse_sudo_root_session():
    line = (
        "Nov 25 09:02:15 ubuntu-server sudo: "
        "pam_unix(sudo:session): session opened for user root "
        "by alice(uid=1000)"
    )

    event = parse_linux_privilege_event(line, year=2026)

    assert event is not None
    assert event["event_type"] == "SUDO_ROOT_SESSION_OPENED"
    assert event["actor"] == "alice"
    assert event["target_username"] == "root"


def test_parse_su_root_session():
    line = (
        "Nov 25 09:05:20 ubuntu-server su: "
        "pam_unix(su:session): session opened for user root "
        "by bob(uid=1001)"
    )

    event = parse_linux_privilege_event(line, year=2026)

    assert event is not None
    assert event["event_type"] == "SU_ROOT_SESSION_OPENED"
    assert event["actor"] == "bob"
    assert event["target_username"] == "root"


def test_parse_user_account_modification():
    line = (
        "Nov 25 09:12:45 ubuntu-server "
        "usermod[2101]: add 'testuser' to group 'sudo'"
    )

    event = parse_linux_privilege_event(line, year=2026)

    assert event is not None
    assert event["event_type"] == "PRIVILEGED_ACCOUNT_MODIFICATION"


def test_parse_group_creation():
    line = (
        "Nov 25 09:15:00 ubuntu-server "
        "groupadd[2102]: new group: name=securityteam, GID=1003"
    )

    event = parse_linux_privilege_event(line, year=2026)

    assert event is not None
    assert event["event_type"] == "PRIVILEGED_ACCOUNT_MODIFICATION"


def test_ignore_unrelated_ssh_event():
    line = (
        "Nov 25 09:25:00 ubuntu-server sshd[2200]: "
        "Accepted publickey for alice from 192.0.2.10 port 45000 ssh2"
    )

    assert parse_linux_privilege_event(line, year=2026) is None


def test_ignore_invalid_timestamp():
    line = "Invalid timestamp ubuntu-server sudo: alice COMMAND=/usr/bin/id"

    assert parse_linux_privilege_event(line, year=2026) is None


def test_missing_linux_log_file():
    with pytest.raises(FileNotFoundError):
        load_linux_privilege_events(
            Path("missing_linux_privilege.log"),
            year=2026
        )