import pytest
from pathlib import Path
from importlib import import_module

windows_parser = import_module(
    "06_Privilege_Escalation_Detection.src.windows_parser"
)

parse_windows_privilege_event = windows_parser.parse_windows_privilege_event
load_windows_privilege_events = windows_parser.load_windows_privilege_events


def test_parse_special_privileges_assigned():
    row = {
        "Id": "4672",
        "SubjectUserName": "Administrator",
        "TargetUserName": "Administrator",
        "PrivilegeList": "SeBackupPrivilege"
    }

    event = parse_windows_privilege_event(row)

    assert event is not None
    assert event["event_type"] == "SPECIAL_PRIVILEGES_ASSIGNED"
    assert event["actor"] == "Administrator"


def test_parse_user_account_created():
    row = {
        "Id": "4720",
        "SubjectUserName": "admin01",
        "TargetUserName": "newuser01"
    }

    event = parse_windows_privilege_event(row)

    assert event["event_type"] == "USER_ACCOUNT_CREATED"
    assert event["actor"] == "admin01"
    assert event["username"] == "newuser01"


def test_parse_local_group_member_added():
    row = {
        "Id": "4732",
        "SubjectUserName": "admin01",
        "TargetUserName": "Administrators",
        "MemberName": "testuser"
    }

    event = parse_windows_privilege_event(row)

    assert event["event_type"] == "LOCAL_GROUP_MEMBER_ADDED"
    assert event["group_name"] == "Administrators"
    assert event["username"] == "testuser"


def test_parse_global_group_member_added():
    row = {
        "Id": "4728",
        "SubjectUserName": "domainadmin",
        "TargetUserName": "Domain Admins",
        "MemberName": "testuser"
    }

    event = parse_windows_privilege_event(row)

    assert event["event_type"] == "GLOBAL_GROUP_MEMBER_ADDED"
    assert event["group_name"] == "Domain Admins"


def test_parse_universal_group_member_added():
    row = {
        "Id": "4756",
        "SubjectUserName": "domainadmin",
        "TargetUserName": "Enterprise Admins",
        "MemberName": "testuser"
    }

    event = parse_windows_privilege_event(row)

    assert event["event_type"] == "UNIVERSAL_GROUP_MEMBER_ADDED"
    assert event["username"] == "testuser"


def test_parse_user_account_changed():
    row = {
        "Id": "4738",
        "SubjectUserName": "admin01",
        "TargetUserName": "testuser"
    }

    event = parse_windows_privilege_event(row)

    assert event["event_type"] == "USER_ACCOUNT_CHANGED"


def test_ignore_unsupported_event():
    row = {
        "Id": "4624",
        "SubjectUserName": "Administrator"
    }

    assert parse_windows_privilege_event(row) is None


def test_missing_event_file():
    with pytest.raises(FileNotFoundError):
        load_windows_privilege_events(
            Path("missing_windows_events.csv")
        )