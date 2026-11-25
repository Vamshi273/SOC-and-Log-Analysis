from importlib import import_module

classifier_module = import_module(
    "06_Privilege_Escalation_Detection.src.classifier"
)

classify_privilege_event = classifier_module.classify_privilege_event


def test_windows_special_privileges_medium_risk():
    event = {
        "platform": "Windows",
        "event_id": "4672",
        "event_type": "SPECIAL_PRIVILEGES_ASSIGNED"
    }

    result = classify_privilege_event(event)

    assert result["risk_level"] == "MEDIUM"


def test_windows_user_account_creation_medium_risk():
    event = {
        "platform": "Windows",
        "event_id": "4720",
        "event_type": "USER_ACCOUNT_CREATED"
    }

    result = classify_privilege_event(event)

    assert result["risk_level"] == "MEDIUM"


def test_windows_admin_group_change_high_risk():
    event = {
        "platform": "Windows",
        "event_id": "4732",
        "event_type": "LOCAL_GROUP_MEMBER_ADDED"
    }

    result = classify_privilege_event(event)

    assert result["risk_level"] == "HIGH"


def test_windows_domain_group_change_high_risk():
    event = {
        "platform": "Windows",
        "event_id": "4728",
        "event_type": "GLOBAL_GROUP_MEMBER_ADDED"
    }

    result = classify_privilege_event(event)

    assert result["risk_level"] == "HIGH"


def test_linux_sudo_command_medium_risk():
    event = {
        "platform": "Linux",
        "event_type": "SUDO_COMMAND_EXECUTED"
    }

    result = classify_privilege_event(event)

    assert result["risk_level"] == "MEDIUM"


def test_linux_sudo_root_session_high_risk():
    event = {
        "platform": "Linux",
        "event_type": "SUDO_ROOT_SESSION_OPENED"
    }

    result = classify_privilege_event(event)

    assert result["risk_level"] == "HIGH"


def test_linux_su_root_session_high_risk():
    event = {
        "platform": "Linux",
        "event_type": "SU_ROOT_SESSION_OPENED"
    }

    result = classify_privilege_event(event)

    assert result["risk_level"] == "HIGH"


def test_linux_account_modification_high_risk():
    event = {
        "platform": "Linux",
        "event_type": "PRIVILEGED_ACCOUNT_MODIFICATION"
    }

    result = classify_privilege_event(event)

    assert result["risk_level"] == "HIGH"


def test_unknown_event_defaults_to_low_risk():
    event = {
        "platform": "Unknown",
        "event_type": "UNKNOWN_EVENT"
    }

    result = classify_privilege_event(event)

    assert result["risk_level"] == "LOW"