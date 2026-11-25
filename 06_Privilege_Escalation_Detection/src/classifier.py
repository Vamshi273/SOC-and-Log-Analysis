WINDOWS_CLASSIFICATIONS = {
    "SPECIAL_PRIVILEGES_ASSIGNED": (
        "MEDIUM",
        "Special privileges were assigned to a logon. "
        "Verify whether the account and logon activity are authorized."
    ),
    "USER_ACCOUNT_CREATED": (
        "MEDIUM",
        "A Windows user account was created. "
        "Verify the account owner and creation request."
    ),
    "GLOBAL_GROUP_MEMBER_ADDED": (
        "HIGH",
        "A member was added to a global security group. "
        "Investigate whether this grants elevated permissions."
    ),
    "LOCAL_GROUP_MEMBER_ADDED": (
        "HIGH",
        "A member was added to a local security group. "
        "Check whether the group grants administrator privileges."
    ),
    "UNIVERSAL_GROUP_MEMBER_ADDED": (
        "HIGH",
        "A member was added to a universal security group. "
        "Verify the permission impact."
    ),
    "USER_ACCOUNT_CHANGED": (
        "MEDIUM",
        "A Windows user account was modified. "
        "Review the changed account attributes."
    )
}


LINUX_CLASSIFICATIONS = {
    "SUDO_COMMAND_EXECUTED": (
        "MEDIUM",
        "A sudo command was executed. "
        "Review the actor, target account and command."
    ),
    "SUDO_ROOT_SESSION_OPENED": (
        "HIGH",
        "A privileged root session was opened through sudo. "
        "Verify whether the access was authorized."
    ),
    "SUDO_SESSION_OPENED": (
        "MEDIUM",
        "A sudo session was opened for another account. "
        "Review the target account and authorization."
    ),
    "SU_ROOT_SESSION_OPENED": (
        "HIGH",
        "A root session was opened through su. "
        "Investigate the initiating account."
    ),
    "PRIVILEGED_ACCOUNT_MODIFICATION": (
        "HIGH",
        "A privileged account or group management command "
        "was observed. Verify the change and its authorization."
    )
}


def classify_privilege_event(event):
    """Classify a privilege-related event using its event type."""

    platform = str(
        event.get("platform", "")
    ).strip().lower()

    event_type = str(
        event.get("event_type", "UNKNOWN")
    ).strip().upper()

    if platform == "windows":
        classification = WINDOWS_CLASSIFICATIONS.get(
            event_type
        )

    elif platform == "linux":
        classification = LINUX_CLASSIFICATIONS.get(
            event_type
        )

    else:
        classification = None

    if classification is None:
        return {
            "risk_level": "LOW",
            "classification": "UNKNOWN",
            "description": (
                "The available event information does not "
                "match a supported privilege activity."
            )
        }

    risk_level, description = classification

    return {
        "risk_level": risk_level,
        "classification": event_type,
        "description": description
    }