WINDOWS_STATUS_CODES = {
    "0XC0000064": (
        "UNKNOWN_USERNAME",
        "The specified username does not exist."
    ),
    "0XC000006A": (
        "INCORRECT_PASSWORD",
        "The password is incorrect."
    ),
    "0XC000006D": (
        "INVALID_CREDENTIALS",
        "The supplied credentials are invalid."
    ),
    "0XC000006E": (
        "ACCOUNT_RESTRICTION",
        "Account restrictions prevented authentication."
    ),
    "0XC000006F": (
        "LOGON_HOURS_RESTRICTION",
        "The user attempted to log on outside permitted hours."
    ),
    "0XC0000070": (
        "WORKSTATION_RESTRICTION",
        "The user is not permitted to log on from this workstation."
    ),
    "0XC0000071": (
        "PASSWORD_EXPIRED",
        "The user's password has expired."
    ),
    "0XC0000072": (
        "ACCOUNT_DISABLED",
        "The user account is disabled."
    ),
    "0XC000015B": (
        "LOGON_TYPE_NOT_GRANTED",
        "The requested logon type is not permitted."
    ),
    "0XC0000234": (
        "ACCOUNT_LOCKED",
        "The user account is locked."
    ),
}


def normalize_code(value):
    """Normalize Windows status codes for consistent comparison."""

    if value is None:
        return ""

    return str(value).strip().upper()


def classify_windows_failure(event):
    """Classify a Windows failed-logon event using status information."""

    status = normalize_code(event.get("status"))
    sub_status = normalize_code(event.get("sub_status"))

    # Substatus often provides a more specific explanation.
    for code in (sub_status, status):
        if code in WINDOWS_STATUS_CODES:
            category, description = WINDOWS_STATUS_CODES[code]

            return {
                "failure_category": category,
                "description": description,
                "evidence_code": code
            }

    return {
        "failure_category": "UNKNOWN",
        "description": "The available Windows status codes do not identify the failure reason.",
        "evidence_code": sub_status or status or "Unavailable"
    }


def classify_linux_failure(event):
    """Normalize a Linux authentication failure classification."""

    failure_type = str(
        event.get("failure_type", "UNKNOWN")
    ).strip().upper()

    categories = {
        "INCORRECT_PASSWORD": (
            "INCORRECT_PASSWORD",
            "The SSH password authentication attempt failed."
        ),
        "UNKNOWN_USERNAME": (
            "UNKNOWN_USERNAME",
            "The requested username was not recognized."
        ),
        "PAM_FAILURE": (
            "PAM_AUTHENTICATION_FAILURE",
            "PAM reported an authentication failure; the exact cause is not established."
        )
    }

    category, description = categories.get(
        failure_type,
        (
            "UNKNOWN",
            "The available Linux log information does not identify the failure reason."
        )
    )

    return {
        "failure_category": category,
        "description": description,
        "evidence_code": failure_type
    }


def classify_failure(event):
    """Classify a failed-login event based on its platform."""

    platform = str(
        event.get("platform", "")
    ).strip().lower()

    if platform == "windows":
        return classify_windows_failure(event)

    if platform == "linux":
        return classify_linux_failure(event)

    return {
        "failure_category": "UNKNOWN",
        "description": "Unsupported or unidentified platform.",
        "evidence_code": "Unavailable"
    }