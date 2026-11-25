import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from classifier import (
    classify_windows_failure,
    classify_linux_failure,
    classify_failure,
)


def test_windows_incorrect_password():
    event = {
        "status": "0xC000006D",
        "sub_status": "0xC000006A"
    }

    result = classify_windows_failure(event)

    assert result["failure_category"] == "INCORRECT_PASSWORD"
    assert result["evidence_code"] == "0XC000006A"


def test_windows_unknown_username():
    event = {
        "status": "0xC000006D",
        "sub_status": "0xC0000064"
    }

    result = classify_windows_failure(event)

    assert result["failure_category"] == "UNKNOWN_USERNAME"


def test_windows_account_locked():
    event = {
        "status": "0xC0000234",
        "sub_status": "0x0"
    }

    result = classify_windows_failure(event)

    assert result["failure_category"] == "ACCOUNT_LOCKED"


def test_windows_unknown_status():
    event = {
        "status": "0xDEADBEEF",
        "sub_status": "0x00000000"
    }

    result = classify_windows_failure(event)

    assert result["failure_category"] == "UNKNOWN"


def test_windows_missing_status():
    result = classify_windows_failure({})

    assert result["failure_category"] == "UNKNOWN"
    assert result["evidence_code"] == "Unavailable"


def test_linux_incorrect_password():
    event = {
        "platform": "Linux",
        "failure_type": "INCORRECT_PASSWORD"
    }

    result = classify_linux_failure(event)

    assert result["failure_category"] == "INCORRECT_PASSWORD"


def test_linux_unknown_username():
    event = {
        "platform": "Linux",
        "failure_type": "UNKNOWN_USERNAME"
    }

    result = classify_linux_failure(event)

    assert result["failure_category"] == "UNKNOWN_USERNAME"


def test_linux_pam_failure():
    event = {
        "platform": "Linux",
        "failure_type": "PAM_FAILURE"
    }

    result = classify_linux_failure(event)

    assert result["failure_category"] == "PAM_AUTHENTICATION_FAILURE"
    assert "exact cause is not established" in result["description"]


def test_linux_unknown_failure():
    event = {
        "platform": "Linux",
        "failure_type": "SOMETHING_ELSE"
    }

    result = classify_linux_failure(event)

    assert result["failure_category"] == "UNKNOWN"


def test_cross_platform_windows():
    event = {
        "platform": "Windows",
        "status": "0xC0000064",
        "sub_status": "0x0"
    }

    result = classify_failure(event)

    assert result["failure_category"] == "UNKNOWN_USERNAME"


def test_cross_platform_linux():
    event = {
        "platform": "Linux",
        "failure_type": "PAM_FAILURE"
    }

    result = classify_failure(event)

    assert result["failure_category"] == "PAM_AUTHENTICATION_FAILURE"


def test_unsupported_platform():
    event = {
        "platform": "macOS"
    }

    result = classify_failure(event)

    assert result["failure_category"] == "UNKNOWN"