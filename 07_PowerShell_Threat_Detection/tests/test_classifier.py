from importlib import import_module


classifier_module = import_module(
    "07_PowerShell_Threat_Detection.src.classifier"
)

classify_event = classifier_module.classify_event
calculate_severity_summary = classifier_module.calculate_severity_summary


def test_classify_empty_alerts_as_low():
    assert classify_event([]) == "LOW"


def test_classify_medium_alert():
    alerts = [{"severity": "MEDIUM"}]

    assert classify_event(alerts) == "MEDIUM"


def test_classify_highest_severity():
    alerts = [
        {"severity": "LOW"},
        {"severity": "MEDIUM"},
        {"severity": "CRITICAL"},
        {"severity": "HIGH"},
    ]

    assert classify_event(alerts) == "CRITICAL"


def test_calculate_severity_summary():
    events = [
        {"severity": "LOW"},
        {"severity": "LOW"},
        {"severity": "MEDIUM"},
        {"severity": "HIGH"},
        {"severity": "CRITICAL"},
    ]

    summary = calculate_severity_summary(events)

    assert summary == {
        "LOW": 2,
        "MEDIUM": 1,
        "HIGH": 1,
        "CRITICAL": 1,
    }


def test_empty_severity_summary():
    assert calculate_severity_summary([]) == {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }