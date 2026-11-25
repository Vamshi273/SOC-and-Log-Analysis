from importlib import import_module
from pathlib import Path

analyzer_module = import_module(
    "06_Privilege_Escalation_Detection.src.analyzer"
)

analyze_privilege_events = analyzer_module.analyze_privilege_events

BASE_DIR = Path("06_Privilege_Escalation_Detection")
WINDOWS_LOG = BASE_DIR / "sample_logs" / "windows_privilege_events.csv"
LINUX_LOG = BASE_DIR / "sample_logs" / "linux_privilege.log"


def get_result():
    return analyze_privilege_events(
        windows_file=WINDOWS_LOG,
        linux_file=LINUX_LOG,
        year=2026
    )


def test_analyzer_total_event_count():
    result = get_result()

    assert result["summary"]["total_events"] == 13
    assert len(result["events"]) == 13


def test_analyzer_platform_breakdown():
    result = get_result()

    assert result["summary"]["platforms"]["Windows"] == 6
    assert result["summary"]["platforms"]["Linux"] == 7


def test_analyzer_event_types():
    result = get_result()

    event_types = result["summary"]["event_types"]

    assert event_types["SUDO_COMMAND_EXECUTED"] == 2
    assert event_types["PRIVILEGED_ACCOUNT_MODIFICATION"] == 3


def test_analyzer_risk_summary():
    result = get_result()

    risk_levels = result["summary"]["risk_levels"]

    assert risk_levels["MEDIUM"] == 5
    assert risk_levels["HIGH"] == 8


def test_analyzer_skipped_records():
    result = get_result()

    skipped = result["summary"]["skipped_events"]

    assert skipped["windows"] == 1
    assert skipped["linux"] == 2


def test_analyzer_events_are_chronological():
    result = get_result()

    timestamps = [
        event["timestamp"]
        for event in result["events"]
    ]

    assert timestamps == sorted(timestamps)


def test_analyzer_privileged_group_changes():
    result = get_result()

    assert result["summary"]["privileged_group_changes"] == 3


def test_analyzer_missing_file():
    missing_file = BASE_DIR / "sample_logs" / "missing.csv"

    try:
        analyze_privilege_events(windows_file=missing_file)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError")