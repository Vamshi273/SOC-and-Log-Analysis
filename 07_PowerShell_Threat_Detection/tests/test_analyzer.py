from importlib import import_module
from pathlib import Path


analyzer_module = import_module(
    "07_PowerShell_Threat_Detection.src.analyzer"
)

analyze_log_file = analyzer_module.analyze_log_file


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SAMPLE_LOG = (
    PROJECT_ROOT
    / "07_PowerShell_Threat_Detection"
    / "sample_logs"
    / "powershell_events.log"
)


def test_analyze_sample_log():
    results = analyze_log_file(SAMPLE_LOG)

    assert results["summary"]["total_events"] == 12
    assert results["summary"]["skipped_events"] == 0


def test_analyzer_finds_suspicious_events():
    results = analyze_log_file(SAMPLE_LOG)

    assert results["summary"]["suspicious_events"] > 0


def test_analyzer_finds_normal_events():
    results = analyze_log_file(SAMPLE_LOG)

    assert results["summary"]["normal_events"] > 0


def test_analyzer_generates_alert_counts():
    results = analyze_log_file(SAMPLE_LOG)

    assert results["summary"]["total_alerts"] > 0
    assert results["summary"]["detection_rule_counts"]


def test_analyzer_returns_all_event_records():
    results = analyze_log_file(SAMPLE_LOG)

    assert len(results["events"]) == 12


def test_analyzer_severity_distribution():
    results = analyze_log_file(SAMPLE_LOG)

    severity = results["summary"]["severity_levels"]

    assert sum(severity.values()) == 12
    assert set(severity) == {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }