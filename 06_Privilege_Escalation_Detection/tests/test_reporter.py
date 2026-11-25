import csv
import json
from importlib import import_module
from pathlib import Path

reporter_module = import_module(
    "06_Privilege_Escalation_Detection.src.reporter"
)

export_json_report = reporter_module.export_json_report
export_csv_report = reporter_module.export_csv_report

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


def test_json_report_creation(tmp_path):
    result = get_result()

    output_file = export_json_report(result, tmp_path)

    assert output_file.exists()

    with output_file.open("r", encoding="utf-8") as file:
        data = json.load(file)

    assert data["summary"]["total_events"] == 13


def test_csv_report_creation(tmp_path):
    result = get_result()

    output_file = export_csv_report(result, tmp_path)

    assert output_file.exists()

    with output_file.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 13


def test_json_report_contains_both_platforms(tmp_path):
    result = get_result()

    output_file = export_json_report(result, tmp_path)

    with output_file.open("r", encoding="utf-8") as file:
        data = json.load(file)

    assert data["summary"]["platforms"]["Windows"] == 6
    assert data["summary"]["platforms"]["Linux"] == 7


def test_csv_report_contains_risk_levels(tmp_path):
    result = get_result()

    output_file = export_csv_report(result, tmp_path)

    with output_file.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as file:
        rows = list(csv.DictReader(file))

    risk_levels = {row["risk_level"] for row in rows}

    assert "HIGH" in risk_levels
    assert "MEDIUM" in risk_levels


def test_report_output_directory_creation(tmp_path):
    result = get_result()
    output_dir = tmp_path / "nested" / "reports"

    export_json_report(result, output_dir)
    export_csv_report(result, output_dir)

    assert (output_dir / "privilege_analysis_report.json").exists()
    assert (output_dir / "privilege_events_report.csv").exists()