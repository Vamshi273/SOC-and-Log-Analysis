import csv
import json
from importlib import import_module


reporter_module = import_module(
    "07_PowerShell_Threat_Detection.src.reporter"
)

generate_json_report = reporter_module.generate_json_report
generate_csv_report = reporter_module.generate_csv_report
generate_reports = reporter_module.generate_reports


SAMPLE_RESULTS = {
    "summary": {
        "total_events": 2,
        "suspicious_events": 1,
        "normal_events": 1,
    },
    "events": [
        {
            "timestamp": "2026-11-20T09:10:15+00:00",
            "computer": "WS-USER01",
            "user": "user01",
            "process_id": 2480,
            "event_id": 4104,
            "severity": "HIGH",
            "is_suspicious": True,
            "script_block": "Encoded PowerShell command",
            "alerts": [
                {
                    "rule_name": "Encoded PowerShell Command",
                    "category": "Obfuscation",
                    "severity": "HIGH",
                    "description": "Encoded command detected.",
                }
            ],
        }
    ],
    "errors": [],
}


def test_generate_json_report(tmp_path):
    report = generate_json_report(SAMPLE_RESULTS, tmp_path)

    assert report.exists()

    with report.open(encoding="utf-8") as file:
        data = json.load(file)

    assert data["summary"]["total_events"] == 2


def test_generate_csv_report(tmp_path):
    report = generate_csv_report(SAMPLE_RESULTS, tmp_path)

    assert report.exists()

    with report.open(encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 1
    assert rows[0]["computer"] == "WS-USER01"
    assert rows[0]["severity"] == "HIGH"


def test_generate_both_reports(tmp_path):
    reports = generate_reports(SAMPLE_RESULTS, tmp_path)

    assert reports["json"].exists()
    assert reports["csv"].exists()


def test_csv_contains_no_rows_for_benign_events(tmp_path):
    benign_results = {
        "events": [
            {
                **SAMPLE_RESULTS["events"][0],
                "alerts": [],
                "is_suspicious": False,
            }
        ]
    }

    report = generate_csv_report(benign_results, tmp_path)

    with report.open(encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))

    assert rows == []