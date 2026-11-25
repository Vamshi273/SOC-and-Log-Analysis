import csv
import json
from pathlib import Path

from src.reporter import export_json, export_csv


SAMPLE_ALERTS = [
    {
        "ip": "192.0.2.10",
        "attack": "SQL Injection Attempt",
        "severity": "HIGH",
        "url": "/search?q=test",
        "mitre_attack": "T1190",
        "evidence": "union select",
    },
    {
        "ip": "192.0.2.20",
        "attack": "Automated Web Scanner",
        "severity": "MEDIUM",
        "url": "Multiple resources",
        "mitre_attack": "T1595",
        "event_count": 3,
        "evidence": ["sqlmap/1.8", "sqlmap/1.8"],
    },
]


def test_json_report_generation(tmp_path):
    output = tmp_path / "reports" / "alerts.json"

    export_json(SAMPLE_ALERTS, output)

    assert output.exists()

    with output.open(encoding="utf-8") as file:
        data = json.load(file)

    assert len(data) == 2
    assert data[0]["attack"] == "SQL Injection Attempt"


def test_csv_report_generation(tmp_path):
    output = tmp_path / "reports" / "alerts.csv"

    export_csv(SAMPLE_ALERTS, output)

    assert output.exists()

    with output.open(encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 2
    assert rows[0]["severity"] == "HIGH"


def test_csv_list_evidence_conversion(tmp_path):
    output = tmp_path / "alerts.csv"

    export_csv(SAMPLE_ALERTS, output)

    with output.open(encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))

    assert "sqlmap/1.8" in rows[1]["evidence"]


def test_empty_alert_report(tmp_path):
    output = tmp_path / "empty.json"

    export_json([], output)

    with output.open(encoding="utf-8") as file:
        data = json.load(file)

    assert data == []
