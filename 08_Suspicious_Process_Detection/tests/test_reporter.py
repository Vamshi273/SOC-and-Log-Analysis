import csv
import json

from src.analyzer import analyze_process_logs
from src.reporter import generate_reports


def test_report_generation(tmp_path):
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]

    analysis = analyze_process_logs(
        root / "datasets" / "sample_process_logs.csv",
        root / "config" / "detection_rules.json"
    )

    json_path, csv_path = generate_reports(analysis, tmp_path)

    assert json_path.exists()
    assert csv_path.exists()

    with json_path.open("r", encoding="utf-8") as file:
        report = json.load(file)

    assert report["summary"]["total_records"] == 14
    assert report["summary"]["total_alerts"] == 8

    with csv_path.open("r", encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 8
