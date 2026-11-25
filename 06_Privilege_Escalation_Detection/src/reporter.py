import csv
import json
from pathlib import Path


def export_json_report(result, output_dir):
    """Export the complete analysis result as JSON."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report_file = output_path / "privilege_analysis_report.json"

    with report_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            result,
            file,
            indent=4,
            ensure_ascii=False
        )

    return report_file


def export_csv_report(result, output_dir):
    """Export analyzed privilege events as CSV."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report_file = output_path / "privilege_events_report.csv"

    fields = [
        "platform",
        "timestamp",
        "hostname",
        "event_id",
        "event_type",
        "risk_level",
        "classification",
        "actor",
        "username",
        "target_username",
        "group_name",
        "command",
        "source_ip",
        "description",
        "details"
    ]

    with report_file.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()

        for event in result.get("events", []):
            writer.writerow(event)

    return report_file