import csv
import json
from pathlib import Path


def generate_json_report(results, output_directory):
    """Generate a complete JSON analysis report."""
    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)

    report_file = output_path / "powershell_analysis_report.json"

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=4, ensure_ascii=False)

    return report_file


def generate_csv_report(results, output_directory):
    """Generate a CSV report containing detected alerts."""
    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)

    report_file = output_path / "powershell_alerts_report.csv"

    fieldnames = [
        "timestamp",
        "computer",
        "user",
        "process_id",
        "event_id",
        "severity",
        "rule_name",
        "category",
        "description",
        "script_block",
    ]

    with report_file.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for event in results.get("events", []):
            for alert in event.get("alerts", []):
                writer.writerow({
                    "timestamp": event["timestamp"],
                    "computer": event["computer"],
                    "user": event["user"],
                    "process_id": event["process_id"],
                    "event_id": event["event_id"],
                    "severity": event["severity"],
                    "rule_name": alert["rule_name"],
                    "category": alert["category"],
                    "description": alert["description"],
                    "script_block": event["script_block"],
                })

    return report_file


def generate_reports(results, output_directory):
    """Generate both JSON and CSV reports."""
    return {
        "json": generate_json_report(results, output_directory),
        "csv": generate_csv_report(results, output_directory),
    }
