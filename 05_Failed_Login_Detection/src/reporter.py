import csv
import json
from pathlib import Path
from datetime import datetime, timezone


def generate_json_report(analysis, output_dir):
    """Generate a JSON failed-login investigation report."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    report = {
        "report_title": "Failed Login Investigation Report",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        **analysis
    }

    file_path = output_path / "failed_login_report.json"

    with file_path.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return file_path


def generate_csv_report(analysis, output_dir):
    """Generate a CSV report containing classified failed logins."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    file_path = output_path / "failed_login_events.csv"

    fieldnames = [
        "platform",
        "timestamp",
        "username",
        "source_ip",
        "failure_category",
        "failure_description",
        "evidence_code",
        "event_id",
        "status",
        "sub_status",
        "failure_type",
        "details"
    ]

    with file_path.open(
        "w",
        encoding="utf-8-sig",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore"
        )

        writer.writeheader()

        for event in analysis.get("events", []):
            writer.writerow({
                field: event.get(field, "")
                for field in fieldnames
            })

    return file_path


def generate_reports(analysis, output_dir):
    """Generate all supported investigation reports."""

    json_path = generate_json_report(
        analysis,
        output_dir
    )

    csv_path = generate_csv_report(
        analysis,
        output_dir
    )

    return {
        "json": json_path,
        "csv": csv_path
    }