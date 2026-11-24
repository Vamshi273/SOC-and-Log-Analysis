import csv
import json
from pathlib import Path
from datetime import datetime, timezone


def build_report(events, analysis):
    """Build a complete, JSON-serializable analysis report."""

    return {
        "report_metadata": {
            "module": "Linux Authentication Log Analysis",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": "Linux authentication log"
        },
        "summary": {
            "total_events": analysis["total_events"],
            "event_counts": dict(analysis["event_counts"]),
            "total_alerts": len(analysis["alerts"])
        },
        "account_activity": dict(analysis["account_activity"]),
        "source_ip_activity": dict(analysis["source_ip_activity"]),
        "alerts": analysis["alerts"],
        "events": events
    }


def save_json_report(report, output_dir):
    """Export the complete report as JSON."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    file_path = output_path / "linux_auth_report.json"

    with file_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return file_path


def save_events_csv(events, output_dir):
    """Export parsed authentication events as CSV."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    file_path = output_path / "authentication_events.csv"

    if not events:
        fieldnames = [
            "timestamp", "hostname", "process", "event_type",
            "status", "username", "source_ip", "method",
            "details", "raw"
        ]
    else:
        fieldnames = list(events[0].keys())

    with file_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

    return file_path


def save_alerts_csv(alerts, output_dir):
    """Export security alerts as CSV."""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    file_path = output_path / "security_alerts.csv"

    fieldnames = [
        "severity",
        "alert_type",
        "username",
        "source_ip",
        "timestamp",
        "description"
    ]

    with file_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)

    return file_path


def export_reports(events, analysis, output_dir):
    """Generate all report formats."""

    report = build_report(events, analysis)

    return [
        save_json_report(report, output_dir),
        save_events_csv(events, output_dir),
        save_alerts_csv(analysis["alerts"], output_dir)
    ]
