import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def build_report(events, analysis):
    """Build a complete JSON-serializable SSH security report."""

    return {
        "metadata": {
            "module": "SSH Brute-Force Detection",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_version": "1.0"
        },
        "summary": {
            "total_events": analysis["total_events"],
            "failed_attempts": analysis["failed_attempts"],
            "successful_logins": analysis["successful_logins"],
            "total_alerts": analysis["total_alerts"],
            "severity_counts": analysis["severity_counts"]
        },
        "alerts": analysis["alerts"],
        "events": events
    }


def save_json_report(report, output_path):
    """Export the complete report as JSON."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return path


def save_events_csv(events, output_path):
    """Export parsed SSH authentication events as CSV."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "timestamp",
        "hostname",
        "event_type",
        "status",
        "username",
        "source_ip",
        "method",
        "details"
    ]

    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(events)

    return path


def save_alerts_csv(alerts, output_path):
    """Export security alerts as CSV."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "rule",
        "severity",
        "timestamp",
        "source_ips",
        "targeted_usernames",
        "failed_attempts",
        "successful_logins",
        "description"
    ]

    with path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields
        )

        writer.writeheader()

        for alert in alerts:
            row = alert.copy()
            row["source_ips"] = ", ".join(row["source_ips"])
            row["targeted_usernames"] = ", ".join(
                row["targeted_usernames"]
            )
            writer.writerow(row)

    return path


def export_reports(events, analysis, output_directory):
    """Generate all SSH detection reports."""

    output_dir = Path(output_directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    report = build_report(events, analysis)

    json_path = save_json_report(
        report,
        output_dir / "ssh_attack_report.json"
    )

    events_path = save_events_csv(
        events,
        output_dir / "ssh_attack_events.csv"
    )

    alerts_path = save_alerts_csv(
        analysis["alerts"],
        output_dir / "security_alerts.csv"
    )

    return {
        "json": json_path,
        "events_csv": events_path,
        "alerts_csv": alerts_path
    }
