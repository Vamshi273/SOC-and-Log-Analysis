import csv
import json
from pathlib import Path
from datetime import datetime, timezone


def generate_reports(analysis, output_dir):
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = output_path / f"process_analysis_{timestamp}.json"
    csv_path = output_path / f"process_alerts_{timestamp}.csv"

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_records": analysis["total_records"],
            "invalid_records": len(analysis["invalid_records"]),
            "total_alerts": analysis["total_alerts"],
            "normal_records": analysis["normal_records"],
            "risk_summary": analysis["risk_summary"],
        },
        "invalid_records": analysis["invalid_records"],
        "results": analysis["results"],
    }

    with json_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    fieldnames = [
        "ProcessId",
        "ProcessName",
        "ParentProcessName",
        "Username",
        "ExecutablePath",
        "RiskScore",
        "RiskLevel",
        "Findings",
        "Status",
    ]

    with csv_path.open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for item in analysis["results"]:
            if item["Status"] == "ALERT":
                row = item.copy()
                row["Findings"] = "; ".join(item["Findings"])
                writer.writerow(row)

    return json_path, csv_path
