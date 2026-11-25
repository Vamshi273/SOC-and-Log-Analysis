import csv
import json
from pathlib import Path


def export_json(alerts, output_file):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    return output_path


def export_csv(alerts, output_file):
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "ip",
        "attack",
        "severity",
        "url",
        "mitre_attack",
        "event_count",
        "evidence",
    ]

    with output_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()

        for alert in alerts:
            row = alert.copy()

            if isinstance(row.get("evidence"), list):
                row["evidence"] = " | ".join(row["evidence"])

            writer.writerow(row)

    return output_path
