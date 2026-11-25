import argparse
from pathlib import Path

from src.parser import parse_log_file
from src.detector import detect_attacks
from src.reporter import export_json, export_csv


def main():
    base_dir = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(
        description="Apache Access Log SOC Analyzer"
    )

    parser.add_argument(
        "--log",
        default=str(base_dir / "sample_logs" / "access.log"),
        help="Path to Apache access log file",
    )

    parser.add_argument(
        "--output",
        default=str(base_dir / "reports"),
        help="Directory for generated reports",
    )

    args = parser.parse_args()

    log_file = Path(args.log)
    output_dir = Path(args.output)

    if not log_file.is_file():
        parser.error(f"Log file not found: {log_file}")

    # Parse Apache logs
    data = parse_log_file(str(log_file))

    # Detect suspicious activity
    alerts = detect_attacks(data["entries"])

    # Generate reports
    json_report = export_json(
        alerts,
        output_dir / "security_alerts.json",
    )

    csv_report = export_csv(
        alerts,
        output_dir / "security_alerts.csv",
    )

    # Display analysis summary
    print("\n========== APACHE SOC LOG ANALYZER ==========")
    print(f"Log file:       {log_file}")
    print(f"Total lines:    {data['total_lines']}")
    print(f"Parsed lines:   {data['parsed_lines']}")
    print(f"Malformed:      {data['malformed_lines']}")
    print(f"Total alerts:   {len(alerts)}")

    print("\n========== SECURITY ALERTS ==========")

    if not alerts:
        print("No suspicious activity detected.")
    else:
        for index, alert in enumerate(alerts, start=1):
            print(
                f"\n{index}. [{alert['severity']}] "
                f"{alert['attack']}"
            )
            print(f"   Source IP: {alert['ip']}")
            print(f"   MITRE ATT&CK: {alert['mitre_attack']}")

            if "event_count" in alert:
                print(f"   Event Count: {alert['event_count']}")

    print("\n========== REPORTS GENERATED ==========")
    print(f"JSON: {json_report}")
    print(f"CSV:  {csv_report}")
    print("\nAnalysis completed successfully!")


if __name__ == "__main__":
    main()
