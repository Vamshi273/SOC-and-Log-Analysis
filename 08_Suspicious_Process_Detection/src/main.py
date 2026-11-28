import argparse
from pathlib import Path

from src.analyzer import analyze_process_logs
from src.reporter import generate_reports


def main():
    project_dir = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(
        description="Windows Suspicious Process Detection Tool"
    )

    parser.add_argument(
        "--input",
        default=str(project_dir / "datasets" / "sample_process_logs.csv"),
        help="Path to process telemetry CSV",
    )

    parser.add_argument(
        "--rules",
        default=str(project_dir / "config" / "detection_rules.json"),
        help="Path to detection rules JSON",
    )

    parser.add_argument(
        "--output",
        default=str(project_dir / "reports"),
        help="Directory for generated reports",
    )

    args = parser.parse_args()

    analysis = analyze_process_logs(args.input, args.rules)
    json_report, csv_report = generate_reports(analysis, args.output)

    print("\n========================================")
    print(" SUSPICIOUS PROCESS DETECTION REPORT")
    print("========================================")
    print(f"Total records  : {analysis['total_records']}")
    print(f"Invalid records: {len(analysis['invalid_records'])}")
    print(f"Normal records : {analysis['normal_records']}")
    print(f"Alerts         : {analysis['total_alerts']}")

    print("\nRisk Summary")
    for level, count in analysis["risk_summary"].items():
        print(f"{level:10}: {count}")

    print("\nDetected Alerts")
    for item in analysis["results"]:
        if item["Status"] == "ALERT":
            print(
                f"[{item['RiskLevel']}] "
                f"{item['ProcessName']} "
                f"(PID: {item['ProcessId']}) "
                f"Score: {item['RiskScore']}"
            )

            for finding in item["Findings"]:
                print(f"    - {finding}")

    print("\nReports Generated")
    print(f"JSON: {json_report}")
    print(f"CSV : {csv_report}")


if __name__ == "__main__":
    main()
