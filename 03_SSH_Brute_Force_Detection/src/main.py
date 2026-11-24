import argparse
import sys
from pathlib import Path

# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODULE02_SRC = (
    PROJECT_ROOT / "02_Linux_Authentication_Log_Analysis" / "src"
)

MODULE03_SRC = Path(__file__).resolve().parent

# Import Module 03 detector before adding Module 02 parser path.
sys.path.insert(0, str(MODULE03_SRC))

from detector import detect_ssh_attacks
from reporter import export_reports

# Import the parser from Module 02.
sys.path.insert(0, str(MODULE02_SRC))

from parser import load_auth_logs


def main():
    parser = argparse.ArgumentParser(
        description="SSH Brute-Force Detection and Analysis"
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=PROJECT_ROOT / "03_SSH_Brute_Force_Detection"
        / "sample_logs" / "ssh_brute_force.log",
        help="Path to SSH authentication log file"
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "03_SSH_Brute_Force_Detection"
        / "reports",
        help="Directory for generated reports"
    )

    parser.add_argument(
        "--year",
        type=int,
        default=2026,
        help="Year used to interpret syslog timestamps"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts required for detection"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=5,
        help="Detection window in minutes"
    )

    args = parser.parse_args()

    if not args.input.is_file():
        parser.error(f"Input log file not found: {args.input}")

    print("\nSSH BRUTE-FORCE DETECTION")
    print("=" * 45)

    # Parse authentication logs.
    events, invalid_lines = load_auth_logs(
        args.input,
        year=args.year
    )

    print(f"Parsed events: {len(events)}")
    print(f"Invalid lines: {invalid_lines}")

    # Analyze SSH attacks.
    analysis = detect_ssh_attacks(
        events,
        threshold=args.threshold,
        window_minutes=args.window
    )

    print(f"Failed attempts: {analysis['failed_attempts']}")
    print(f"Successful logins: {analysis['successful_logins']}")
    print(f"Total alerts: {analysis['total_alerts']}")

    print("\nSeverity Summary:")
    for severity, count in analysis["severity_counts"].items():
        print(f"  {severity}: {count}")

    print("\nDetected Attacks:")
    if not analysis["alerts"]:
        print("  No SSH attacks detected.")
    else:
        for index, alert in enumerate(analysis["alerts"], start=1):
            print(f"\n  Alert {index}: {alert['rule']}")
            print(f"  Severity: {alert['severity']}")
            print(f"  Source IPs: {', '.join(alert['source_ips'])}")
            print(
                "  Targeted usernames: "
                + ", ".join(alert["targeted_usernames"])
            )
            print(f"  Description: {alert['description']}")

    # Generate JSON and CSV reports.
    report_paths = export_reports(
        events,
        analysis,
        args.output
    )

    print("\nReports Generated:")
    for report_type, report_path in report_paths.items():
        print(f"  {report_type}: {report_path}")

    print("\nAnalysis completed successfully.")


if __name__ == "__main__":
    main()
