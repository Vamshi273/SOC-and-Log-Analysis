import argparse
from pathlib import Path

from parser import load_auth_logs
from detector import analyze_auth_events
from reporter import export_reports


def main():
    parser = argparse.ArgumentParser(
        description="Linux Authentication Log Analysis Tool"
    )

    parser.add_argument(
        "--input",
        default="02_Linux_Authentication_Log_Analysis/sample_logs/auth.log",
        help="Path to Linux authentication log"
    )

    parser.add_argument(
        "--output",
        default="02_Linux_Authentication_Log_Analysis/reports",
        help="Directory for generated reports"
    )

    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Year used to interpret syslog timestamps"
    )

    args = parser.parse_args()

    input_path = Path(args.input)

    print("\n========================================")
    print(" LINUX AUTHENTICATION LOG ANALYZER")
    print("========================================")

    events, invalid_lines = load_auth_logs(
        input_path,
        year=args.year
    )

    analysis = analyze_auth_events(events)

    report_files = export_reports(
        events,
        analysis,
        args.output
    )

    print(f"\nInput file       : {input_path}")
    print(f"Parsed events    : {len(events)}")
    print(f"Invalid lines    : {invalid_lines}")
    print(f"Total alerts     : {len(analysis['alerts'])}")

    print("\nEvent classification:")

    for event_type, count in analysis["event_counts"].items():
        print(f"  {event_type:<25} {count}")

    print("\nGenerated reports:")

    for file_path in report_files:
        print(f"  {file_path}")

    print("\nAnalysis completed successfully.")


if __name__ == "__main__":
    main()
