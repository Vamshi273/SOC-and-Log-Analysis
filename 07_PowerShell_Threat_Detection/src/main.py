import argparse
import sys

from .analyzer import analyze_log_file
from .reporter import generate_reports


def create_argument_parser():
    parser = argparse.ArgumentParser(
        description="PowerShell Threat Detection and Log Analysis Tool"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to the PowerShell event log file",
    )

    parser.add_argument(
        "--output",
        default="07_PowerShell_Threat_Detection/reports",
        help="Directory for generated reports",
    )

    return parser


def main():
    parser = create_argument_parser()
    args = parser.parse_args()

    try:
        print("\nPowerShell Threat Detection")
        print("=" * 45)

        results = analyze_log_file(args.input)
        reports = generate_reports(results, args.output)

        summary = results["summary"]

        print("\nAnalysis Summary")
        print("-" * 45)
        print(f"Total Events       : {summary['total_events']}")
        print(f"Suspicious Events  : {summary['suspicious_events']}")
        print(f"Normal Events      : {summary['normal_events']}")
        print(f"Skipped Events     : {summary['skipped_events']}")
        print(f"Total Alerts       : {summary['total_alerts']}")

        print("\nSeverity Distribution")
        print("-" * 45)

        for severity, count in summary["severity_levels"].items():
            print(f"{severity:<12}: {count}")

        print("\nDetection Rules")
        print("-" * 45)

        for rule, count in summary["detection_rule_counts"].items():
            print(f"{rule}: {count}")

        print("\nGenerated Reports")
        print("-" * 45)
        print(f"JSON: {reports['json']}")
        print(f"CSV : {reports['csv']}")

        print("\nAnalysis completed successfully.")

        return 0

    except (OSError, ValueError) as error:
        print(f"\nError: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
