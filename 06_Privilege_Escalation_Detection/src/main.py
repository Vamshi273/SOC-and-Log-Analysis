import argparse
import sys
from pathlib import Path

from .analyzer import (
    analyze_privilege_events,
    print_analysis_report
)
from .reporter import (
    export_csv_report,
    export_json_report
)


def create_argument_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Windows and Linux Privilege Escalation "
            "Detection and Analysis Tool"
        )
    )

    parser.add_argument(
        "--windows",
        help="Path to Windows Security Event CSV file"
    )

    parser.add_argument(
        "--linux",
        help="Path to Linux authentication log file"
    )

    parser.add_argument(
        "--year",
        type=int,
        help="Year to use when parsing Linux syslog timestamps"
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Directory for generated reports (default: reports)"
    )

    return parser


def main():
    parser = create_argument_parser()
    args = parser.parse_args()

    if not args.windows and not args.linux:
        parser.error(
            "Provide at least one input using --windows or --linux."
        )

    try:
        result = analyze_privilege_events(
            windows_file=args.windows,
            linux_file=args.linux,
            year=args.year
        )

        print_analysis_report(result)

        json_file = export_json_report(
            result,
            args.output
        )

        csv_file = export_csv_report(
            result,
            args.output
        )

        print("\n--- REPORT FILES ---")
        print(f"JSON: {json_file}")
        print(f"CSV : {csv_file}")

        print("\nReports generated successfully.")

    except (FileNotFoundError, ValueError, OSError) as error:
        print(f"\nERROR: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())