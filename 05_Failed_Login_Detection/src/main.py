import argparse
import sys
from pathlib import Path

from windows_parser import load_windows_failures
from linux_parser import load_linux_failures
from analyzer import analyze_failures
from reporter import generate_reports


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Cross-platform failed-login investigation tool "
            "for Windows and Linux authentication logs."
        )
    )

    parser.add_argument(
        "--windows",
        help="Path to Windows Security Event CSV file."
    )

    parser.add_argument(
        "--linux",
        help="Path to Linux authentication log file."
    )

    parser.add_argument(
        "--year",
        type=int,
        help="Year used to interpret Linux syslog timestamps."
    )

    parser.add_argument(
        "--output",
        default="05_Failed_Login_Detection/reports",
        help="Directory for generated reports."
    )

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.windows and not args.linux:
        parser.error(
            "Provide at least one input using --windows or --linux."
        )

    events = []
    skipped = {
        "Windows": 0,
        "Linux": 0
    }

    try:
        if args.windows:
            windows_events, windows_skipped = (
                load_windows_failures(args.windows)
            )

            events.extend(windows_events)
            skipped["Windows"] = windows_skipped

        if args.linux:
            linux_events, linux_skipped = (
                load_linux_failures(
                    args.linux,
                    year=args.year
                )
            )

            events.extend(linux_events)
            skipped["Linux"] = linux_skipped

        analysis = analyze_failures(events)

        report_paths = generate_reports(
            analysis,
            args.output
        )

    except (FileNotFoundError, PermissionError, ValueError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1

    summary = analysis["summary"]

    print("\n" + "=" * 55)
    print("       FAILED LOGIN INVESTIGATION REPORT")
    print("=" * 55)

    print(f"\nTotal failed logins : {summary['total_failures']}")

    print("\nPlatform breakdown:")

    for platform, count in summary["platform_counts"].items():
        print(f"  {platform:<12}: {count}")

    print("\nFailure categories:")

    for category, count in summary["category_counts"].items():
        print(f"  {category:<30}: {count}")

    print("\nTop affected accounts:")

    for item in analysis["top_usernames"][:5]:
        print(
            f"  {item['username']:<25} "
            f"{item['count']} failures"
        )

    print("\nTop source IP addresses:")

    for item in analysis["top_source_ips"][:5]:
        print(
            f"  {item['source_ip']:<25} "
            f"{item['count']} failures"
        )

    print("\nSkipped records:")

    for platform, count in skipped.items():
        print(f"  {platform:<12}: {count}")

    print("\nGenerated reports:")

    for report_type, path in report_paths.items():
        print(f"  {report_type.upper():<8}: {path}")

    print("\nInvestigation completed.")
    print("=" * 55)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())