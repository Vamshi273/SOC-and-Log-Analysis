import csv
import argparse
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime, timezone


FAILED_LOGIN = "4625"
SUCCESSFUL_LOGIN = "4624"
BRUTE_FORCE_THRESHOLD = 5


def load_logs(file_path):

    events = []

    with open(file_path, "r", encoding="utf-8-sig") as file:

        reader = csv.DictReader(file)

        for row in reader:
            events.append(row)

    return events


def analyze_logs(events):

    failed_logins = []
    successful_logins = []

    account_failures = Counter()
    ip_failures = Counter()

    for event in events:

        event_id = str(event.get("Id", "")).strip()

        message = event.get("Message", "")

        if event_id == FAILED_LOGIN:

            failed_logins.append(event)

            account = event.get("TargetUserName", "Unknown")
            ip = event.get("IpAddress", "Unknown")

            account_failures[account] += 1
            ip_failures[ip] += 1

        elif event_id == SUCCESSFUL_LOGIN:

            successful_logins.append(event)

    alerts = []

    for ip, count in ip_failures.items():

        if ip not in ("Unknown", "-", "") and count >= BRUTE_FORCE_THRESHOLD:

            alerts.append({
                "severity": "HIGH",
                "type": "Possible Brute Force",
                "source_ip": ip,
                "attempts": count
            })

    return {
        "total_events": len(events),
        "failed_logins": len(failed_logins),
        "successful_logins": len(successful_logins),
        "account_failures": account_failures,
        "ip_failures": ip_failures,
        "alerts": alerts
    }


def generate_report(results, output_file):

    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Severity",
            "Detection",
            "Source IP",
            "Attempts"
        ])

        for alert in results["alerts"]:

            writer.writerow([
                alert["severity"],
                alert["type"],
                alert["source_ip"],
                alert["attempts"]
            ])

    print(f"\nReport generated: {output_file}")


def display_results(results):

    print("\n" + "=" * 55)
    print("       WINDOWS SECURITY LOG ANALYZER")
    print("=" * 55)

    print(f"\nTotal Events       : {results['total_events']}")
    print(f"Failed Logins      : {results['failed_logins']}")
    print(f"Successful Logins  : {results['successful_logins']}")

    print("\n--- Account Failure Summary ---")

    for account, count in results["account_failures"].most_common():

        print(f"{account:<25} {count}")

    print("\n--- Security Alerts ---")

    if not results["alerts"]:

        print("No brute-force patterns detected.")

    else:

        for alert in results["alerts"]:

            print(
                f"[{alert['severity']}] "
                f"{alert['type']} | "
                f"IP: {alert['source_ip']} | "
                f"Attempts: {alert['attempts']}"
            )

    print("\n" + "=" * 55)


def main():

    parser = argparse.ArgumentParser(
        description="Windows Security Event Log Analyzer"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to Windows Event Log CSV"
    )

    parser.add_argument(
        "--output",
        default="../reports/security_report.csv",
        help="Output report path"
    )

    args = parser.parse_args()

    events = load_logs(args.input)

    results = analyze_logs(events)

    display_results(results)

    generate_report(results, args.output)


if __name__ == "__main__":
    main()