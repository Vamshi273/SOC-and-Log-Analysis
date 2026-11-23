import argparse
import csv
import json

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


FAILED_LOGIN = "4625"
SUCCESSFUL_LOGIN = "4624"
EXPLICIT_CREDENTIALS = "4648"
SPECIAL_PRIVILEGES = "4672"

BRUTE_FORCE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 10


def load_logs(file_path):
    """Load Windows Security events from CSV."""

    events = []

    with open(file_path, "r", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("CSV file is empty or has no headers.")

        for row in reader:
            events.append(row)

    return events


def get_event_id(event):
    return str(
        event.get("Id") or event.get("EventId") or ""
    ).strip()


def get_timestamp(event):
    """Parse timestamps and normalize them to UTC."""

    value = event.get("TimeCreated", "")

    if not value:
        return None

    try:
        timestamp = datetime.fromisoformat(value.strip())

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    except (ValueError, TypeError, AttributeError):
        return None

def get_field(event, field):
    value = event.get(field)

    if value is None or str(value).strip() in ("", "-", "None"):
        return "Unknown"

    return str(value).strip()


def analyze_logs(events):
    """Analyze Windows Security events and correlate suspicious activity."""

    failed_logins = []
    successful_logins = []

    account_failures = Counter()
    ip_failures = Counter()

    event_counts = Counter()

    alerts = []

    for event in events:

        event_id = get_event_id(event)

        event_counts[event_id] += 1

        if event_id == FAILED_LOGIN:

            failed_logins.append(event)

            account = get_field(event, "TargetUserName")
            ip = get_field(event, "IpAddress")

            account_failures[account] += 1
            ip_failures[ip] += 1

        elif event_id == SUCCESSFUL_LOGIN:

            successful_logins.append(event)

    # Sort failed and successful events chronologically.
    minimum_time = datetime.min.replace(tzinfo=timezone.utc)

    failed_logins.sort(
        key=lambda e: get_timestamp(e) or minimum_time
    )

    successful_logins.sort(
        key=lambda e: get_timestamp(e) or minimum_time
    )

    # Group failed logins by source IP.
    failures_by_ip = defaultdict(list)

    for event in failed_logins:

        ip = get_field(event, "IpAddress")

        if ip != "Unknown":
            failures_by_ip[ip].append(event)

    # Detection 1: Time-window brute-force detection.
    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for ip, ip_events in failures_by_ip.items():

        valid_events = [
            event for event in ip_events
            if get_timestamp(event) is not None
        ]

        index = 0

        while index <= len(valid_events) - BRUTE_FORCE_THRESHOLD:

            start_time = get_timestamp(valid_events[index])
            end_time = start_time + window

            matching_events = []

            for event in valid_events[index:]:

                event_time = get_timestamp(event)

                if event_time <= end_time:
                    matching_events.append(event)
                else:
                    break

            if len(matching_events) >= BRUTE_FORCE_THRESHOLD:

                accounts = sorted({
                    get_field(event, "TargetUserName")
                    for event in matching_events
                })

                alerts.append({
                    "severity": "HIGH",
                    "type": "Possible Brute Force",
                    "source_ip": ip,
                    "attempts": len(matching_events),
                    "accounts": ", ".join(accounts),
                    "timestamp": start_time.isoformat(),
                    "mitre_attack": "T1110 - Brute Force",
                    "description": (
                        f"{len(matching_events)} failed logins "
                        f"from {ip} within "
                        f"{TIME_WINDOW_MINUTES} minutes."
                    )
                })

                index += len(matching_events)

            else:
                index += 1
    # Detection 2: Successful login after repeated failures.
    for success in successful_logins:

        success_time = get_timestamp(success)

        if success_time is None:
            continue

        success_ip = get_field(success, "IpAddress")

        if success_ip == "Unknown":
            continue

        matching_failures = []

        for failure in failures_by_ip.get(success_ip, []):

            failure_time = get_timestamp(failure)

            if failure_time is None:
                continue

            if timedelta(0) <= success_time - failure_time <= window:
                matching_failures.append(failure)

        if len(matching_failures) >= BRUTE_FORCE_THRESHOLD:

            alerts.append({
                "severity": "HIGH",
                "type": "Successful Login After Repeated Failures",
                "source_ip": success_ip,
                "attempts": len(matching_failures),
                "accounts": get_field(success, "TargetUserName"),
                "timestamp": success_time.isoformat(),
                "mitre_attack": "T1078 - Valid Accounts",
                "description": (
                    "Successful login occurred after "
                    f"{len(matching_failures)} failed attempts."
                )
            })

    # Detection 3: Explicit credential usage.
    explicit_credential_events = [
        event for event in events
        if get_event_id(event) == EXPLICIT_CREDENTIALS
    ]

    if explicit_credential_events:

        alerts.append({
            "severity": "LOW",
            "type": "Explicit Credential Usage Observed",
            "source_ip": "Local or recorded address",
            "attempts": len(explicit_credential_events),
            "accounts": ", ".join(sorted({
                get_field(event, "TargetUserName")
                for event in explicit_credential_events
            })),
            "timestamp": "",
            "mitre_attack": "Requires investigation",
            "description": (
                "Windows recorded explicit credential usage. "
                "Review the process and account context."
            )
        })

    # Detection 4: Special privileges assigned.
    privileged_events = [
        event for event in events
        if get_event_id(event) == SPECIAL_PRIVILEGES
    ]

    if privileged_events:

        alerts.append({
            "severity": "INFO",
            "type": "Special Privileges Assigned",
            "source_ip": "N/A",
            "attempts": len(privileged_events),
            "accounts": "Review event details",
            "timestamp": "",
            "mitre_attack": "Context-dependent",
            "description": (
                "Special privileges were assigned to logon sessions. "
                "This is not automatically malicious."
            )
        })

    return {
        "total_events": len(events),
        "failed_logins": len(failed_logins),
        "successful_logins": len(successful_logins),
        "explicit_credentials": len(explicit_credential_events),
        "privileged_events": len(privileged_events),
        "account_failures": account_failures,
        "ip_failures": ip_failures,
        "event_counts": event_counts,
        "alerts": alerts
    }


def generate_report(results, output_file):

    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "Severity",
        "Detection",
        "Source IP",
        "Attempts",
        "Accounts",
        "Timestamp",
        "MITRE ATT&CK",
        "Description"
    ]

    with output_file.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(file, fieldnames=fields)

        writer.writeheader()

        for alert in results["alerts"]:

            writer.writerow({
                "Severity": alert["severity"],
                "Detection": alert["type"],
                "Source IP": alert["source_ip"],
                "Attempts": alert["attempts"],
                "Accounts": alert["accounts"],
                "Timestamp": alert["timestamp"],
                "MITRE ATT&CK": alert["mitre_attack"],
                "Description": alert["description"]
            })

    print(f"\nCSV report generated: {output_file}")


def generate_json_report(results, output_file):

    output_file = Path(output_file)

    json_file = output_file.with_suffix(".json")

    json_file.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "summary": {
            "total_events": results["total_events"],
            "failed_logins": results["failed_logins"],
            "successful_logins": results["successful_logins"],
            "explicit_credentials": results["explicit_credentials"],
            "privileged_events": results["privileged_events"]
        },
        "event_distribution": dict(results["event_counts"]),
        "alerts": results["alerts"]
    }

    with json_file.open("w", encoding="utf-8") as file:

        json.dump(report, file, indent=4)

    print(f"JSON report generated: {json_file}")


def display_results(results):

    print("\n" + "=" * 60)
    print("          WINDOWS SECURITY LOG ANALYZER")
    print("=" * 60)

    print(f"\nTotal Events          : {results['total_events']}")
    print(f"Failed Logins         : {results['failed_logins']}")
    print(f"Successful Logins     : {results['successful_logins']}")
    print(f"Explicit Credentials  : {results['explicit_credentials']}")
    print(f"Special Privileges    : {results['privileged_events']}")

    print("\n--- Event Distribution ---")

    for event_id, count in results["event_counts"].most_common():

        print(f"Event ID {event_id:<12} {count}")

    print("\n--- Account Failure Summary ---")

    if not results["account_failures"]:
        print("No failed logins recorded.")

    for account, count in results["account_failures"].most_common():

        print(f"{account:<25} {count}")

    print("\n--- Security Alerts ---")

    if not results["alerts"]:
        print("No suspicious patterns detected.")

    for alert in results["alerts"]:

        print(
            f"\n[{alert['severity']}] {alert['type']}"
        )

        print(f"Source IP : {alert['source_ip']}")
        print(f"Attempts  : {alert['attempts']}")
        print(f"Accounts  : {alert['accounts']}")

        if alert["mitre_attack"]:
            print(f"MITRE     : {alert['mitre_attack']}")

        print(f"Details   : {alert['description']}")

    print("\n" + "=" * 60)


def main():

    parser = argparse.ArgumentParser(
        description="Windows Security Event Log Analyzer"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to Windows Security CSV"
    )

    parser.add_argument(
        "--output",
        default=str(
            Path(__file__).resolve().parents[1]
            / "reports"
            / "security_report.csv"
        )
    )

    args = parser.parse_args()

    events = load_logs(args.input)

    results = analyze_logs(events)

    display_results(results)

    generate_report(results, args.output)

    generate_json_report(results, args.output)


if __name__ == "__main__":
    main()


