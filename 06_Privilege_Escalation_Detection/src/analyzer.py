from collections import Counter
from datetime import datetime

from .classifier import classify_privilege_event
from .linux_parser import load_linux_privilege_events
from .windows_parser import load_windows_privilege_events


def analyze_privilege_events(windows_file=None, linux_file=None, year=None):
    """Analyze Windows and Linux privilege-related events."""

    events = []
    skipped = {
        "windows": 0,
        "linux": 0
    }

    # Load Windows events
    if windows_file:
        windows_events, skipped["windows"] = (
            load_windows_privilege_events(windows_file)
        )
        events.extend(windows_events)

    # Load Linux events
    if linux_file:
        linux_events, skipped["linux"] = (
            load_linux_privilege_events(
                linux_file,
                year=year
            )
        )
        events.extend(linux_events)

    # Classify every event
    for event in events:
        classification = classify_privilege_event(event)
        event.update(classification)

    # Sort events chronologically
    events.sort(
        key=lambda event: event.get("timestamp", "")
    )

    # Summary statistics
    platforms = Counter(
        event.get("platform", "Unknown")
        for event in events
    )

    event_types = Counter(
        event.get("event_type", "UNKNOWN")
        for event in events
    )

    risk_levels = Counter(
        event.get("risk_level", "UNKNOWN")
        for event in events
    )

    actors = Counter(
        event.get("actor", "Unknown")
        for event in events
        if event.get("actor", "Unknown") != "Unknown"
    )

    targets = Counter(
        event.get("target_username", "Unknown")
        for event in events
        if event.get("target_username", "Unknown") != "Unknown"
    )

    # Identify privileged group membership changes
    privileged_group_keywords = (
        "administrator",
        "domain admin",
        "enterprise admin",
        "root",
        "sudo"
    )

    privileged_group_events = []

    for event in events:
        group_name = str(
            event.get("group_name", "")
        ).lower()

        if any(
            keyword in group_name
            for keyword in privileged_group_keywords
        ):
            privileged_group_events.append(event)

    summary = {
        "generated_at": datetime.now().isoformat(
            timespec="seconds"
        ),
        "total_events": len(events),
        "skipped_events": skipped,
        "platforms": dict(platforms),
        "event_types": dict(event_types),
        "risk_levels": dict(risk_levels),
        "top_actors": dict(actors.most_common(10)),
        "top_targets": dict(targets.most_common(10)),
        "privileged_group_changes": len(
            privileged_group_events
        )
    }

    return {
        "summary": summary,
        "events": events
    }


def print_analysis_report(result):
    """Print a readable privilege activity report."""

    summary = result["summary"]
    events = result["events"]

    print("\n" + "=" * 65)
    print("       PRIVILEGE ESCALATION DETECTION REPORT")
    print("=" * 65)

    print(f"\nGenerated At       : {summary['generated_at']}")
    print(f"Total Events       : {summary['total_events']}")
    print(f"Privileged Group Changes : {summary['privileged_group_changes']}")

    print("\n--- PLATFORM BREAKDOWN ---")

    for platform, count in summary["platforms"].items():
        print(f"{platform:<20}: {count}")

    print("\n--- RISK BREAKDOWN ---")

    for risk, count in summary["risk_levels"].items():
        print(f"{risk:<20}: {count}")

    print("\n--- EVENT TYPE BREAKDOWN ---")

    for event_type, count in summary["event_types"].items():
        print(f"{event_type:<40}: {count}")

    print("\n--- TOP ACTORS ---")

    for actor, count in summary["top_actors"].items():
        print(f"{actor:<25}: {count}")

    print("\n--- TOP TARGET ACCOUNTS ---")

    for target, count in summary["top_targets"].items():
        print(f"{target:<25}: {count}")

    print("\n--- INVESTIGATION EVENTS ---")

    if not events:
        print("No supported privilege-related events found.")

    for index, event in enumerate(events, start=1):
        print(f"\n[{index}] {event.get('risk_level', 'UNKNOWN')} "
              f"- {event.get('event_type', 'UNKNOWN')}")

        print(f"Platform      : {event.get('platform', 'Unknown')}")
        print(f"Timestamp     : {event.get('timestamp', 'Unknown')}")
        print(f"Actor         : {event.get('actor', 'Unknown')}")
        print(f"Target        : {event.get('target_username', 'Unknown')}")
        print(f"Description   : {event.get('description', 'Unknown')}")

        if event.get("command", "Unknown") != "Unknown":
            print(f"Command       : {event['command']}")

        if event.get("group_name", "Unknown") != "Unknown":
            print(f"Group         : {event['group_name']}")

    print("\n--- PARSING INFORMATION ---")

    print(
        f"Skipped Windows rows : "
        f"{summary['skipped_events']['windows']}"
    )

    print(
        f"Skipped Linux lines  : "
        f"{summary['skipped_events']['linux']}"
    )

    print("\n" + "=" * 65)
    print("                 ANALYSIS COMPLETED")
    print("=" * 65)