from collections import Counter
from datetime import datetime, timezone

from .parser import parse_log_file
from .detector import analyze_event
from .classifier import classify_event, calculate_severity_summary


def analyze_log_file(file_path):
    """Parse, detect and classify PowerShell security events."""

    events, errors = parse_log_file(file_path)

    analyzed_events = []

    for event in events:
        result = analyze_event(event)

        result["severity"] = classify_event(result["alerts"])

        analyzed_events.append(result)

    suspicious_events = [
        event for event in analyzed_events
        if event["is_suspicious"]
    ]

    event_type_counts = Counter(
        str(event["event_id"]) for event in analyzed_events
    )

    host_counts = Counter(
        event["computer"] for event in analyzed_events
    )

    user_counts = Counter(
        event["user"] for event in analyzed_events
    )

    alert_counts = Counter(
        alert["rule_name"]
        for event in analyzed_events
        for alert in event["alerts"]
    )

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events": len(analyzed_events),
        "suspicious_events": len(suspicious_events),
        "normal_events": len(analyzed_events) - len(suspicious_events),
        "skipped_events": len(errors),
        "event_types": dict(event_type_counts),
        "severity_levels": calculate_severity_summary(analyzed_events),
        "top_hosts": dict(host_counts.most_common(10)),
        "top_users": dict(user_counts.most_common(10)),
        "detection_rule_counts": dict(alert_counts),
        "total_alerts": sum(alert_counts.values()),
    }

    return {
        "summary": summary,
        "events": analyzed_events,
        "errors": errors,
    }
