from collections import Counter


SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def classify_event(alerts):
    """Determine the highest severity among an event's alerts."""
    if not alerts:
        return "LOW"

    return max(
        (alert["severity"] for alert in alerts),
        key=lambda severity: SEVERITY_ORDER.get(severity, 0),
    )


def calculate_severity_summary(events):
    """Count events by their highest assigned severity."""
    summary = Counter({
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    })

    for event in events:
        severity = event.get("severity", "LOW")
        if severity in summary:
            summary[severity] += 1

    return dict(summary)
