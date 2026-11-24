from collections import Counter, defaultdict


def analyze_auth_events(events):
    """
    Analyze parsed Linux authentication events.

    This module classifies authentication activity and generates
    basic alerts. Dedicated brute-force detection belongs in Module 03.
    """
    event_counts = Counter()
    account_activity = Counter()
    source_ip_activity = Counter()
    alerts = []

    for event in events:
        event_type = event.get("event_type", "OTHER")
        username = event.get("username")
        source_ip = event.get("source_ip")

        event_counts[event_type] += 1

        if username:
            account_activity[username] += 1

        if source_ip:
            source_ip_activity[source_ip] += 1

        if event_type == "SSH_INVALID_USER":
            alerts.append({
                "severity": "MEDIUM",
                "alert_type": "Invalid Username Attempt",
                "username": username,
                "source_ip": source_ip,
                "timestamp": str(event.get("timestamp")),
                "description": (
                    f"SSH authentication attempt involving "
                    f"unknown account: {username}"
                )
            })

        elif event_type == "SSH_ROOT_LOGIN":
            alerts.append({
                "severity": "HIGH",
                "alert_type": "Successful Root SSH Login",
                "username": username,
                "source_ip": source_ip,
                "timestamp": str(event.get("timestamp")),
                "description": (
                    "A successful SSH login was recorded for root."
                )
            })

        elif event_type == "SSH_LOGIN_FAILURE":
            alerts.append({
                "severity": "INFO",
                "alert_type": "Failed SSH Authentication",
                "username": username,
                "source_ip": source_ip,
                "timestamp": str(event.get("timestamp")),
                "description": (
                    f"Failed SSH authentication for {username}."
                )
            })

    return {
        "total_events": len(events),
        "event_counts": event_counts,
        "account_activity": account_activity,
        "source_ip_activity": source_ip_activity,
        "alerts": alerts
    }
