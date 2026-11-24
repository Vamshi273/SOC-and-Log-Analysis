from datetime import datetime, timedelta
from collections import defaultdict


FAILURE_TYPES = {
    "SSH_LOGIN_FAILURE",
    "SSH_INVALID_USER",
}

SUCCESS_TYPES = {
    "SSH_LOGIN_SUCCESS",
    "SSH_ROOT_LOGIN",
}


def _timestamp(event):
    """Convert an event timestamp into a datetime object."""
    value = event.get("timestamp")

    if isinstance(value, datetime):
        return value

    return datetime.fromisoformat(value)


def _severity(attempts, multiple_users=False):
    """Classify brute-force alert severity."""
    if attempts >= 20:
        return "CRITICAL"

    if attempts >= 10 or multiple_users:
        return "HIGH"

    if attempts >= 5:
        return "MEDIUM"

    return "LOW"


def _make_alert(
    rule,
    severity,
    timestamp,
    source_ips,
    usernames,
    failures,
    successes,
    description,
):
    """Create a standardized security alert."""

    return {
        "rule": rule,
        "severity": severity,
        "timestamp": timestamp.isoformat(),
        "source_ips": sorted(source_ips),
        "targeted_usernames": sorted(usernames),
        "failed_attempts": failures,
        "successful_logins": successes,
        "description": description,
    }


def detect_ssh_attacks(
    events,
    threshold=5,
    window_minutes=5,
    multi_user_threshold=3,
    distributed_ip_threshold=2,
):
    """
    Detect SSH brute-force and related authentication attacks.

    Args:
        events: Parsed authentication events.
        threshold: Minimum failed attempts.
        window_minutes: Correlation time window.
        multi_user_threshold: Minimum usernames targeted.
        distributed_ip_threshold: Minimum IPs targeting one account.

    Returns:
        Dictionary containing summary statistics and security alerts.
    """

    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes < 1:
        raise ValueError("window_minutes must be at least 1")

    if multi_user_threshold < 2:
        raise ValueError("multi_user_threshold must be at least 2")

    if distributed_ip_threshold < 2:
        raise ValueError("distributed_ip_threshold must be at least 2")

    window = timedelta(minutes=window_minutes)

    failures = []
    successes = []

    for event in events:
        event_type = event.get("event_type")

        if event_type in FAILURE_TYPES:
            if event.get("source_ip") not in (None, "", "Unknown"):
                failures.append(event)

        elif event_type in SUCCESS_TYPES:
            if event.get("source_ip") not in (None, "", "Unknown"):
                successes.append(event)

    failures.sort(key=_timestamp)
    successes.sort(key=_timestamp)

    alerts = []

    # -------------------------------------------------
    # 1. Group failed attempts by source IP.
    # -------------------------------------------------

    ip_groups = defaultdict(list)

    for event in failures:
        ip_groups[event["source_ip"]].append(event)

    for source_ip, ip_events in ip_groups.items():

        left = 0
        alert_active = False

        for right in range(len(ip_events)):

            current_time = _timestamp(ip_events[right])

            while (
                left <= right
                and current_time - _timestamp(ip_events[left]) > window
            ):
                left += 1

            current_window = ip_events[left:right + 1]

            if len(current_window) < threshold:
                alert_active = False
                continue

            if alert_active:
                continue

            usernames = {
                event.get("username", "Unknown")
                for event in current_window
            }

            multi_user = len(usernames) >= multi_user_threshold

            severity = _severity(
                len(current_window),
                multiple_users=multi_user,
            )

            rule = (
                "SSH_MULTI_ACCOUNT_BRUTE_FORCE"
                if multi_user
                else "SSH_BRUTE_FORCE"
            )

            alerts.append(
                _make_alert(
                    rule=rule,
                    severity=severity,
                    timestamp=current_time,
                    source_ips={source_ip},
                    usernames=usernames,
                    failures=len(current_window),
                    successes=0,
                    description=(
                        f"{len(current_window)} failed SSH attempts "
                        f"from {source_ip} within "
                        f"{window_minutes} minutes."
                    ),
                )
            )

            alert_active = True

    # -------------------------------------------------
    # 2. Detect distributed attacks against one account.
    # -------------------------------------------------

    username_groups = defaultdict(list)

    for event in failures:
        username_groups[event.get("username", "Unknown")].append(event)

    for username, user_events in username_groups.items():

        left = 0
        alert_active = False

        for right in range(len(user_events)):

            current_time = _timestamp(user_events[right])

            while (
                left <= right
                and current_time - _timestamp(user_events[left]) > window
            ):
                left += 1

            current_window = user_events[left:right + 1]

            source_ips = {
                event["source_ip"]
                for event in current_window
            }

            qualifies = (
                len(current_window) >= threshold
                and len(source_ips) >= distributed_ip_threshold
            )

            if not qualifies:
                alert_active = False
                continue

            if alert_active:
                continue

            alerts.append(
                _make_alert(
                    rule="SSH_DISTRIBUTED_BRUTE_FORCE",
                    severity="HIGH",
                    timestamp=current_time,
                    source_ips=source_ips,
                    usernames={username},
                    failures=len(current_window),
                    successes=0,
                    description=(
                        f"Account {username} received "
                        f"{len(current_window)} failed SSH attempts "
                        f"from {len(source_ips)} source IPs."
                    ),
                )
            )

            alert_active = True

    # -------------------------------------------------
    # 3. Detect successful login after repeated failures.
    # -------------------------------------------------

    for success in successes:

        success_time = _timestamp(success)
        source_ip = success["source_ip"]
        username = success.get("username", "Unknown")

        previous_failures = [
            event
            for event in failures
            if event["source_ip"] == source_ip
            and event.get("username", "Unknown") == username
            and timedelta(0)
            <= success_time - _timestamp(event)
            <= window
        ]

        if len(previous_failures) >= threshold:

            alerts.append(
                _make_alert(
                    rule="SSH_SUCCESS_AFTER_BRUTE_FORCE",
                    severity="CRITICAL",
                    timestamp=success_time,
                    source_ips={source_ip},
                    usernames={username},
                    failures=len(previous_failures),
                    successes=1,
                    description=(
                        f"Successful SSH login for {username} from "
                        f"{source_ip} following "
                        f"{len(previous_failures)} failed attempts."
                    ),
                )
            )

    alerts.sort(key=lambda alert: alert["timestamp"])

    severity_counts = {
        level: sum(
            alert["severity"] == level
            for alert in alerts
        )
        for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    }

    return {
        "total_events": len(events),
        "failed_attempts": len(failures),
        "successful_logins": len(successes),
        "total_alerts": len(alerts),
        "severity_counts": severity_counts,
        "alerts": alerts,
    }


def analyze_ssh_logs(events, **kwargs):
    """Convenience wrapper for SSH attack analysis."""
    return detect_ssh_attacks(events, **kwargs)
