from collections import Counter
from classifier import classify_failure


def analyze_failures(events):
    """Analyze Windows and Linux failed-login events."""

    total = 0
    platform_counts = Counter()
    category_counts = Counter()
    username_counts = Counter()
    source_ip_counts = Counter()
    timeline = []

    classified_events = []

    for event in events:
        if not isinstance(event, dict):
            continue

        platform = str(
            event.get("platform", "Unknown")
        ).strip() or "Unknown"

        classification = classify_failure(event)

        category = classification["failure_category"]
        username = str(
            event.get("username", "Unknown")
        ).strip() or "Unknown"

        source_ip = str(
            event.get("source_ip", "Unknown")
        ).strip() or "Unknown"

        timestamp = event.get("timestamp", "Unknown")

        total += 1
        platform_counts[platform] += 1
        category_counts[category] += 1
        username_counts[username] += 1
        source_ip_counts[source_ip] += 1

        analyzed_event = {
            **event,
            "failure_category": category,
            "failure_description": classification["description"],
            "evidence_code": classification["evidence_code"]
        }

        classified_events.append(analyzed_event)

        timeline.append({
            "timestamp": timestamp,
            "platform": platform,
            "username": username,
            "source_ip": source_ip,
            "failure_category": category
        })

    timeline.sort(
        key=lambda item: str(item["timestamp"])
    )

    return {
        "summary": {
            "total_failures": total,
            "platform_counts": dict(platform_counts),
            "category_counts": dict(category_counts),
            "unique_usernames": len(username_counts),
            "unique_source_ips": len(source_ip_counts)
        },
        "top_usernames": [
            {"username": name, "count": count}
            for name, count in username_counts.most_common()
        ],
        "top_source_ips": [
            {"source_ip": ip, "count": count}
            for ip, count in source_ip_counts.most_common()
        ],
        "timeline": timeline,
        "events": classified_events
    }