from collections import defaultdict
from urllib.parse import unquote
import re


DETECTION_RULES = [
    {
        "name": "SQL Injection Attempt",
        "pattern": r"union\s+select|select\s+.+\s+from|or\s+['\"]?1['\"]?\s*=\s*['\"]?1",
        "severity": "HIGH",
        "mitre": "T1190",
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "pattern": r"<script|javascript:|onerror\s*=|onload\s*=",
        "severity": "HIGH",
        "mitre": "T1190",
    },
    {
        "name": "Directory Traversal",
        "pattern": r"\.\./|\.\.\\|/etc/passwd|/etc/shadow",
        "severity": "HIGH",
        "mitre": "T1190",
    },
]


SCANNER_SIGNATURES = [
    "sqlmap",
    "nikto",
    "nmap",
    "gobuster",
    "dirbuster",
    "wpscan",
]


def detect_attacks(entries):
    alerts = []

    ip_failures = defaultdict(int)
    ip_404_count = defaultdict(int)
    scanner_activity = defaultdict(list)

    for entry in entries:
        ip = entry["ip"]
        url = unquote(entry["url"]).lower()
        user_agent = entry["user_agent"].lower()
        status = entry["status"]

        # SQL Injection, XSS and Directory Traversal
        for rule in DETECTION_RULES:
            if re.search(rule["pattern"], url, re.IGNORECASE):
                alerts.append({
                    "ip": ip,
                    "attack": rule["name"],
                    "severity": rule["severity"],
                    "url": entry["url"],
                    "mitre_attack": rule["mitre"],
                    "evidence": url,
                })

        # Aggregate automated scanner activity by IP
        for scanner in SCANNER_SIGNATURES:
            if scanner in user_agent:
                scanner_activity[ip].append({
                    "url": entry["url"],
                    "user_agent": entry["user_agent"],
                })
                break

        # Failed authentication tracking
        if status == 401:
            ip_failures[ip] += 1

        # HTTP 404 scanning tracking
        if status == 404:
            ip_404_count[ip] += 1

    # Generate one scanner alert per IP
    for ip, events in scanner_activity.items():
        alerts.append({
            "ip": ip,
            "attack": "Automated Web Scanner",
            "severity": "MEDIUM",
            "url": "Multiple resources",
            "mitre_attack": "T1595",
            "event_count": len(events),
            "evidence": [
                event["user_agent"] for event in events
            ],
        })

    # Detect repeated failed authentication
    for ip, count in ip_failures.items():
        if count >= 5:
            alerts.append({
                "ip": ip,
                "attack": "Possible Login Brute Force",
                "severity": "HIGH",
                "url": "/login",
                "mitre_attack": "T1110",
                "event_count": count,
                "evidence": f"{count} HTTP 401 responses",
            })

    # Detect repeated missing-resource requests
    for ip, count in ip_404_count.items():
        if count >= 3:
            alerts.append({
                "ip": ip,
                "attack": "Possible Directory Scanning",
                "severity": "MEDIUM",
                "url": "Multiple resources",
                "mitre_attack": "T1595.003",
                "event_count": count,
                "evidence": f"{count} HTTP 404 responses",
            })

    return alerts