import re


DETECTION_RULES = [
    {
        "name": "Encoded PowerShell Command",
        "category": "Obfuscation",
        "severity": "HIGH",
        "description": "PowerShell was launched with an encoded command argument.",
        "pattern": r"(?i)(?:^|\s)-(?:enc|encodedcommand|e)(?:\s|:)",
    },
        {
        "name": "Execution Policy Bypass",
        "category": "Execution Policy",
        "severity": "MEDIUM",
        "description": "PowerShell execution policy bypass or unrestricted mode was detected.",
        "pattern": r"(?i)(?:-executionpolicy\s+|set-executionpolicy\s+)(?:bypass|unrestricted)\b",
    },
    {
        "name": "Hidden PowerShell Window",
        "category": "Stealth Execution",
        "severity": "MEDIUM",
        "description": "PowerShell was configured to run with a hidden window.",
        "pattern": r"(?i)-windowstyle\s+hidden",
    },
    {
        "name": "Download and Execute Pattern",
        "category": "Download and Execution",
        "severity": "CRITICAL",
        "description": "A remote download pattern was combined with execution behavior.",
        "pattern": r"(?is)(?:downloadstring|downloadfile|invoke-webrequest|start-bitstransfer).{0,500}(?:iex|invoke-expression|start-process)|(?:iex|invoke-expression|start-process).{0,500}(?:downloadstring|downloadfile|invoke-webrequest|start-bitstransfer)",
    },
    {
        "name": "Invoke Expression with Remote Content",
        "category": "Remote Execution",
        "severity": "CRITICAL",
        "description": "Invoke-Expression appears alongside remote content retrieval.",
        "pattern": r"(?is)(?:iex|invoke-expression).{0,300}(?:https?://|downloadstring|downloadfile)",
    },
    {
        "name": "Base64 Decoding",
        "category": "Obfuscation",
        "severity": "MEDIUM",
        "description": "A Base64 decoding operation was detected.",
        "pattern": r"(?i)(?:frombase64string|base64\s*decode)",
    },
    {
        "name": "Remote Script Execution",
        "category": "Remote Execution",
        "severity": "HIGH",
        "description": "A remote script or command execution pattern was detected.",
        "pattern": r"(?i)(?:invoke-command|icm)\b.{0,200}(?:-computername|-cn)|(?:iex|invoke-expression)\s*\(\s*\(?(?:new-object\s+net\.webclient|invoke-webrequest)",
    },
    {
        "name": "Suspicious PowerShell Combination",
        "category": "Defense Evasion",
        "severity": "HIGH",
        "description": "Multiple suspicious PowerShell execution options were combined.",
        "pattern": r"(?is)(?=.*-executionpolicy\s+(?:bypass|unrestricted))(?=.*-windowstyle\s+hidden).*",
    },
]


def detect_threats(event):
    """Apply detection rules to a PowerShell event."""
    searchable_text = " ".join([
        str(event.get("host_application", "")),
        str(event.get("script_block", "")),
    ])

    alerts = []

    for rule in DETECTION_RULES:
        if re.search(rule["pattern"], searchable_text):
            alerts.append({
                "rule_name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "description": rule["description"],
            })

    return alerts


def analyze_event(event):
    """Attach detection alerts to an event."""
    alerts = detect_threats(event)

    result = dict(event)
    result["alerts"] = alerts
    result["is_suspicious"] = bool(alerts)

    return result
