def detect_suspicious_process(process, rules):
    findings = []
    score = 0

    process_name = process["ProcessName"].lower()
    parent_name = process["ParentProcessName"].lower()
    command_line = process["CommandLine"].lower()
    executable_path = process["ExecutablePath"].lower()

    risk_scores = rules["risk_scores"]

    # Suspicious process execution
    if process_name in rules["suspicious_processes"]:
        findings.append("Suspicious process: " + process_name)
        score += risk_scores["suspicious_process"]

    # Suspicious command-line arguments
    for argument in rules["suspicious_arguments"]:
        if argument.lower() in command_line:
            findings.append("Suspicious argument: " + argument.strip())
            score += risk_scores["suspicious_argument"]

    # Suspicious parent-child process relationship
    for relationship in rules["suspicious_parent_child"]:
        if (
            parent_name == relationship["parent"].lower()
            and process_name == relationship["child"].lower()
        ):
            findings.append(
                f"Suspicious process chain: {parent_name} -> {process_name}"
            )
            score += risk_scores["suspicious_parent_child"]

    # Suspicious executable location
    for suspicious_path in rules["suspicious_paths"]:
        if suspicious_path.lower() in executable_path:
            findings.append("Suspicious executable path: " + suspicious_path)
            score += risk_scores["suspicious_path"]

    score = min(score, 100)

    if score >= 75:
        risk_level = "CRITICAL"
    elif score >= 50:
        risk_level = "HIGH"
    elif score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "ProcessId": process["ProcessId"],
        "ProcessName": process["ProcessName"],
        "ParentProcessName": process["ParentProcessName"],
        "Username": process["Username"],
        "ExecutablePath": process["ExecutablePath"],
        "RiskScore": score,
        "RiskLevel": risk_level,
        "Findings": findings,
        "Status": "ALERT" if findings else "NORMAL",
    }
