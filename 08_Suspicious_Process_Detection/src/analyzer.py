import json
from pathlib import Path

from src.parser import parse_process_logs
from src.detector import detect_suspicious_process


def load_rules(rules_path):
    with Path(rules_path).open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def analyze_process_logs(log_path, rules_path):
    processes, invalid_records = parse_process_logs(log_path)
    rules = load_rules(rules_path)

    results = [
        detect_suspicious_process(process, rules)
        for process in processes
    ]

    alerts = [item for item in results if item["Status"] == "ALERT"]

    risk_summary = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0,
    }

    for item in results:
        risk_summary[item["RiskLevel"]] += 1

    return {
        "total_records": len(processes),
        "invalid_records": invalid_records,
        "total_alerts": len(alerts),
        "normal_records": len(processes) - len(alerts),
        "risk_summary": risk_summary,
        "results": results,
    }
