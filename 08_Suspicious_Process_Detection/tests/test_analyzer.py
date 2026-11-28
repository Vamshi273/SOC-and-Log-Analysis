from pathlib import Path

from src.analyzer import analyze_process_logs


def test_analyzer_processes_sample_dataset():
    root = Path(__file__).resolve().parents[1]

    result = analyze_process_logs(
        root / "datasets" / "sample_process_logs.csv",
        root / "config" / "detection_rules.json"
    )

    assert result["total_records"] == 14
    assert result["total_alerts"] == 8
    assert result["normal_records"] == 6
    assert len(result["invalid_records"]) == 0


def test_risk_summary_counts_all_records():
    root = Path(__file__).resolve().parents[1]

    result = analyze_process_logs(
        root / "datasets" / "sample_process_logs.csv",
        root / "config" / "detection_rules.json"
    )

    assert sum(result["risk_summary"].values()) == 14
