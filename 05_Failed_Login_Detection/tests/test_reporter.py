import sys
import csv
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from reporter import (
    generate_json_report,
    generate_csv_report,
    generate_reports
)


def sample_analysis():
    return {
        "summary": {
            "total_failures": 2,
            "platform_counts": {
                "Windows": 1,
                "Linux": 1
            },
            "category_counts": {
                "INCORRECT_PASSWORD": 1,
                "UNKNOWN_USERNAME": 1
            },
            "unique_usernames": 2,
            "unique_source_ips": 2
        },
        "events": [
            {
                "platform": "Windows",
                "timestamp": "2026-11-25T10:00:00",
                "username": "admin",
                "source_ip": "192.168.1.10",
                "failure_category": "INCORRECT_PASSWORD",
                "failure_description": "The password is incorrect.",
                "evidence_code": "0XC000006A",
                "event_id": "4625",
                "status": "0xC000006D",
                "sub_status": "0xC000006A"
            },
            {
                "platform": "Linux",
                "timestamp": "2026-11-25T10:01:00",
                "username": "hacker",
                "source_ip": "192.168.1.20",
                "failure_category": "UNKNOWN_USERNAME",
                "failure_description": "The requested username was not recognized.",
                "evidence_code": "UNKNOWN_USERNAME",
                "failure_type": "UNKNOWN_USERNAME"
            }
        ]
    }


def test_generate_json_report(tmp_path):
    analysis = sample_analysis()

    path = generate_json_report(
        analysis,
        tmp_path
    )

    assert path.exists()

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        report = json.load(file)

    assert report["report_title"] == "Failed Login Investigation Report"
    assert report["summary"]["total_failures"] == 2
    assert len(report["events"]) == 2
    assert report["generated_at"]


def test_generate_csv_report(tmp_path):
    analysis = sample_analysis()

    path = generate_csv_report(
        analysis,
        tmp_path
    )

    assert path.exists()

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        rows = list(csv.DictReader(file))

    assert len(rows) == 2
    assert rows[0]["username"] == "admin"
    assert rows[0]["failure_category"] == "INCORRECT_PASSWORD"
    assert rows[1]["username"] == "hacker"


def test_generate_empty_json_report(tmp_path):
    analysis = {
        "summary": {
            "total_failures": 0
        },
        "events": []
    }

    path = generate_json_report(
        analysis,
        tmp_path
    )

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        report = json.load(file)

    assert report["summary"]["total_failures"] == 0
    assert report["events"] == []


def test_generate_empty_csv_report(tmp_path):
    analysis = {
        "events": []
    }

    path = generate_csv_report(
        analysis,
        tmp_path
    )

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        rows = list(csv.DictReader(file))

    assert rows == []


def test_create_output_directory(tmp_path):
    output_dir = tmp_path / "nested" / "reports"

    generate_json_report(
        sample_analysis(),
        output_dir
    )

    assert output_dir.exists()


def test_generate_both_reports(tmp_path):
    paths = generate_reports(
        sample_analysis(),
        tmp_path
    )

    assert paths["json"].exists()
    assert paths["csv"].exists()
