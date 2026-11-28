from pathlib import Path

import pytest

from src.parser import parse_process_logs


DATASET = (
    Path(__file__).resolve().parents[1]
    / "datasets"
    / "sample_process_logs.csv"
)


def test_parse_sample_dataset():
    records, invalid = parse_process_logs(DATASET)
    assert len(records) == 14
    assert len(invalid) == 0


def test_process_names_are_normalized():
    records, _ = parse_process_logs(DATASET)
    assert all(
        record["ProcessName"] == record["ProcessName"].lower()
        for record in records
    )


def test_missing_file_raises_error():
    with pytest.raises(FileNotFoundError):
        parse_process_logs("missing_process_logs.csv")
