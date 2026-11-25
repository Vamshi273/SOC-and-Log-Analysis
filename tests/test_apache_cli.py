import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "04_Apache_Access_Log_Analysis"

ENV = os.environ.copy()
ENV["PYTHONPATH"] = str(PROJECT)


def test_cli_runs_successfully(tmp_path):
    output_dir = tmp_path / "reports"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.main",
            "--output",
            str(output_dir),
        ],
        cwd=ROOT,
        env=ENV,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Total lines:    17" in result.stdout
    assert "Total alerts:   6" in result.stdout
    assert (output_dir / "security_alerts.json").exists()
    assert (output_dir / "security_alerts.csv").exists()


def test_cli_rejects_missing_log(tmp_path):
    missing_log = tmp_path / "missing.log"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.main",
            "--log",
            str(missing_log),
        ],
        cwd=ROOT,
        env=ENV,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "Log file not found" in result.stderr


def test_cli_help():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.main",
            "--help",
        ],
        cwd=ROOT,
        env=ENV,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "--log" in result.stdout
    assert "--output" in result.stdout
