import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"

sys.path.insert(0, str(SRC_PATH))

from main import main


def test_cli_requires_input():
    with pytest.raises(SystemExit) as error:
        main([])

    assert error.value.code == 2


def test_cli_missing_windows_file(tmp_path, capsys):
    output_dir = tmp_path / "reports"

    result = main([
        "--windows",
        str(tmp_path / "missing.csv"),
        "--output",
        str(output_dir)
    ])

    captured = capsys.readouterr()

    assert result == 1
    assert "[ERROR]" in captured.err


def test_cli_missing_linux_file(tmp_path, capsys):
    output_dir = tmp_path / "reports"

    result = main([
        "--linux",
        str(tmp_path / "missing_auth.log"),
        "--output",
        str(output_dir)
    ])

    captured = capsys.readouterr()

    assert result == 1
    assert "[ERROR]" in captured.err


def test_cli_linux_execution(tmp_path, capsys):
    log_file = tmp_path / "auth.log"
    output_dir = tmp_path / "reports"

    log_file.write_text(
        "Nov 25 10:00:00 ubuntu sshd[1001]: "
        "Failed password for admin from 192.168.1.50 "
        "port 41000 ssh2\n"
        "Nov 25 10:01:00 ubuntu sshd[1002]: "
        "Invalid user hacker from 192.168.1.60\n",
        encoding="utf-8"
    )

    result = main([
        "--linux",
        str(log_file),
        "--year",
        "2026",
        "--output",
        str(output_dir)
    ])

    captured = capsys.readouterr()

    assert result == 0
    assert "Total failed logins : 2" in captured.out
    assert "Generated reports:" in captured.out
    assert (output_dir / "failed_login_report.json").exists()
    assert (output_dir / "failed_login_events.csv").exists()


def test_cli_windows_and_linux_execution(tmp_path, capsys):
    windows_file = tmp_path / "windows.csv"
    linux_file = tmp_path / "auth.log"
    output_dir = tmp_path / "reports"

    windows_file.write_text(
        "Id,TimeCreated,TargetUserName,IpAddress,Status,SubStatus\n"
        "4625,2026-11-25T10:00:00,admin,192.168.1.10,"
        "0xC000006D,0xC000006A\n",
        encoding="utf-8"
    )

    linux_file.write_text(
        "Nov 25 10:01:00 ubuntu sshd[1001]: "
        "Invalid user hacker from 192.168.1.20\n",
        encoding="utf-8"
    )

    result = main([
        "--windows",
        str(windows_file),
        "--linux",
        str(linux_file),
        "--year",
        "2026",
        "--output",
        str(output_dir)
    ])

    captured = capsys.readouterr()

    assert result == 0
    assert "Total failed logins : 2" in captured.out
    assert "Windows" in captured.out
    assert "Linux" in captured.out
    assert (output_dir / "failed_login_report.json").exists()
    assert (output_dir / "failed_login_events.csv").exists()