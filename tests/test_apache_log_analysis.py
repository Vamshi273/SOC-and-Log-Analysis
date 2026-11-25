import pytest

from src.parser import parse_log_line


SAMPLE_LOG = (
    '192.168.1.10 - - [25/Nov/2026:09:00:01 +0530] '
    '"GET / HTTP/1.1" 200 4521 "-" "Mozilla/5.0"'
)


def test_valid_apache_log():
    result = parse_log_line(SAMPLE_LOG)

    assert result is not None
    assert result["ip"] == "192.168.1.10"
    assert result["method"] == "GET"
    assert result["status"] == 200


def test_ip_extraction():
    result = parse_log_line(SAMPLE_LOG)
    assert result["ip"] == "192.168.1.10"


def test_http_status_extraction():
    result = parse_log_line(SAMPLE_LOG)
    assert result["status"] == 200


def test_timestamp_timezone():
    result = parse_log_line(SAMPLE_LOG)
    assert result["timestamp"].endswith("+05:30")


def test_url_decoding():
    log = SAMPLE_LOG.replace(
        'GET / HTTP/1.1',
        'GET /search?q=%3Cscript%3E HTTP/1.1'
    )

    result = parse_log_line(log)

    assert result["decoded_url"] == "/search?q=<script>"


def test_missing_response_size():
    log = SAMPLE_LOG.replace("200 4521", "200 -")

    result = parse_log_line(log)

    assert result is not None
    assert result["size"] is None


def test_malformed_log():
    assert parse_log_line("invalid apache log") is None


def test_empty_log():
    assert parse_log_line("") is None


def test_http_method():
    result = parse_log_line(SAMPLE_LOG)
    assert result["method"] == "GET"


def test_user_agent():
    result = parse_log_line(SAMPLE_LOG)
    assert result["user_agent"] == "Mozilla/5.0"
