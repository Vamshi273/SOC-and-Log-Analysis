from src.detector import detect_suspicious_process


RULES = {
    "suspicious_processes": ["mshta.exe", "certutil.exe"],
    "suspicious_arguments": ["-encodedcommand", "downloadstring"],
    "suspicious_parent_child": [
        {"parent": "winword.exe", "child": "powershell.exe"}
    ],
    "suspicious_paths": ["\\appdata\\local\\temp\\"],
    "risk_scores": {
        "suspicious_process": 25,
        "suspicious_argument": 30,
        "suspicious_parent_child": 35,
        "suspicious_path": 25
    }
}


def make_process(**overrides):
    process = {
        "ProcessId": 1000,
        "ProcessName": "notepad.exe",
        "ParentProcessName": "explorer.exe",
        "Username": "SHIVA",
        "CommandLine": "notepad.exe",
        "ExecutablePath": "C:\\Windows\\System32\\notepad.exe"
    }
    process.update(overrides)
    return process


def test_normal_process():
    result = detect_suspicious_process(make_process(), RULES)
    assert result["Status"] == "NORMAL"
    assert result["RiskLevel"] == "LOW"


def test_suspicious_process():
    result = detect_suspicious_process(
        make_process(ProcessName="mshta.exe"), RULES
    )
    assert result["Status"] == "ALERT"
    assert result["RiskScore"] == 25


def test_encoded_command_detection():
    result = detect_suspicious_process(
        make_process(CommandLine="powershell.exe -EncodedCommand ABC"),
        RULES
    )
    assert result["RiskScore"] == 30


def test_parent_child_detection():
    result = detect_suspicious_process(
        make_process(
            ProcessName="powershell.exe",
            ParentProcessName="winword.exe"
        ),
        RULES
    )
    assert result["RiskScore"] == 35


def test_suspicious_path_detection():
    result = detect_suspicious_process(
        make_process(
            ExecutablePath="C:\\Users\\SHIVA\\AppData\\Local\\Temp\\test.exe"
        ),
        RULES
    )
    assert result["RiskScore"] == 25


def test_risk_score_is_capped_at_100():
    result = detect_suspicious_process(
        make_process(
            ProcessName="mshta.exe",
            CommandLine="downloadstring -encodedcommand",
            ParentProcessName="winword.exe",
            ExecutablePath="C:\\Users\\SHIVA\\AppData\\Local\\Temp\\test.exe"
        ),
        RULES
    )
    assert result["RiskScore"] == 100
    assert result["RiskLevel"] == "CRITICAL"
