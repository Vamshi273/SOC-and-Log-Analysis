# PowerShell Threat Detection and Log Analysis

A Python-based security monitoring tool that analyzes PowerShell event logs to identify suspicious command execution, obfuscation, execution policy bypasses, and potential remote code execution patterns.

This project demonstrates practical SOC log analysis, rule-based threat detection, event classification, and automated security reporting.

## Project Overview

PowerShell is widely used for Windows administration, but attackers can also abuse it to execute malicious commands, download remote payloads, evade security controls, and hide their activities.

This tool analyzes structured PowerShell event records and identifies suspicious behavior using configurable detection rules.

## Features

- PowerShell event log parsing and validation.
- Detection of encoded PowerShell commands.
- Execution policy bypass detection.
- Hidden PowerShell window detection.
- Base64 decoding detection.
- Remote script execution pattern detection.
- Download-and-execute behavior detection.
- Severity classification.
- Suspicious and normal event summaries.
- JSON and CSV report generation.
- Automated unit tests using pytest.

## Detection Rules

| Detection Rule | Category | Severity |
|---|---|---|
| Encoded PowerShell Command | Obfuscation | HIGH |
| Execution Policy Bypass | Execution Policy | MEDIUM |
| Hidden PowerShell Window | Stealth Execution | MEDIUM |
| Download and Execute Pattern | Download and Execution | CRITICAL |
| Invoke Expression with Remote Content | Remote Execution | CRITICAL |
| Base64 Decoding | Obfuscation | MEDIUM |
| Remote Script Execution | Remote Execution | HIGH |
| Suspicious PowerShell Combination | Defense Evasion | HIGH |

Severity represents the configured detection priority, not proof of a successful compromise.

## Project Structure

```text
07_PowerShell_Threat_Detection/
│
├── sample_logs/
│   └── powershell_events.log
│
├── reports/
│   ├── powershell_analysis_report.json
│   └── powershell_alerts_report.csv
│
├── src/
│   ├── parser.py
│   ├── detector.py
│   ├── classifier.py
│   ├── analyzer.py
│   ├── reporter.py
│   └── main.py
│
├── tests/
│   ├── test_parser.py
│   ├── test_detector.py
│   ├── test_classifier.py
│   ├── test_analyzer.py
│   └── test_reporter.py
│
└── README.md
```

## Technologies Used

- Python 3
- Regular Expressions
- JSON
- CSV
- Pytest
- Windows PowerShell event concepts

## Supported Event IDs

The parser currently supports:

| Event ID | Description |
|---|---|
| 400 | PowerShell engine state information |
| 403 | PowerShell engine stopped |
| 4103 | Module logging |
| 4104 | Script block logging |
| 4688 | Process creation |

The sample input uses a structured pipe-delimited format representing these event records.

## Installation

Clone the repository:

```bash
git clone https://github.com/Vamshi273/SOC-and-Log-Analysis.git
```

Navigate into the repository:

```bash
cd SOC-and-Log-Analysis
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

No third-party runtime packages are required by the analyzer. Install pytest to run the tests:

```bash
python -m pip install pytest
```

## Usage

Run the analyzer from the repository root:

```powershell
python -m 07_PowerShell_Threat_Detection.src.main `
    --input ".\07_PowerShell_Threat_Detection\sample_logs\powershell_events.log" `
    --output ".\07_PowerShell_Threat_Detection\reports"
```

Optional arguments:

| Argument | Description |
|---|---|
| `--input` | Input PowerShell event log path (required) |
| `--output` | Report output directory |

## Sample Analysis Results

The included sample dataset contains 12 synthetic PowerShell event records.

Initial analysis results:

| Metric | Result |
|---|---:|
| Total Events | 12 |
| Suspicious Events | 5 |
| Normal Events | 7 |
| Skipped Events | 0 |
| Total Alerts | 12 |

These figures describe the included sample dataset and may change when detection rules or sample records are updated.

## Generated Reports

### JSON Report

`reports/powershell_analysis_report.json`

Contains:
- Analysis summary.
- Parsed event records.
- Detection alerts.
- Severity classifications.
- Invalid record details.

### CSV Report

`reports/powershell_alerts_report.csv`

Contains:
- Event timestamp.
- Computer name.
- Username.
- Process ID.
- Event ID.
- Severity.
- Detection rule.
- Detection category.
- Alert description.
- Script block.

## Running Tests

Run all Module 07 tests:

```powershell
python -m pytest ".\07_PowerShell_Threat_Detection\tests" --import-mode=importlib -v
```

The project currently contains 33 automated tests covering parsing, detection, classification, analysis, and reporting.

## Current Limitations

- Detection is rule-based and may produce false positives.
- The analyzer evaluates individual events independently; it does not yet correlate activity across multiple events or processes.
- Input records use a structured pipe-delimited format rather than directly importing native Windows Event Log XML.
- Detection results require investigation and validation by a security analyst.

## Security and Ethical Use

This project is intended for educational purposes, defensive security monitoring, and authorized SOC analysis.

The included sample logs are synthetic. The analyzer does not execute commands found in log records or contact remote hosts.

