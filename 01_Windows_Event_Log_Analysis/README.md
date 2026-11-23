# Windows Event Log Analyzer

A Python-based defensive security tool for analyzing Windows Security Event Logs, identifying suspicious authentication activity, and generating security reports.

## Features

- Windows Security Event Log analysis
- Successful and failed login monitoring
- Brute-force attack detection
- Successful login after repeated failures detection
- Explicit credential usage monitoring
- Special privilege assignment monitoring
- Timestamp validation and UTC normalization
- CSV and JSON report generation
- PowerShell-based Windows event collection
- Automated testing with pytest

## Project Structure

```text
01_Windows_Event_Log_Analysis/
│
├── README.md
│
├── src/
│   ├── main.py
│   └── collect_windows_logs.ps1
│
├── sample_logs/
│   └── sample_security_logs.csv
│
└── reports/
```

## Technologies Used

- **Python** – Log processing and security analysis
- **PowerShell** – Windows Security Event Log collection
- **Pandas / CSV** – Data processing and report generation
- **JSON** – Structured security reports
- **pytest** – Automated testing

## Windows Event IDs Analyzed

| Event ID | Description |
|:---:|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Explicit credential usage |
| 4672 | Special privileges assigned |

## Detection Capabilities

### 1. Brute-Force Detection

Detects five or more failed login attempts from the same IP address within a ten-minute window.

**Severity:** High  
**MITRE ATT&CK:** T1110 – Brute Force

### 2. Successful Login After Repeated Failures

Identifies successful logins following repeated failed login attempts from the same IP address.

**Severity:** High  
**MITRE ATT&CK:** T1078 – Valid Accounts

### 3. Explicit Credential Usage

Reports Windows Event ID 4648 for further investigation.

**Severity:** Low

Explicit credential usage is not automatically malicious and requires contextual investigation.

### 4. Special Privilege Assignment

Reports Windows Event ID 4672 as informational security context.

**Severity:** Informational

Special privilege assignments are not automatically malicious.

## Installation

Run the following command from the main repository directory:

```bash
pip install -r requirements.txt
```

## Usage

### Analyze the Synthetic Sample Dataset

```bash
python .\01_Windows_Event_Log_Analysis\src\main.py --input .\01_Windows_Event_Log_Analysis\sample_logs\sample_security_logs.csv
```

### Display Available Options

```bash
python .\01_Windows_Event_Log_Analysis\src\main.py --help
```

### Analyze Your Windows Security Logs

After collecting Windows Security events:

```bash
python .\01_Windows_Event_Log_Analysis\src\main.py --input .\01_Windows_Event_Log_Analysis\sample_logs\windows_security_logs.csv
```

## Windows Event Collection

The project includes a PowerShell script for collecting Windows Security Event Logs.

Open PowerShell as Administrator and execute:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\01_Windows_Event_Log_Analysis\src\collect_windows_logs.ps1 -Days 7
```

Appropriate administrative permissions are required to access Windows Security logs.

## Generated Reports

The analyzer generates two report formats:

| File | Description |
|---|---|
| `security_report.csv` | Tabular security analysis results |
| `security_report.json` | Structured JSON security report |

Reports are saved in the module's `reports/` directory.

## Testing

Run the automated test suite from the repository root:

```bash
python -m pytest .\tests\test_windows_event_analyzer.py -v
```

**Test Results:** 10 tests passed.

## Limitations

- Analysis depends on the fields available in the input CSV.
- Missing IP addresses can limit correlation.
- Explicit credential usage and special privilege events require contextual investigation.
- No detected alerts does not guarantee that a system is secure.
- This project is not a replacement for an enterprise SIEM solution.

## Security Notice

Use this tool only on systems and logs that you own or are authorized to analyze.

Do not publish personal Windows Security logs or reports containing private system information.

## Project Status

**Status:** Core implementation completed.

**Automated Tests:** 10 passed.

**Documentation:** Completed.
